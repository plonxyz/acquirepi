"""
Views for acquirepi manager system.
"""
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view
from rest_framework.response import Response
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import yaml
import logging
import os
from functools import wraps

logger = logging.getLogger(__name__)


# ===== Role-Based Access Control Decorators =====

def role_required(*roles):
    """
    Decorator to check if user has one of the specified roles.
    Usage: @role_required('admin', 'examiner')
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('login')

            # Superusers always have access
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)

            # Check if user has profile with required role
            if hasattr(request.user, 'profile'):
                if request.user.profile.role in roles:
                    return view_func(request, *args, **kwargs)

            messages.error(request, 'You do not have permission to access this page.')
            return redirect('dashboard')

        return wrapper
    return decorator


def can_approve_agents(user):
    """Check if user can approve agents."""
    if user.is_superuser:
        return True
    return hasattr(user, 'profile') and user.profile.can_approve_agents()


def can_create_jobs(user):
    """Check if user can create jobs."""
    if user.is_superuser:
        return True
    return hasattr(user, 'profile') and user.profile.can_create_jobs()


def can_manage_users(user):
    """Check if user can manage users."""
    if user.is_superuser:
        return True
    return hasattr(user, 'profile') and user.profile.can_manage_users()

from .models import (
    SSHKey, NFSServer, Agent, ImagingJob, JobLog, AuditLog, WebhookConfig,
    WriteBlockerVerification, SourceDevice, QAReview, EvidenceHandlingEvent,
    MobileDevice, MobileExtractionJob, SystemSettings
)
from .serializers import (
    AgentSerializer, AgentRegistrationSerializer,
    ImagingJobSerializer, JobProgressSerializer,
    MobileDeviceSerializer, MobileExtractionJobSerializer
)
from .webhooks import WebhookNotifier
from .forensics import HashVerifier, EWFMetadataExtractor
from .ssh_utils import generate_ssh_key_pair, delete_ssh_key_pair
from .forms import (
    WriteBlockerVerificationForm, SourceDeviceForm, QAReviewForm,
    QAReviewApprovalForm, EvidenceHandlingEventForm
)


# ===== Helper Functions =====

def get_client_ip(request):
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_user_agent(request):
    """Get user agent from request."""
    return request.META.get('HTTP_USER_AGENT', '')


# ===== Web Views (Frontend) =====

@login_required
def dashboard(request):
    """Main dashboard view."""
    agents = Agent.objects.all()
    all_jobs = ImagingJob.objects.all()

    # Count agents by their display status (takes heartbeat freshness into account)
    online_count = 0
    pending_count = 0
    for agent in agents:
        display_status = agent.get_display_status()
        if display_status == 'online' or display_status == 'imaging':
            online_count += 1
        elif display_status == 'pending':
            pending_count += 1

    context = {
        'agents': agents,
        'jobs': all_jobs[:20],  # Only slice for display
        'pending_agents': pending_count,
        'online_agents': online_count,
        'active_jobs': all_jobs.filter(status='in_progress').count(),  # Filter before slicing
    }
    return render(request, 'imager/dashboard.html', context)


@login_required
def dashboard_api(request):
    """API endpoint for dashboard data (used for AJAX refresh)."""
    agents = Agent.objects.all()
    all_jobs = ImagingJob.objects.all()

    # Count agents by display status
    online_count = 0
    pending_count = 0
    agents_data = []

    for agent in agents:
        display_status = agent.get_display_status()
        if display_status == 'online' or display_status == 'imaging':
            online_count += 1
        elif display_status == 'pending':
            pending_count += 1

        agents_data.append({
            'id': agent.id,
            'hostname': agent.hostname,
            'ip_address': agent.ip_address,
            'status': display_status,
            'cpu_percent': agent.cpu_percent if display_status != 'offline' else 0,
            'memory_percent': agent.memory_percent if display_status != 'offline' else 0,
            'disk_percent': agent.disk_percent if display_status != 'offline' else 0,
            'temperature_celsius': agent.temperature_celsius if display_status != 'offline' else 0,
        })

    # Recent jobs
    jobs_data = []
    for job in all_jobs[:10]:
        jobs_data.append({
            'id': job.id,
            'case_number': job.case_number,
            'evidence_number': job.evidence_number,
            'agent_hostname': job.agent.hostname if job.agent else 'N/A',
            'status': job.status,
            'progress_percentage': float(job.progress_percentage) if job.progress_percentage else 0,
            'created_at': job.created_at.isoformat() if job.created_at else None,
        })

    return JsonResponse({
        'stats': {
            'online_agents': online_count,
            'pending_agents': pending_count,
            'active_jobs': all_jobs.filter(status='in_progress').count(),
        },
        'agents': agents_data[:10],  # First 10 for dashboard
        'jobs': jobs_data,
    })


@login_required
def agent_list(request):
    """List all agents."""
    agents = Agent.objects.all()
    return render(request, 'imager/agent_list.html', {'agents': agents})


@login_required
def agent_list_api(request):
    """API endpoint for agents list (used for AJAX refresh)."""
    agents = Agent.objects.all()
    agents_data = []

    for agent in agents:
        display_status = agent.get_display_status()
        agents_data.append({
            'id': agent.id,
            'hostname': agent.hostname,
            'ip_address': agent.ip_address,
            'mac_address': agent.mac_address,
            'status': display_status,
            'cpu_percent': agent.cpu_percent if display_status != 'offline' else 0,
            'memory_percent': agent.memory_percent if display_status != 'offline' else 0,
            'disk_percent': agent.disk_percent if display_status != 'offline' else 0,
            'temperature_celsius': agent.temperature_celsius if display_status != 'offline' else 0,
            'is_approved': agent.is_approved,
            'last_heartbeat': agent.last_heartbeat.isoformat() if agent.last_heartbeat else None,
        })

    return JsonResponse({'agents': agents_data})


@login_required
def agent_detail(request, agent_id):
    """Detail view for a specific agent."""
    agent = get_object_or_404(Agent, id=agent_id)
    jobs = agent.jobs.all()[:20]
    return render(request, 'imager/agent_detail.html', {'agent': agent, 'jobs': jobs})


@login_required
def agent_terminal(request, agent_id):
    """Terminal view for remote shell access to agent."""
    agent = get_object_or_404(Agent, id=agent_id)
    return render(request, 'imager/agent_terminal.html', {'agent': agent})


@login_required
@user_passes_test(can_approve_agents)
@require_http_methods(["POST"])
def agent_approve(request, agent_id):
    """Approve an agent."""
    agent = get_object_or_404(Agent, id=agent_id)
    agent.approve()

    # Log the approval action
    AuditLog.log_action(
        user=request.user,
        action='agent_approve',
        description=f'Approved agent {agent.hostname} (MAC: {agent.mac_address}, IP: {agent.ip_address})',
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        content_object=agent
    )

    messages.success(request, f'Agent {agent.hostname} has been approved.')
    return redirect('agent_list')


@login_required
@user_passes_test(can_approve_agents)
@require_http_methods(["POST"])
def agent_deny(request, agent_id):
    """Deny an agent."""
    agent = get_object_or_404(Agent, id=agent_id)
    agent.deny()

    # Log the denial action
    AuditLog.log_action(
        user=request.user,
        action='agent_deny',
        description=f'Denied agent {agent.hostname} (MAC: {agent.mac_address}, IP: {agent.ip_address})',
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        content_object=agent
    )

    messages.warning(request, f'Agent {agent.hostname} has been denied.')
    return redirect('agent_list')


@login_required
@role_required('admin')
@require_http_methods(["POST"])
def agent_delete(request, agent_id):
    """Delete an agent and all associated jobs."""
    agent = get_object_or_404(Agent, id=agent_id)
    hostname = agent.hostname
    mac_address = agent.mac_address
    ip_address = agent.ip_address

    # Log the deletion action BEFORE deleting (so we can capture the object)
    AuditLog.log_action(
        user=request.user,
        action='agent_delete',
        description=f'Deleted agent {hostname} (MAC: {mac_address}, IP: {ip_address}) and all associated jobs',
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        extra_data={'hostname': hostname, 'mac_address': mac_address, 'ip_address': ip_address}
    )

    # Delete SSH keys
    if delete_ssh_key_pair(mac_address):
        logger.info(f"SSH keys deleted for agent {mac_address}")

    agent.delete()
    messages.success(request, f'Agent {hostname} and all associated jobs have been deleted.')
    return redirect('agent_list')


@login_required
def job_list(request):
    """List all imaging jobs."""
    jobs = ImagingJob.objects.all()
    return render(request, 'imager/job_list.html', {'jobs': jobs})


@login_required
def job_list_api(request):
    """API endpoint for jobs list (used for AJAX refresh)."""
    jobs = ImagingJob.objects.all()
    jobs_data = []

    for job in jobs:
        jobs_data.append({
            'id': job.id,
            'case_number': job.case_number,
            'evidence_number': job.evidence_number,
            'agent_hostname': job.agent.hostname if job.agent else 'N/A',
            'agent_id': job.agent.id if job.agent else None,
            'status': job.status,
            'progress_percentage': float(job.progress_percentage) if job.progress_percentage else 0,
            'created_at': job.created_at.strftime('%Y-%m-%d %H:%M') if job.created_at else None,
            'started_at': job.started_at.strftime('%Y-%m-%d %H:%M') if job.started_at else None,
            'completed_at': job.completed_at.strftime('%Y-%m-%d %H:%M') if job.completed_at else None,
            'upload_method': job.upload_method,
            'image_name': job.image_name,
            'integrity_verified': job.integrity_verified,
            'integrity_valid': job.integrity_valid,
        })

    return JsonResponse({'jobs': jobs_data})


@login_required
def job_detail(request, job_id):
    """Detail view for a specific job."""
    job = get_object_or_404(ImagingJob, id=job_id)
    logs = job.logs.all()
    settings = SystemSettings.get_settings()
    return render(request, 'imager/job_detail.html', {
        'job': job,
        'logs': logs,
        'settings': settings
    })


@login_required
@user_passes_test(can_create_jobs)
def job_create(request):
    """Create a new imaging job."""
    if request.method == 'POST':
        # Get form data
        agent_id = request.POST.get('agent')
        agent = get_object_or_404(Agent, id=agent_id)

        # Check if this is a mobile device extraction
        source_type = request.POST.get('source_type', 'disk')
        mobile_device_id = request.POST.get('mobile_device')

        # For mobile extraction, use image_name from form and provide defaults for optional fields
        if source_type == 'mobile':
            image_name = request.POST.get('image_name', 'mobile_backup')
            case_number = request.POST.get('case_number', 'MOBILE')
            evidence_number = request.POST.get('evidence_number', 'MOBILE')
            examiner_name = request.POST.get('examiner_name', 'N/A')
            description = request.POST.get('description', 'Mobile device extraction')
        else:
            image_name = request.POST.get('image_name')
            case_number = request.POST.get('case_number')
            evidence_number = request.POST.get('evidence_number')
            examiner_name = request.POST.get('examiner_name')
            description = request.POST.get('description')

        # Determine upload method based on source type
        if source_type == 'mobile':
            upload_method = request.POST.get('mobile_upload_method', 'disk')
        else:
            upload_method = request.POST.get('upload_method', 'disk')

        # Get device path - for disk imaging it's source, for mobile it's destination
        if source_type == 'mobile':
            # For mobile extraction, use mobile_destination_device as the destination path
            device_path = request.POST.get('mobile_destination_device', '')
        else:
            # For disk imaging, use source_device_path as the source
            device_path = request.POST.get('source_device_path', '')

        # Create job
        job = ImagingJob.objects.create(
            agent=agent,
            upload_method=upload_method,
            case_number=case_number,
            evidence_number=evidence_number,
            examiner_name=examiner_name,
            description=description,
            image_name=image_name,
            base_path=request.POST.get('base_path', '/tmp'),
            source_device_path=device_path,
        )

        # Add SSH keys if selected (ManyToMany)
        ssh_key_ids = request.POST.getlist('ssh_keys')  # Changed to getlist for multiple selection
        if ssh_key_ids:
            job.ssh_keys.set(ssh_key_ids)

        # Add method-specific configuration
        if job.upload_method == 's3':
            job.s3_access_key = request.POST.get('s3_access_key')
            job.s3_secret_key = request.POST.get('s3_secret_key')
            job.s3_server = request.POST.get('s3_server')
            job.s3_bucket_name = request.POST.get('s3_bucket_name')
            job.s3_bucket_location = request.POST.get('s3_bucket_location', 'us-east-1')
            job.s3_use_https = request.POST.get('s3_use_https') == 'on'
        elif job.upload_method == 'nfs':
            # Use different field names for mobile vs disk
            if source_type == 'mobile':
                nfs_server_id = request.POST.get('mobile_nfs_server_config')
                nfs_server_field = 'mobile_nfs_server'
                nfs_share_field = 'mobile_nfs_share'
                nfs_mount_field = 'mobile_nfs_mount_point'
            else:
                nfs_server_id = request.POST.get('nfs_server_config')
                nfs_server_field = 'nfs_server'
                nfs_share_field = 'nfs_share'
                nfs_mount_field = 'nfs_mount_point'

            # Check if using pre-configured NFS server or manual entry
            if nfs_server_id == 'manual' or not nfs_server_id:
                # Manual entry - use the manual fields
                job.nfs_server = request.POST.get(nfs_server_field)
                job.nfs_share = request.POST.get(nfs_share_field)
                job.nfs_mount_point = request.POST.get(nfs_mount_field, '/mnt/nfs-share')
                # Don't set nfs_server_config_id (it should be None/null)
            elif nfs_server_id and nfs_server_id != '':
                # Pre-configured server selected
                try:
                    job.nfs_server_config_id = int(nfs_server_id)
                    # The model's to_yaml_config() will use the nfs_server_config relationship
                except (ValueError, TypeError):
                    # Invalid ID - fall back to manual fields if they exist
                    job.nfs_server = request.POST.get(nfs_server_field)
                    job.nfs_share = request.POST.get(nfs_share_field)
                    job.nfs_mount_point = request.POST.get(nfs_mount_field, '/mnt/nfs-share')

        job.status = 'queued'
        job.save()

        # Log job creation
        AuditLog.log_action(
            user=request.user,
            action='job_create',
            description=f'Created imaging job #{job.id}: Case {job.case_number}, Evidence {job.evidence_number} on agent {agent.hostname}',
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
            content_object=job,
            extra_data={
                'case_number': job.case_number,
                'evidence_number': job.evidence_number,
                'upload_method': job.upload_method,
                'agent_hostname': agent.hostname
            }
        )

        # Create mobile extraction job if source is a mobile device
        if source_type == 'mobile' and mobile_device_id:
            mobile_device = get_object_or_404(MobileDevice, id=mobile_device_id)

            # Create mobile extraction job
            mobile_extraction = MobileExtractionJob.objects.create(
                imaging_job=job,
                mobile_device=mobile_device,
                extraction_method=request.POST.get('extraction_method', 'logical'),
                backup_encrypted=request.POST.get('backup_encrypted') == 'on',
                backup_password=request.POST.get('backup_password', ''),
                include_app_data=request.POST.get('include_app_data', 'on') == 'on',
                include_photos=request.POST.get('include_photos', 'on') == 'on',
                include_messages=request.POST.get('include_messages', 'on') == 'on',
                include_internal_storage=request.POST.get('include_internal_storage', 'on') == 'on',
                include_sd_card=request.POST.get('include_sd_card') == 'on',
                include_system_partition=request.POST.get('include_system_partition') == 'on',
                # Metadata fields
                device_owner=request.POST.get('device_owner', ''),
                device_context=request.POST.get('device_context', ''),
                extraction_notes=request.POST.get('extraction_notes', ''),
                backup_name=request.POST.get('backup_name', ''),
            )

            # Mark device as extracting
            mobile_device.connection_status = 'extracting'
            mobile_device.save()

            # Log mobile extraction start
            AuditLog.log_action(
                user=request.user if request.user.is_authenticated else None,
                action='mobile_extraction_started',
                description=f"Started {mobile_extraction.get_extraction_method_display()} extraction of {mobile_device.device_name} ({mobile_device.model})",
                content_object=mobile_extraction
            )

        # Broadcast job creation to job list WebSocket
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync

        channel_layer = get_channel_layer()
        job_data = {
            'id': job.id,
            'status': job.status,
            'progress_percentage': float(job.progress_percentage),
            'acquired_bytes': job.acquired_bytes,
            'total_bytes': job.total_bytes,
            'transfer_speed': job.transfer_speed,
        }

        # Broadcast to job list for real-time updates
        async_to_sync(channel_layer.group_send)(
            'job_list',
            {
                'type': 'job_list_update',
                'job': job_data
            }
        )

        messages.success(request, f'Imaging job created successfully for {agent.hostname}.')
        return redirect('job_detail', job_id=job.id)

    # GET request - show form
    agents = Agent.objects.filter(is_approved=True, status='online')
    ssh_keys = SSHKey.objects.all()
    nfs_servers = NFSServer.objects.filter(is_active=True)
    mobile_devices = MobileDevice.objects.filter(connection_status='connected').order_by('-last_seen')

    return render(request, 'imager/job_create.html', {
        'agents': agents,
        'ssh_keys': ssh_keys,
        'nfs_servers': nfs_servers,
        'mobile_devices': mobile_devices
    })


@require_http_methods(["POST"])
@login_required
@user_passes_test(can_create_jobs)
def job_cancel(request, job_id):
    """Cancel a job."""
    job = get_object_or_404(ImagingJob, id=job_id)
    job.cancel()

    # Reset mobile device status if this is a mobile extraction
    if hasattr(job, 'mobile_extraction'):
        try:
            mobile_job = job.mobile_extraction
            if mobile_job.mobile_device:
                mobile_job.mobile_device.connection_status = 'connected'
                mobile_job.mobile_device.save(update_fields=['connection_status'])
                logger.info(f"Reset device {mobile_job.mobile_device.serial_number} status to connected after cancellation")
        except Exception as e:
            logger.warning(f"Failed to reset mobile device status: {e}")

    # Log job cancellation
    AuditLog.log_action(
        user=request.user,
        action='job_cancel',
        description=f'Cancelled job #{job.id}: Case {job.case_number}, Evidence {job.evidence_number}',
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        content_object=job
    )

    messages.info(request, f'Job {job.id} has been cancelled.')
    return redirect('job_detail', job_id=job.id)


@require_http_methods(["POST"])
@login_required
@user_passes_test(can_create_jobs)
def job_restart(request, job_id):
    """Restart a failed or cancelled job."""
    job = get_object_or_404(ImagingJob, id=job_id)

    # Only allow restarting failed or cancelled jobs
    if job.status not in ['failed', 'cancelled']:
        messages.error(request, f'Cannot restart job {job.id} - only failed or cancelled jobs can be restarted.')
        return redirect('job_detail', job_id=job.id)

    job.restart()

    # Set mobile device status to 'extracting' if this is a mobile extraction
    if hasattr(job, 'mobile_extraction'):
        try:
            mobile_job = job.mobile_extraction
            if mobile_job.mobile_device:
                mobile_job.mobile_device.connection_status = 'extracting'
                mobile_job.mobile_device.save(update_fields=['connection_status'])
                logger.info(f"Set device {mobile_job.mobile_device.serial_number} status to extracting")
        except Exception as e:
            logger.warning(f"Failed to set mobile device status: {e}")

    # Broadcast job restart via WebSocket
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync
    from .serializers import ImagingJobSerializer

    channel_layer = get_channel_layer()
    serializer = ImagingJobSerializer(job)

    # Broadcast to job detail page
    async_to_sync(channel_layer.group_send)(
        f'job_{job.id}',
        {
            'type': 'job_update',
            'job': serializer.data
        }
    )

    # Broadcast to dashboard
    async_to_sync(channel_layer.group_send)(
        'dashboard',
        {
            'type': 'job_update',
            'job': serializer.data
        }
    )

    messages.success(request, f'Job {job.id} has been restarted and queued for execution.')
    return redirect('job_detail', job_id=job.id)


# ===== SSH Key Management Views =====

def sshkey_list(request):
    """List all SSH keys."""
    ssh_keys = SSHKey.objects.all()
    return render(request, 'imager/sshkey_list.html', {'ssh_keys': ssh_keys})


def sshkey_create(request):
    """Create a new SSH key."""
    if request.method == 'POST':
        try:
            ssh_key = SSHKey.objects.create(
                name=request.POST.get('name'),
                public_key=request.POST.get('public_key'),
            )

            # Log SSH key creation
            AuditLog.log_action(
                user=request.user if request.user.is_authenticated else None,
                action='ssh_create',
                description=f'Created SSH key "{ssh_key.name}"',
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request),
                content_object=ssh_key
            )

            messages.success(request, f'SSH key "{ssh_key.name}" created successfully.')
            return redirect('sshkey_list')
        except Exception as e:
            messages.error(request, f'Error creating SSH key: {str(e)}')

    return render(request, 'imager/sshkey_form.html', {'ssh_key': None})


def sshkey_edit(request, key_id):
    """Edit an existing SSH key."""
    ssh_key = get_object_or_404(SSHKey, id=key_id)

    if request.method == 'POST':
        try:
            ssh_key.name = request.POST.get('name')
            ssh_key.public_key = request.POST.get('public_key')
            ssh_key.save()
            messages.success(request, f'SSH key "{ssh_key.name}" updated successfully.')
            return redirect('sshkey_list')
        except Exception as e:
            messages.error(request, f'Error updating SSH key: {str(e)}')

    return render(request, 'imager/sshkey_form.html', {'ssh_key': ssh_key})


@require_http_methods(["POST"])
def sshkey_delete(request, key_id):
    """Delete an SSH key."""
    ssh_key = get_object_or_404(SSHKey, id=key_id)
    name = ssh_key.name

    # Log SSH key deletion BEFORE deleting
    AuditLog.log_action(
        user=request.user if request.user.is_authenticated else None,
        action='ssh_delete',
        description=f'Deleted SSH key "{name}"',
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        extra_data={'ssh_key_name': name}
    )

    ssh_key.delete()
    messages.success(request, f'SSH key "{name}" has been deleted.')
    return redirect('sshkey_list')


# ===== API Views (Agent Communication) =====

class AgentViewSet(viewsets.ModelViewSet):
    """API ViewSet for agents."""
    queryset = Agent.objects.all()
    serializer_class = AgentSerializer

    @action(detail=False, methods=['post'])
    def register(self, request):
        """Register a new agent or update existing one."""
        serializer = AgentRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data

            # Try to find existing agent by MAC address
            agent, created = Agent.objects.update_or_create(
                mac_address=data['mac_address'],
                defaults={
                    'hostname': data['hostname'],
                    'ip_address': data['ip_address'],
                    'hardware_model': data.get('hardware_model', ''),
                    'serial_number': data.get('serial_number', ''),
                    'supports_s3': data.get('supports_s3', True),
                    'supports_nfs': data.get('supports_nfs', True),
                    'supports_disk': data.get('supports_disk', True),
                }
            )

            # Generate SSH key pair for new agents
            if created or not agent.ssh_key_path:
                logger.info(f"Generating SSH key pair for agent {agent.mac_address}")
                private_key_path, public_key = generate_ssh_key_pair(agent.mac_address)

                if private_key_path and public_key:
                    agent.ssh_key_path = private_key_path
                    agent.save()
                    logger.info(f"SSH key generated and saved for agent {agent.mac_address}")
                else:
                    logger.error(f"Failed to generate SSH key for agent {agent.mac_address}")

            # If agent was previously approved, mark as online
            if not created and agent.is_approved:
                agent.mark_online()
            elif created:
                # New agent registered, send webhook notification
                WebhookNotifier.notify_agent_registered(agent)

            return Response({
                'agent_id': agent.id,
                'status': agent.status,
                'is_approved': agent.is_approved,
                'created': created
            }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def heartbeat(self, request, pk=None):
        """Agent heartbeat to mark it as online and update resource stats."""
        agent = self.get_object()
        agent.mark_online()

        # Update resource stats if provided
        stats_updated = False
        if request.data:
            if 'cpu_percent' in request.data:
                agent.cpu_percent = request.data['cpu_percent']
                stats_updated = True
            if 'memory_percent' in request.data:
                agent.memory_percent = request.data['memory_percent']
                stats_updated = True
            if 'memory_total_mb' in request.data:
                agent.memory_total_mb = request.data['memory_total_mb']
                stats_updated = True
            if 'memory_used_mb' in request.data:
                agent.memory_used_mb = request.data['memory_used_mb']
                stats_updated = True
            if 'disk_percent' in request.data:
                agent.disk_percent = request.data['disk_percent']
                stats_updated = True
            if 'disk_total_gb' in request.data:
                agent.disk_total_gb = request.data['disk_total_gb']
                stats_updated = True
            if 'disk_used_gb' in request.data:
                agent.disk_used_gb = request.data['disk_used_gb']
                stats_updated = True
            if 'temperature_celsius' in request.data:
                agent.temperature_celsius = request.data['temperature_celsius']
                stats_updated = True
            if 'network_sent_mb' in request.data:
                agent.network_sent_mb = request.data['network_sent_mb']
                stats_updated = True
            if 'network_recv_mb' in request.data:
                agent.network_recv_mb = request.data['network_recv_mb']
                stats_updated = True
            if 'available_disks' in request.data:
                agent.available_disks = request.data['available_disks']
                stats_updated = True

            agent.save()

            # Broadcast updated stats to dashboard
            if stats_updated:
                agent._broadcast_agent_update()

        # Include pending command in response
        response_data = {
            'status': 'ok',
            'agent_status': agent.status,
            'pending_command': agent.pending_command if agent.pending_command != 'none' else None
        }

        # Clear pending command after sending it to agent
        if agent.pending_command != 'none':
            agent.pending_command = 'none'
            agent.pending_command_at = None
            agent.save(update_fields=['pending_command', 'pending_command_at'])

        return Response(response_data)

    @action(detail=True, methods=['post'])
    def cleanup_orphaned_jobs(self, request, pk=None):
        """
        Mark any in-progress jobs for this agent as failed.
        Called when agent restarts to clean up orphaned jobs.
        """
        agent = self.get_object()
        reason = request.data.get('reason', 'Agent restarted - job was interrupted')

        # Find all in-progress jobs for this agent
        orphaned_jobs = ImagingJob.objects.filter(
            agent=agent,
            status='in_progress'
        )

        failed_count = 0
        for job in orphaned_jobs:
            job.fail(reason)
            failed_count += 1

            # Log the failure
            JobLog.objects.create(
                job=job,
                level='error',
                message=f"Job marked as failed: {reason}"
            )

            # Create audit log entry
            AuditLog.log_action(
                user=None,
                action='job_orphaned',
                description=f"Job {job.id} marked as failed due to agent restart",
                content_object=job
            )

            logger.warning(f"Marked orphaned job {job.id} as failed for agent {agent.hostname}")

        return Response({
            'status': 'ok',
            'failed_count': failed_count,
            'message': f'{failed_count} orphaned job(s) marked as failed' if failed_count else 'No orphaned jobs found'
        })

    @action(detail=False, methods=['get'])
    def get_ssh_key(self, request):
        """Get the manager-generated SSH public key for an agent."""
        mac_address = request.query_params.get('mac_address')

        if not mac_address:
            return Response({'error': 'mac_address parameter required'},
                          status=status.HTTP_400_BAD_REQUEST)

        try:
            agent = Agent.objects.get(mac_address=mac_address)
        except Agent.DoesNotExist:
            return Response({'error': 'Agent not found'},
                          status=status.HTTP_404_NOT_FOUND)

        # Get the public key
        from .ssh_utils import get_public_key
        public_key = get_public_key(agent.mac_address)

        if public_key:
            return Response({
                'has_key': True,
                'public_key': public_key,
                'ssh_username': agent.ssh_username
            })
        else:
            return Response({
                'has_key': False,
                'error': 'SSH key not found for this agent'
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['post'])
    def reboot(self, request, pk=None):
        """Queue a reboot command for the agent."""
        agent = self.get_object()

        if not agent.is_truly_online():
            return Response({
                'error': 'Agent is offline and cannot receive commands'
            }, status=status.HTTP_400_BAD_REQUEST)

        agent.pending_command = 'reboot'
        agent.pending_command_at = timezone.now()
        agent.save(update_fields=['pending_command', 'pending_command_at'])

        return Response({
            'status': 'ok',
            'message': f'Reboot command queued for {agent.hostname}',
            'agent_id': agent.id,
            'command': 'reboot'
        })

    @action(detail=True, methods=['post'])
    def shutdown(self, request, pk=None):
        """Queue a shutdown command for the agent."""
        agent = self.get_object()

        if not agent.is_truly_online():
            return Response({
                'error': 'Agent is offline and cannot receive commands'
            }, status=status.HTTP_400_BAD_REQUEST)

        agent.pending_command = 'shutdown'
        agent.pending_command_at = timezone.now()
        agent.save(update_fields=['pending_command', 'pending_command_at'])

        return Response({
            'status': 'ok',
            'message': f'Shutdown command queued for {agent.hostname}',
            'agent_id': agent.id,
            'command': 'shutdown'
        })


class ImagingJobViewSet(viewsets.ModelViewSet):
    """API ViewSet for imaging jobs."""
    queryset = ImagingJob.objects.all()
    serializer_class = ImagingJobSerializer

    @action(detail=False, methods=['get'])
    def pending(self, request):
        """Get pending jobs for a specific agent."""
        mac_address = request.query_params.get('mac_address')

        if not mac_address:
            return Response({'error': 'mac_address parameter required'},
                          status=status.HTTP_400_BAD_REQUEST)

        try:
            agent = Agent.objects.get(mac_address=mac_address)
        except Agent.DoesNotExist:
            return Response({'error': 'Agent not found'},
                          status=status.HTTP_404_NOT_FOUND)

        # Get queued jobs for this agent
        jobs = ImagingJob.objects.filter(agent=agent, status='queued')

        if jobs.exists():
            job = jobs.first()
            # Generate YAML config
            config = job.to_yaml_config()

            # Check if this is a mobile extraction job
            mobile_extraction_data = None
            try:
                mobile_extraction = job.mobile_extraction
                mobile_extraction_data = {
                    'id': mobile_extraction.id,
                    'mobile_device_id': mobile_extraction.mobile_device.id,
                    'udid': mobile_extraction.mobile_device.udid,
                    'serial_number': mobile_extraction.mobile_device.serial_number,
                    'device_name': mobile_extraction.mobile_device.device_name,
                    'extraction_method': mobile_extraction.extraction_method,
                    'backup_encrypted': mobile_extraction.backup_encrypted,
                    'backup_password': mobile_extraction.backup_password,
                    'include_app_data': mobile_extraction.include_app_data,
                    'include_photos': mobile_extraction.include_photos,
                    'include_messages': mobile_extraction.include_messages,
                }
            except:
                pass  # Not a mobile extraction job

            return Response({
                'has_job': True,
                'job_id': job.id,
                'config': config,
                'config_yaml': yaml.dump(config, default_flow_style=False),
                'mobile_extraction': mobile_extraction_data
            })

        return Response({'has_job': False})

    @action(detail=True, methods=['get'])
    def status(self, request, pk=None):
        """Get current status of a job (for agent to check if cancelled)."""
        job = self.get_object()
        return Response({
            'job_id': job.id,
            'status': job.status,
            'is_cancelled': job.status == 'cancelled'
        })

    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        """Mark a job as started."""
        job = self.get_object()
        job.start()

        # Automatically log imaging started event to Chain of Custody (if enabled)
        settings = SystemSettings.get_settings()
        if settings.enable_chain_of_custody:
            EvidenceHandlingEvent.objects.create(
                job=job,
                event_type='imaging_started',
                performed_by=request.user if request.user.is_authenticated else None,
                event_description=f"Imaging job started by {job.agent.hostname} using {job.get_imaging_method_display()}."
            )

        # Update agent status and last_seen
        job.agent.status = 'imaging'
        job.agent.last_seen = timezone.now()
        job.agent.save(update_fields=['status', 'last_seen'])

        # Send webhook notification
        WebhookNotifier.notify_job_started(job)

        # Broadcast to WebSocket
        self._broadcast_job_update(job)

        return Response({'status': 'started'})

    @action(detail=True, methods=['post'])
    def progress(self, request, pk=None):
        """Update job progress."""
        job = self.get_object()
        serializer = JobProgressSerializer(data=request.data)

        if serializer.is_valid():
            data = serializer.validated_data
            job.update_progress(
                percentage=data['progress_percentage'],
                acquired_bytes=data.get('acquired_bytes'),
                total_bytes=data.get('total_bytes'),
                speed=data.get('transfer_speed')
            )

            # Update status if provided
            if 'status' in data:
                job.status = data['status']
                job.save()

            # Update agent's last_seen timestamp since progress updates mean agent is alive
            job.agent.last_seen = timezone.now()
            job.agent.save(update_fields=['last_seen'])

            # Update mobile device's last_seen if this is a mobile extraction job
            if hasattr(job, 'mobile_extraction'):
                try:
                    mobile_job = job.mobile_extraction
                    if mobile_job.mobile_device:
                        mobile_job.mobile_device.last_seen = timezone.now()
                        mobile_job.mobile_device.save(update_fields=['last_seen'])
                except Exception:
                    pass  # Ignore errors updating mobile device

            # Broadcast to WebSocket
            self._broadcast_job_update(job)

            return Response({'status': 'updated'})

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        """Mark a job as completed."""
        job = self.get_object()

        # Update job with completion data
        job.output_path = request.data.get('output_path')
        job.image_size = request.data.get('image_size')

        # Update hashes if provided
        if 'source_md5' in request.data:
            job.source_md5 = request.data['source_md5']
        if 'source_sha1' in request.data:
            job.source_sha1 = request.data['source_sha1']
        if 'source_sha256' in request.data:
            job.source_sha256 = request.data['source_sha256']
        if 'image_md5' in request.data:
            job.image_md5 = request.data['image_md5']
        if 'image_sha1' in request.data:
            job.image_sha1 = request.data['image_sha1']
        if 'image_sha256' in request.data:
            job.image_sha256 = request.data['image_sha256']

        # Update post-acquisition verification status if provided
        if 'post_verification_passed' in request.data:
            job.post_verification_passed = request.data['post_verification_passed']
            job.post_verification_at = timezone.now()
            logger.info(f"Post-verification status: {job.post_verification_passed}")

        # Verify hashes BEFORE completing job (so integrity verification sees the verified status)
        if job.source_md5 or job.source_sha1 or job.source_sha256:
            HashVerifier.verify_hashes(job)

        # Mark job as completed (this triggers automatic forensic integrity verification)
        job.complete()

        # Auto-parse SMART data if provided by agent
        smart_data = request.data.get('smart_data')
        if smart_data:
            try:
                # Check if SourceDevice exists, create if not
                try:
                    source_device = job.source_device
                except:
                    # Create a new SourceDevice record to store SMART data
                    from .models import SourceDevice
                    source_device = SourceDevice.objects.create(
                        job=job,
                        physical_condition="Auto-documented via agent SMART data"
                    )
                    logger.info(f"Auto-created SourceDevice for job {job.id}")

                # Parse and store SMART data
                if source_device.parse_smart_data(smart_data):
                    logger.info(f"Auto-parsed SMART data for job {job.id}")

                    # Automatically log SMART data collection to Chain of Custody
                    smart_description = "SMART data collected from source device (pre-imaging)."

                    # Add device details if available
                    device_details = []
                    if source_device.manufacturer or source_device.model_number:
                        device_name = f"{source_device.manufacturer} {source_device.model_number}".strip()
                        if device_name:
                            device_details.append(f"Device: {device_name}")
                    if source_device.serial_number:
                        device_details.append(f"S/N: {source_device.serial_number}")
                    if source_device.capacity_formatted:
                        device_details.append(f"Capacity: {source_device.capacity_formatted}")

                    # Add SMART health status
                    smart_health = []
                    if source_device.smart_status:
                        smart_health.append(f"SMART Status: {source_device.smart_status.upper()}")
                    if source_device.power_on_hours:
                        smart_health.append(f"Power-On Hours: {source_device.power_on_hours:,}")
                    if smart_data.get('temperature', {}).get('current'):
                        temp = smart_data['temperature']['current']
                        smart_health.append(f"Temperature: {temp}°C")

                    # Build complete description
                    if device_details:
                        smart_description += " " + ", ".join(device_details) + "."
                    if smart_health:
                        smart_description += " " + ", ".join(smart_health) + "."

                    # Determine evidence condition based on SMART status
                    evidence_condition = "Good - SMART diagnostics passed"
                    if source_device.smart_status == 'failed':
                        evidence_condition = "Warning - SMART diagnostics failed"
                    elif source_device.reallocated_sectors and source_device.reallocated_sectors > 0:
                        evidence_condition = f"Caution - {source_device.reallocated_sectors} reallocated sectors detected"

                    # Create CoC event for SMART data collection (if enabled)
                    settings = SystemSettings.get_settings()
                    if settings.enable_chain_of_custody:
                        EvidenceHandlingEvent.objects.create(
                            job=job,
                            event_type='physical_examination',
                            performed_by=None,  # System-generated event
                            event_description=smart_description,
                            evidence_condition=evidence_condition,
                            location=f"Agent: {job.agent.hostname}"
                        )
                        logger.info(f"Logged SMART data collection to Chain of Custody for job {job.id}")

            except Exception as e:
                logger.warning(f"Failed to auto-parse SMART data for job {job.id}: {e}")

        # Update MobileExtractionJob fields if this is a mobile extraction
        if hasattr(job, 'mobile_extraction'):
            try:
                mobile_job = job.mobile_extraction

                # Update extraction timestamps
                if not mobile_job.extraction_started_at and job.started_at:
                    mobile_job.extraction_started_at = job.started_at

                mobile_job.extraction_completed_at = timezone.now()

                # Update extraction size
                if job.image_size:
                    mobile_job.extraction_size_bytes = job.image_size

                # Update file count if provided
                files_extracted = request.data.get('files_extracted')
                if files_extracted is not None:
                    mobile_job.files_extracted = files_extracted
                    logger.info(f"Mobile extraction: {files_extracted} files extracted")

                # Add extraction notes if applicable
                if request.data.get('extraction_method'):
                    extraction_method = request.data['extraction_method']
                    notes = f"Extraction method: {extraction_method}. "
                    if mobile_job.extraction_size_bytes:
                        notes += f"Total size: {mobile_job.extraction_size_bytes:,} bytes. "
                    if mobile_job.files_extracted:
                        notes += f"Files extracted: {mobile_job.files_extracted:,}."
                    mobile_job.extraction_notes = notes

                mobile_job.save()
                logger.info(f"Updated MobileExtractionJob for job {job.id}")

                # Reset device status back to 'connected' after extraction completes
                if mobile_job.mobile_device:
                    mobile_job.mobile_device.connection_status = 'connected'
                    mobile_job.mobile_device.save(update_fields=['connection_status'])
                    logger.info(f"Reset device {mobile_job.mobile_device.serial_number} status to connected")

            except Exception as e:
                logger.warning(f"Failed to update MobileExtractionJob for job {job.id}: {e}")

        # Automatically log imaging completed event to Chain of Custody (if enabled)
        settings = SystemSettings.get_settings()
        if settings.enable_chain_of_custody:
            completion_details = f"Imaging completed by {job.agent.hostname}."
            if job.image_size:
                completion_details += f" Image size: {job.image_size:,} bytes."
            if job.image_md5 or job.image_sha1 or job.image_sha256:
                completion_details += " Cryptographic hashes calculated."

            EvidenceHandlingEvent.objects.create(
                job=job,
                event_type='imaging_completed',
                performed_by=request.user if request.user.is_authenticated else None,
                event_description=completion_details
            )

        # Extract EWF metadata if output path is available
        if job.output_path:
            try:
                EWFMetadataExtractor.extract_and_update(job)
            except Exception as e:
                logger.warning(f"Failed to extract EWF metadata: {e}")

        # Update agent status back to online and update last_seen
        job.agent.status = 'online'
        job.agent.last_seen = timezone.now()
        job.agent.save(update_fields=['status', 'last_seen'])

        # Send webhook notification
        WebhookNotifier.notify_job_completed(job)

        # Broadcast to WebSocket
        self._broadcast_job_update(job)

        return Response({'status': 'completed'})

    @action(detail=True, methods=['post'])
    def fail(self, request, pk=None):
        """Mark a job as failed."""
        job = self.get_object()
        error_message = request.data.get('error_message', 'Unknown error')
        job.fail(error_message)

        # Reset mobile device status if this is a mobile extraction
        if hasattr(job, 'mobile_extraction'):
            try:
                mobile_job = job.mobile_extraction
                if mobile_job.mobile_device:
                    mobile_job.mobile_device.connection_status = 'connected'
                    mobile_job.mobile_device.save(update_fields=['connection_status'])
                    logger.info(f"Reset device {mobile_job.mobile_device.serial_number} status to connected after failure")
            except Exception as e:
                logger.warning(f"Failed to reset mobile device status: {e}")

        # Update agent status back to online and update last_seen
        job.agent.status = 'online'
        job.agent.last_seen = timezone.now()
        job.agent.save(update_fields=['status', 'last_seen'])

        # Send webhook notification
        WebhookNotifier.notify_job_failed(job)

        # Broadcast to WebSocket
        self._broadcast_job_update(job)

        return Response({'status': 'failed'})

    @action(detail=True, methods=['post'])
    def log(self, request, pk=None):
        """Add a log entry to the job."""
        job = self.get_object()

        log_entry = JobLog.objects.create(
            job=job,
            level=request.data.get('level', 'info'),
            message=request.data.get('message', '')
        )

        # Update agent's last_seen timestamp since log activity means agent is alive
        job.agent.last_seen = timezone.now()
        job.agent.save(update_fields=['last_seen'])

        # Broadcast to WebSocket
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f'job_{job.id}',
            {
                'type': 'job_log',
                'log': {
                    'level': log_entry.level,
                    'message': log_entry.message,
                    'timestamp': log_entry.timestamp.isoformat()
                }
            }
        )

        return Response({'status': 'logged'})

    def _broadcast_job_update(self, job):
        """Broadcast job update via WebSocket."""
        channel_layer = get_channel_layer()

        job_data = {
            'id': job.id,
            'status': job.status,
            'progress_percentage': float(job.progress_percentage),
            'acquired_bytes': job.acquired_bytes,
            'total_bytes': job.total_bytes,
            'transfer_speed': job.transfer_speed,
        }

        # Broadcast to individual job group
        async_to_sync(channel_layer.group_send)(
            f'job_{job.id}',
            {
                'type': 'job_update',
                'job': job_data
            }
        )

        # Broadcast to job list group for real-time updates
        async_to_sync(channel_layer.group_send)(
            'job_list',
            {
                'type': 'job_list_update',
                'job': job_data
            }
        )

        # Broadcast to dashboard group for real-time dashboard updates
        async_to_sync(channel_layer.group_send)(
            'dashboard',
            {
                'type': 'job_update',
                'job': job_data
            }
        )


class MobileDeviceViewSet(viewsets.ModelViewSet):
    """API endpoints for mobile device management."""
    queryset = MobileDevice.objects.all()
    serializer_class = MobileDeviceSerializer
    permission_classes = []  # Allow agents to register devices

    @action(detail=False, methods=['post'])
    def register(self, request):
        """
        Register a mobile device with the manager.
        Called by agents when they detect a new mobile device.
        """
        agent_id = request.data.get('agent_id')
        device_info = request.data.get('device_info', {})

        if not agent_id or not device_info:
            return Response(
                {'error': 'agent_id and device_info are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Get agent
            agent = Agent.objects.get(id=agent_id)

            # Check if device already exists
            serial_number = device_info.get('serial_number')
            udid = device_info.get('udid', serial_number)

            device, created = MobileDevice.objects.get_or_create(
                serial_number=serial_number,
                defaults={
                    'device_type': device_info.get('device_type', 'ios'),
                    'udid': udid,
                    'model': device_info.get('model', ''),
                    'manufacturer': device_info.get('manufacturer', ''),
                    'product_type': device_info.get('product_type', ''),
                    'os_version': device_info.get('os_version', ''),
                    'build_version': device_info.get('build_version', ''),
                    'connection_status': 'connected',
                    'connected_agent': agent,
                    'device_name': device_info.get('device_name', ''),
                    'is_locked': device_info.get('is_locked', True),
                    'is_encrypted': device_info.get('is_encrypted', True),
                    'is_jailbroken': device_info.get('is_jailbroken', False),
                    'imei': device_info.get('imei', ''),
                    'imei2': device_info.get('imei2', ''),
                    'phone_number': device_info.get('phone_number', ''),
                    'iccid': device_info.get('iccid', ''),
                    'wifi_mac': device_info.get('wifi_mac', ''),
                    'bluetooth_mac': device_info.get('bluetooth_mac', ''),
                    'battery_level': device_info.get('battery_level'),
                    'battery_state': device_info.get('battery_state', ''),
                    'storage_total_bytes': device_info.get('storage_total_bytes'),
                    'storage_used_bytes': device_info.get('storage_used_bytes'),
                    'ios_device_class': device_info.get('ios_device_class', ''),
                    'ios_hardware_model': device_info.get('ios_hardware_model', ''),
                    'ios_device_color': device_info.get('ios_device_color', ''),
                    'ios_region_info': device_info.get('ios_region_info', ''),
                    'device_info_json': device_info.get('device_info_json', {}),
                    'last_seen': timezone.now(),
                }
            )

            if not created:
                # Update existing device - preserve 'extracting' status
                if device.connection_status != 'extracting':
                    device.connection_status = 'connected'
                device.connected_agent = agent
                device.os_version = device_info.get('os_version', device.os_version)
                device.build_version = device_info.get('build_version', device.build_version)
                device.battery_level = device_info.get('battery_level', device.battery_level)
                device.battery_state = device_info.get('battery_state', device.battery_state)
                device.storage_total_bytes = device_info.get('storage_total_bytes', device.storage_total_bytes)
                device.storage_used_bytes = device_info.get('storage_used_bytes', device.storage_used_bytes)
                device.is_locked = device_info.get('is_locked', device.is_locked)
                device.device_info_json = device_info.get('device_info_json', device.device_info_json)
                device.last_seen = timezone.now()  # Update last_seen on register/update
                device.save()

                logger.info(f"Updated mobile device: {device.serial_number}")
            else:
                logger.info(f"Registered new mobile device: {device.serial_number}")

                # Log device registration to audit log
                AuditLog.log_action(
                    user=None,
                    action='mobile_device_connected',
                    description=f"Mobile device connected: {device.device_name} ({device.model}) on agent {agent.hostname}",
                    content_object=device,
                    ip_address=agent.ip_address
                )

            serializer = self.get_serializer(device)
            return Response(serializer.data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

        except Agent.DoesNotExist:
            return Response(
                {'error': 'Agent not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error registering mobile device: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['post'])
    def heartbeat(self, request):
        """
        Update mobile device status (heartbeat).
        Called periodically by agents to keep device status updated.
        """
        agent_id = request.data.get('agent_id')
        serial_number = request.data.get('serial_number')
        device_info = request.data.get('device_info', {})

        if not serial_number:
            return Response(
                {'error': 'serial_number is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            device = MobileDevice.objects.get(serial_number=serial_number)

            # Update device info - preserve 'extracting' status
            if device.connection_status != 'extracting':
                device.connection_status = 'connected'
            device.battery_level = device_info.get('battery_level', device.battery_level)
            device.battery_state = device_info.get('battery_state', device.battery_state)
            device.storage_used_bytes = device_info.get('storage_used_bytes', device.storage_used_bytes)
            device.is_locked = device_info.get('is_locked', device.is_locked)
            device.last_seen = timezone.now()  # Update last_seen on every heartbeat
            device.save()

            return Response({'status': 'ok'})

        except MobileDevice.DoesNotExist:
            # Device not found, trigger re-registration
            return Response(
                {'error': 'Device not found', 'action': 'register'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error updating mobile device status: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['post'])
    def disconnect(self, request, pk=None):
        """Mark a mobile device as disconnected."""
        device = self.get_object()
        device.connection_status = 'disconnected'
        device.connected_agent = None
        device.save()

        logger.info(f"Mobile device disconnected: {device.serial_number}")

        # Log disconnection to audit log
        AuditLog.log_action(
            user=request.user if request.user.is_authenticated else None,
            action='mobile_device_disconnected',
            description=f"Mobile device disconnected: {device.device_name} ({device.model})",
            content_object=device
        )

        return Response({'status': 'disconnected'})

    @action(detail=False, methods=['post'])
    def disconnect_by_serial(self, request):
        """Mark a mobile device as disconnected by serial number (called by agent)."""
        serial_number = request.data.get('serial_number')
        agent_id = request.data.get('agent_id')

        if not serial_number:
            return Response(
                {'error': 'serial_number is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            device = MobileDevice.objects.get(serial_number=serial_number)
            device.connection_status = 'disconnected'
            device.connected_agent = None
            device.save()

            logger.info(f"Mobile device disconnected: {device.device_name} ({serial_number})")

            # Log disconnection to audit log
            AuditLog.log_action(
                user=None,
                action='mobile_device_disconnected',
                description=f"Mobile device disconnected from agent: {device.device_name} ({device.model})",
                content_object=device
            )

            return Response({'status': 'disconnected'})

        except MobileDevice.DoesNotExist:
            logger.warning(f"Disconnect called for unknown device: {serial_number}")
            return Response(
                {'error': 'Device not found'},
                status=status.HTTP_404_NOT_FOUND
            )


# ===== Mobile Device Views =====

@login_required
def mobile_device_list(request):
    """List all detected mobile devices."""
    # Only show connected or extracting devices
    devices = MobileDevice.objects.filter(
        connection_status__in=['connected', 'extracting']
    ).order_by('-last_seen')

    # Count by status (for currently visible devices)
    connected_count = devices.filter(connection_status='connected').count()
    extracting_count = devices.filter(connection_status='extracting').count()

    # Count by type (for currently visible devices)
    ios_count = devices.filter(device_type='ios').count()

    context = {
        'devices': devices,
        'connected_count': connected_count,
        'extracting_count': extracting_count,
        'disconnected_count': 0,  # Not showing disconnected devices
        'ios_count': ios_count,
    }

    return render(request, 'imager/mobile_device_list.html', context)


@login_required
def mobile_device_detail(request, device_id):
    """View details of a mobile device."""
    device = get_object_or_404(MobileDevice, id=device_id)

    # Get extraction jobs for this device
    extraction_jobs = device.extraction_jobs.all().order_by('-imaging_job__created_at')

    # Calculate storage usage percentage
    storage_usage_percent = None
    if device.storage_total_bytes and device.storage_used_bytes:
        storage_usage_percent = round((device.storage_used_bytes / device.storage_total_bytes) * 100, 1)

    # Format storage sizes
    storage_total_gb = None
    storage_used_gb = None
    storage_free_gb = None
    if device.storage_total_bytes:
        storage_total_gb = round(device.storage_total_bytes / (1024**3), 2)
    if device.storage_used_bytes:
        storage_used_gb = round(device.storage_used_bytes / (1024**3), 2)
    if device.storage_total_bytes and device.storage_used_bytes:
        storage_free_gb = round((device.storage_total_bytes - device.storage_used_bytes) / (1024**3), 2)

    context = {
        'device': device,
        'extraction_jobs': extraction_jobs,
        'storage_usage_percent': storage_usage_percent,
        'storage_total_gb': storage_total_gb,
        'storage_used_gb': storage_used_gb,
        'storage_free_gb': storage_free_gb,
    }

    return render(request, 'imager/mobile_device_detail.html', context)


@api_view(['GET'])
def api_stats(request):
    """Get system statistics."""
    return Response({
        'total_agents': Agent.objects.count(),
        'approved_agents': Agent.objects.filter(is_approved=True).count(),
        'pending_agents': Agent.objects.filter(status='pending').count(),
        'online_agents': Agent.objects.filter(status='online').count(),
        'total_jobs': ImagingJob.objects.count(),
        'active_jobs': ImagingJob.objects.filter(status='in_progress').count(),
        'completed_jobs': ImagingJob.objects.filter(status='completed').count(),
        'failed_jobs': ImagingJob.objects.filter(status='failed').count(),
    })


# ===== Chain of Custody Report =====

@login_required
def job_coc_report(request, job_id):
    """Generate chain of custody report for a job."""
    from .forensics import ChainOfCustody
    from django.http import HttpResponse

    job = get_object_or_404(ImagingJob, id=job_id)

    # Check format parameter (default to text for compatibility)
    format_type = request.GET.get('format', 'txt')

    if format_type == 'pdf':
        # Generate PDF report
        from .pdf_generator import CoC_PDF_Generator

        pdf_buffer = CoC_PDF_Generator.generate(job)

        response = HttpResponse(pdf_buffer.getvalue(), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="CoC_{job.case_number}_{job.evidence_number}.pdf"'

        return response
    else:
        # Generate text report (default)
        report = ChainOfCustody.generate_report(job)

        response = HttpResponse(report, content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="CoC_{job.case_number}_{job.evidence_number}.txt"'

        return response


@login_required
@require_http_methods(["POST"])
def job_send_coc_webhook(request, job_id):
    """Send Chain of Custody report to configured webhooks."""
    from .forensics import ChainOfCustody

    job = get_object_or_404(ImagingJob, id=job_id)

    try:
        # Generate report
        report = ChainOfCustody.generate_report(job)

        # Count active webhooks that will receive this
        active_webhooks = WebhookConfig.objects.filter(is_active=True)
        # Filter for 'coc_report' event type (SQLite-compatible)
        webhook_count = sum(1 for w in active_webhooks if 'coc_report' in (w.events or []))

        if webhook_count == 0:
            return JsonResponse({
                'success': False,
                'error': 'No active webhooks configured for CoC reports. Please add a webhook with the "coc_report" event enabled.'
            })

        # Send to webhooks
        WebhookNotifier.notify_coc_report(job, report)

        # Log the action
        AuditLog.log_action(
            user=request.user,
            action="CoC Report Sent",
            description=f"Sent Chain of Custody report to {webhook_count} webhook(s) - Job #{job.id}, Case: {job.case_number}, Evidence: {job.evidence_number}"
        )

        return JsonResponse({
            'success': True,
            'webhook_count': webhook_count
        })

    except Exception as e:
        logger.error(f"Error sending CoC to webhook: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


# ===== QR Code Views =====

@login_required
def job_qr_code(request, job_id):
    """Generate and serve QR code for job detail page."""
    from django.http import HttpResponse
    from .qr_utils import QRCodeGenerator

    job = get_object_or_404(ImagingJob, id=job_id)

    # Get base URL from request
    base_url = f"{request.scheme}://{request.get_host()}"

    # Generate QR code
    qr_image = QRCodeGenerator.generate_job_qr(job, base_url)

    return HttpResponse(qr_image.getvalue(), content_type='image/png')


@login_required
def job_evidence_label(request, job_id):
    """Generate printable evidence label with QR code."""
    job = get_object_or_404(ImagingJob, id=job_id)

    # Get base URL from request
    base_url = f"{request.scheme}://{request.get_host()}"

    context = {
        'job': job,
        'base_url': base_url,
    }

    return render(request, 'imager/evidence_label.html', context)


@login_required
def job_custody_scan(request, job_id):
    """QR scan page for logging custody transfers."""
    job = get_object_or_404(ImagingJob, id=job_id)

    if request.method == 'POST':
        # Get event details from form
        event_type = request.POST.get('event_type', 'checked_out')
        event_description = request.POST.get('description', 'Evidence scanned for custody verification')
        location = request.POST.get('location', '')

        # Create custody transfer event (if enabled)
        settings = SystemSettings.get_settings()
        if settings.enable_chain_of_custody:
            EvidenceHandlingEvent.objects.create(
                job=job,
                event_type=event_type,
                performed_by=request.user,
                event_description=event_description,
            location=location,
        )

        # Log to audit
        AuditLog.log_action(
            user=request.user,
            action="Custody Transfer Logged",
            description=f"QR scan custody transfer ({event_type}) - Job #{job.id}, Case: {job.case_number}"
        )

        messages.success(request, f'Custody transfer logged successfully! ({event_type.replace("_", " ").title()})')
        return redirect('job_detail', job_id=job.id)

    return render(request, 'imager/custody_scan.html', {'job': job})


# ===== Webhook Management Views =====

@login_required
@role_required('admin', 'examiner')
def webhook_list(request):
    """List all webhooks."""
    webhooks = WebhookConfig.objects.all()
    return render(request, 'imager/webhook_list.html', {'webhooks': webhooks})


@login_required
@role_required('admin', 'examiner')
def webhook_create(request):
    """Create a new webhook."""
    if request.method == 'POST':
        try:
            # Get selected events from checkboxes
            events = request.POST.getlist('events')

            webhook = WebhookConfig.objects.create(
                name=request.POST.get('name'),
                webhook_type=request.POST.get('webhook_type'),
                url=request.POST.get('url'),
                events=events,
                is_active=request.POST.get('is_active') == 'on',
                send_progress_updates=request.POST.get('send_progress_updates') == 'on',
                progress_interval=int(request.POST.get('progress_interval', 10)),
                created_by=request.user if request.user.is_authenticated else None
            )

            # Log webhook creation
            AuditLog.log_action(
                user=request.user if request.user.is_authenticated else None,
                action='webhook_create',
                description=f'Created webhook "{webhook.name}" ({webhook.get_webhook_type_display()}) for events: {", ".join(events)}',
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request),
                content_object=webhook
            )

            messages.success(request, f'Webhook "{webhook.name}" created successfully.')
            return redirect('webhook_list')
        except Exception as e:
            messages.error(request, f'Error creating webhook: {str(e)}')

    # Get event choices for the form
    event_choices = WebhookConfig.EVENT_CHOICES
    webhook_types = WebhookConfig.WEBHOOK_TYPE_CHOICES

    return render(request, 'imager/webhook_form.html', {
        'webhook': None,
        'event_choices': event_choices,
        'webhook_types': webhook_types
    })


@login_required
@role_required('admin', 'examiner')
def webhook_edit(request, webhook_id):
    """Edit an existing webhook."""
    webhook = get_object_or_404(WebhookConfig, id=webhook_id)

    if request.method == 'POST':
        try:
            events = request.POST.getlist('events')

            webhook.name = request.POST.get('name')
            webhook.webhook_type = request.POST.get('webhook_type')
            webhook.url = request.POST.get('url')
            webhook.events = events
            webhook.is_active = request.POST.get('is_active') == 'on'
            webhook.send_progress_updates = request.POST.get('send_progress_updates') == 'on'
            webhook.progress_interval = int(request.POST.get('progress_interval', 10))
            webhook.save()

            messages.success(request, f'Webhook "{webhook.name}" updated successfully.')
            return redirect('webhook_list')
        except Exception as e:
            messages.error(request, f'Error updating webhook: {str(e)}')

    event_choices = WebhookConfig.EVENT_CHOICES
    webhook_types = WebhookConfig.WEBHOOK_TYPE_CHOICES

    return render(request, 'imager/webhook_form.html', {
        'webhook': webhook,
        'event_choices': event_choices,
        'webhook_types': webhook_types
    })


@login_required
@role_required('admin', 'examiner')
@require_http_methods(["POST"])
def webhook_delete(request, webhook_id):
    """Delete a webhook."""
    webhook = get_object_or_404(WebhookConfig, id=webhook_id)
    name = webhook.name
    webhook_type = webhook.get_webhook_type_display()

    # Log webhook deletion BEFORE deleting
    AuditLog.log_action(
        user=request.user,
        action='webhook_delete',
        description=f'Deleted webhook "{name}" ({webhook_type})',
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        extra_data={'webhook_name': name, 'webhook_type': webhook_type}
    )

    webhook.delete()
    messages.success(request, f'Webhook "{name}" has been deleted.')
    return redirect('webhook_list')


@login_required
@role_required('admin', 'examiner')
def webhook_test(request, webhook_id):
    """Send a test notification to a webhook."""
    webhook = get_object_or_404(WebhookConfig, id=webhook_id)

    try:
        WebhookNotifier.send_notification(
            'system_alert',
            f'Test Notification from acquirepi Manager',
            f'This is a test message from webhook "{webhook.name}". If you see this, your webhook is configured correctly!',
            {'fields': [
                {'title': 'Webhook', 'value': webhook.name, 'short': True},
                {'title': 'Type', 'value': webhook.get_webhook_type_display(), 'short': True},
            ]}
        )

        messages.success(request, f'Test notification sent to "{webhook.name}".')
    except Exception as e:
        messages.error(request, f'Failed to send test notification: {str(e)}')

    return redirect('webhook_list')


# ===== Audit Log Viewer =====

@login_required
@role_required('admin')
def audit_log_list(request):
    """List audit log entries."""
    logs = AuditLog.objects.all()[:100]  # Last 100 entries
    return render(request, 'imager/audit_log_list.html', {'logs': logs})


@login_required
def forensic_integrity_verification(request):
    """Verify and display forensic integrity of immutable records."""
    from django.http import JsonResponse, HttpResponse
    from .models import AuditLog, JobLog, EvidenceHandlingEvent, ImagingJob
    import json
    from django.utils import timezone

    # Check if export requested
    export_format = request.GET.get('export')
    job_id = request.GET.get('job')

    # Perform verification
    results = {
        'timestamp': timezone.now().isoformat(),
        'all_valid': True,
        'audit_log': None,
        'jobs': []
    }

    # Verify Audit Log chain (unless specific job requested)
    if not job_id:
        audit_result = AuditLog.verify_chain_integrity()
        results['audit_log'] = audit_result
        results['all_valid'] = results['all_valid'] and audit_result['valid']

    # Verify Job-specific chains
    if job_id:
        jobs = [ImagingJob.objects.get(id=job_id)]
    else:
        jobs = ImagingJob.objects.all().order_by('-id')[:20]  # Latest 20 jobs

    for job in jobs:
        job_result = {
            'job_id': job.id,
            'case_number': job.case_number,
            'evidence_number': job.evidence_number,
            'logs': JobLog.verify_job_chain_integrity(job),
            'coc': EvidenceHandlingEvent.verify_job_chain_integrity(job)
        }
        results['all_valid'] = results['all_valid'] and job_result['logs']['valid'] and job_result['coc']['valid']
        results['jobs'].append(job_result)

    # Handle export
    if export_format == 'json':
        response = HttpResponse(
            json.dumps(results, indent=2),
            content_type='application/json'
        )
        response['Content-Disposition'] = f'attachment; filename="forensic_integrity_{timezone.now().strftime("%Y%m%d_%H%M%S")}.json"'
        return response

    # Render web page
    return render(request, 'imager/forensic_integrity_verification.html', {
        'results': results,
        'timestamp': timezone.now()
    })


# ===== Shell Session Management =====

def shell_session_list(request):
    """List all remote shell sessions."""
    from .models import RemoteShellSession
    sessions = RemoteShellSession.objects.all()[:100]
    return render(request, 'imager/shell_session_list.html', {'sessions': sessions})


def shell_session_detail(request, session_id):
    """View details and transcript of a shell session."""
    from .models import RemoteShellSession
    import json

    session = get_object_or_404(RemoteShellSession, id=session_id)

    # Load transcript if available
    transcript = None
    if session.transcript_path and os.path.exists(session.transcript_path):
        try:
            with open(session.transcript_path, 'r') as f:
                transcript = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load transcript: {e}")

    return render(request, 'imager/shell_session_detail.html', {
        'session': session,
        'transcript': transcript
    })


# ===== Forensic Documentation Views =====

@login_required
@role_required('admin', 'examiner')
def write_blocker_verification(request, job_id):
    """Document write-blocker verification for a job."""
    job = get_object_or_404(ImagingJob, id=job_id)

    # Check if write-blocker verification already exists
    try:
        verification = job.write_blocker
        is_new = False
    except WriteBlockerVerification.DoesNotExist:
        verification = None
        is_new = True

    if request.method == 'POST':
        form = WriteBlockerVerificationForm(request.POST, instance=verification)
        if form.is_valid():
            verification = form.save(commit=False)
            if is_new:
                verification.job = job
            verification.save()

            # Log the event (if enabled)
            settings = SystemSettings.get_settings()
            if settings.enable_chain_of_custody:
                EvidenceHandlingEvent.objects.create(
                    job=job,
                    event_type='write_blocker_tested',
                    performed_by=request.user,
                    event_description=f'Write-blocker verification documented: {verification.write_blocker_model}',
                    location=request.POST.get('location', 'Lab')
            )

            messages.success(request, 'Write-blocker verification documented successfully.')
            return redirect('job_detail', job_id=job.id)
    else:
        form = WriteBlockerVerificationForm(instance=verification)

    return render(request, 'imager/write_blocker_verification.html', {
        'form': form,
        'job': job,
        'is_new': is_new
    })


@login_required
@role_required('admin', 'examiner')
def source_device_documentation(request, job_id):
    """Document source device details for a job."""
    job = get_object_or_404(ImagingJob, id=job_id)

    # Check if source device documentation already exists
    try:
        device = job.source_device
        is_new = False
    except SourceDevice.DoesNotExist:
        device = None
        is_new = True

    if request.method == 'POST':
        form = SourceDeviceForm(request.POST, instance=device)
        if form.is_valid():
            device = form.save(commit=False)
            if is_new:
                device.job = job
            device.save()

            # Log the event (if enabled)
            settings = SystemSettings.get_settings()
            if settings.enable_chain_of_custody:
                EvidenceHandlingEvent.objects.create(
                    job=job,
                    event_type='examined',
                    performed_by=request.user,
                    event_description=f'Source device documented: {device.manufacturer} {device.model_number} S/N: {device.serial_number}',
                    location=request.POST.get('location', 'Lab'),
                evidence_condition=device.physical_condition
            )

            messages.success(request, 'Source device documented successfully.')
            return redirect('job_detail', job_id=job.id)
    else:
        form = SourceDeviceForm(instance=device)

    return render(request, 'imager/source_device_documentation.html', {
        'form': form,
        'job': job,
        'is_new': is_new
    })


@login_required
@role_required('admin', 'examiner')
def qa_review(request, job_id):
    """QA review checklist for a completed job."""
    job = get_object_or_404(ImagingJob, id=job_id)

    # Check if QA review already exists
    try:
        review = job.qa_review
        is_new = False
    except QAReview.DoesNotExist:
        review = None
        is_new = True

    if request.method == 'POST':
        form = QAReviewForm(request.POST, instance=review)
        if form.is_valid():
            review = form.save(commit=False)
            if is_new:
                review.job = job
                review.reviewed_by = request.user
                review.review_started_at = timezone.now()

            # Update completion timestamp if review is completed
            if review.review_status in ['approved', 'requires_correction', 'rejected']:
                if not review.review_completed_at:
                    review.review_completed_at = timezone.now()

            review.save()

            # Update job's QA status
            if review.review_status == 'approved' and review.all_checks_passed:
                job.qa_review_completed = True
                job.save()

            # Log the event (if enabled)
            settings = SystemSettings.get_settings()
            if settings.enable_chain_of_custody:
                EvidenceHandlingEvent.objects.create(
                    job=job,
                    event_type='qa_reviewed',
                    performed_by=request.user,
                    event_description=f'QA Review completed with status: {review.get_review_status_display()}',
                    location='QA Department'
                )

            messages.success(request, 'QA review updated successfully.')
            return redirect('job_detail', job_id=job.id)
    else:
        form = QAReviewForm(instance=review)

    return render(request, 'imager/qa_review.html', {
        'form': form,
        'job': job,
        'is_new': is_new,
        'review': review
    })


@login_required
@role_required('admin')
def qa_review_approval(request, job_id):
    """Final QA approval for a job."""
    job = get_object_or_404(ImagingJob, id=job_id)
    review = get_object_or_404(QAReview, job=job)

    if request.method == 'POST':
        form = QAReviewApprovalForm(request.POST, instance=review)
        if form.is_valid():
            review = form.save(commit=False)
            if review.final_approval:
                review.final_approval_by = request.user
                review.final_approval_date = timezone.now()
                job.qa_review_completed = True
                job.forensic_documentation_complete = True
                job.save()
            review.save()

            # Log the event (if enabled)
            settings = SystemSettings.get_settings()
            if settings.enable_chain_of_custody:
                EvidenceHandlingEvent.objects.create(
                    job=job,
                    event_type='qa_reviewed',
                    performed_by=request.user,
                    event_description=f'Final QA approval: {"Approved" if review.final_approval else "Not Approved"}',
                    location='QA Department'
                )

            messages.success(request, 'Final QA approval updated successfully.')
            return redirect('job_detail', job_id=job.id)
    else:
        form = QAReviewApprovalForm(instance=review)

    return render(request, 'imager/qa_review_approval.html', {
        'form': form,
        'job': job,
        'review': review
    })


@login_required
@role_required('admin', 'examiner')
def evidence_event_log(request, job_id):
    """Log a new evidence handling event with optional photo uploads."""
    from .forms import EvidencePhotoForm
    from .models import EvidencePhoto

    job = get_object_or_404(ImagingJob, id=job_id)

    if request.method == 'POST':
        form = EvidenceHandlingEventForm(request.POST)
        if form.is_valid():
            event = form.save(commit=False)
            event.job = job
            event.performed_by = request.user
            event.save()

            # Save many-to-many relationships (witnesses)
            form.save_m2m()

            # Handle photo uploads
            photos = request.FILES.getlist('photos')
            captions = request.POST.getlist('photo_captions')

            for i, photo_file in enumerate(photos):
                caption = captions[i] if i < len(captions) else ""
                EvidencePhoto.objects.create(
                    event=event,
                    photo=photo_file,
                    caption=caption,
                    uploaded_by=request.user
                )

            photo_count = len(photos)
            if photo_count > 0:
                messages.success(request, f'Evidence handling event logged successfully with {photo_count} photo(s).')
            else:
                messages.success(request, 'Evidence handling event logged successfully.')

            return redirect('evidence_timeline', job_id=job.id)
    else:
        form = EvidenceHandlingEventForm()

    return render(request, 'imager/evidence_event_log.html', {
        'form': form,
        'job': job
    })


@login_required
def evidence_timeline(request, job_id):
    """View the complete chain of custody timeline for a job."""
    job = get_object_or_404(ImagingJob, id=job_id)
    events = job.handling_events.all().order_by('event_timestamp')

    return render(request, 'imager/evidence_timeline.html', {
        'job': job,
        'events': events
    })


@login_required
@role_required('admin', 'examiner')
def upload_event_photos(request, event_id):
    """Upload photos to an existing evidence handling event."""
    from .models import EvidencePhoto

    event = get_object_or_404(EvidenceHandlingEvent, id=event_id)

    if request.method == 'POST':
        photos = request.FILES.getlist('photos')
        captions = request.POST.getlist('photo_captions')

        uploaded_count = 0
        for i, photo_file in enumerate(photos):
            caption = captions[i] if i < len(captions) else ""
            EvidencePhoto.objects.create(
                event=event,
                photo=photo_file,
                caption=caption,
                uploaded_by=request.user
            )
            uploaded_count += 1

        messages.success(request, f'{uploaded_count} photo(s) uploaded successfully.')
        return redirect('evidence_timeline', job_id=event.job.id)

    return render(request, 'imager/upload_event_photos.html', {
        'event': event
    })

@login_required
@role_required('admin', 'examiner')
def sign_evidence_event(request, event_id):
    """Capture digital signature for an evidence handling event."""
    from .models import DigitalSignature
    from .forms import DigitalSignatureForm
    import json

    event = get_object_or_404(EvidenceHandlingEvent, id=event_id)

    if request.method == 'POST':
        form = DigitalSignatureForm(request.POST)
        signature_data = request.POST.get('signature_data')

        if form.is_valid() and signature_data:
            # Create event snapshot for the signature
            event_snapshot = {
                'event_id': event.id,
                'event_type': event.event_type,
                'event_timestamp': event.event_timestamp.isoformat(),
                'performed_by': event.performed_by.username if event.performed_by else 'System',
                'event_description': event.event_description,
                'job_id': event.job.id,
                'case_number': event.job.case_number,
                'evidence_number': event.job.evidence_number,
            }

            # Create signature
            signature = form.save(commit=False)
            signature.event = event
            signature.signer = request.user
            signature.signature_data = signature_data
            signature.event_snapshot = event_snapshot

            # Capture IP address
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                signature.ip_address = x_forwarded_for.split(',')[0]
            else:
                signature.ip_address = request.META.get('REMOTE_ADDR')

            signature.save()

            messages.success(request, f'Event signed successfully by {signature.signer_name}.')
            return redirect('evidence_timeline', job_id=event.job.id)
        else:
            if not signature_data:
                messages.error(request, 'Please provide a signature.')
            else:
                messages.error(request, 'Please correct the errors below.')

    else:
        # Pre-fill with current user's name
        initial_data = {
            'signer_name': request.user.get_full_name() or request.user.username,
            'signer_role': request.user.userprofile.role if hasattr(request.user, 'userprofile') else ''
        }
        form = DigitalSignatureForm(initial=initial_data)

    return render(request, 'imager/sign_evidence_event.html', {
        'event': event,
        'form': form
    })


@login_required
@role_required('admin', 'examiner')
def agent_performance_dashboard(request):
    """Comprehensive agent performance and analytics dashboard."""
    from django.db.models import Count, Avg, Sum, Q, F
    from django.db.models.functions import TruncDate
    from datetime import timedelta
    
    # Get all agents
    agents = Agent.objects.all()
    
    # Calculate agent statistics
    agent_stats = []
    for agent in agents:
        jobs = agent.jobs.all()
        completed_jobs = jobs.filter(status='completed')
        failed_jobs = jobs.filter(status='failed')
        
        # Calculate success rate
        total_jobs = jobs.count()
        if total_jobs > 0:
            success_rate = (completed_jobs.count() / total_jobs) * 100
        else:
            success_rate = 0
        
        # Calculate average job duration for completed jobs
        avg_duration = None
        if completed_jobs.exists():
            durations = []
            for job in completed_jobs:
                if job.started_at and job.completed_at:
                    duration = (job.completed_at - job.started_at).total_seconds()
                    durations.append(duration)
            if durations:
                avg_duration = sum(durations) / len(durations)
        
        # Calculate total data processed (in GB)
        total_data_gb = 0
        for job in completed_jobs:
            if job.image_size:
                total_data_gb += job.image_size / (1024**3)  # Convert bytes to GB
        
        agent_stats.append({
            'agent': agent,
            'total_jobs': total_jobs,
            'completed_jobs': completed_jobs.count(),
            'failed_jobs': failed_jobs.count(),
            'in_progress_jobs': jobs.filter(status='in_progress').count(),
            'success_rate': round(success_rate, 1),
            'avg_duration_hours': round(avg_duration / 3600, 2) if avg_duration else None,
            'total_data_gb': round(total_data_gb, 2),
            'status': agent.get_display_status(),
            'last_heartbeat': agent.last_seen,
        })
    
    # Overall system statistics
    all_jobs = ImagingJob.objects.all()
    total_jobs = all_jobs.count()
    completed_jobs = all_jobs.filter(status='completed').count()
    failed_jobs = all_jobs.filter(status='failed').count()
    in_progress_jobs = all_jobs.filter(status='in_progress').count()
    pending_jobs = all_jobs.filter(status='pending').count()
    
    # Calculate overall success rate
    if total_jobs > 0:
        overall_success_rate = (completed_jobs / total_jobs) * 100
    else:
        overall_success_rate = 0
    
    # Jobs by status for pie chart
    jobs_by_status = {
        'completed': completed_jobs,
        'failed': failed_jobs,
        'in_progress': in_progress_jobs,
        'pending': pending_jobs,
    }
    
    # Recent activity - last 30 days
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_jobs = all_jobs.filter(created_at__gte=thirty_days_ago)
    
    # Jobs per day for last 30 days (for line chart)
    jobs_per_day = recent_jobs.annotate(
        date=TruncDate('created_at')
    ).values('date').annotate(
        count=Count('id')
    ).order_by('date')
    
    # Convert to format for Chart.js
    jobs_timeline = {
        'dates': [item['date'].strftime('%Y-%m-%d') for item in jobs_per_day],
        'counts': [item['count'] for item in jobs_per_day],
    }
    
    # Top performing agents (by completed jobs)
    top_agents = sorted(agent_stats, key=lambda x: x['completed_jobs'], reverse=True)[:5]
    
    # Recent failed jobs for attention
    recent_failures = all_jobs.filter(
        status='failed'
    ).order_by('-created_at')[:10]
    
    # System health indicators
    online_agents = sum(1 for stat in agent_stats if stat['status'] in ['online', 'imaging'])
    offline_agents = sum(1 for stat in agent_stats if stat['status'] == 'offline')
    
    context = {
        'agent_stats': agent_stats,
        'total_agents': agents.count(),
        'online_agents': online_agents,
        'offline_agents': offline_agents,
        'total_jobs': total_jobs,
        'completed_jobs': completed_jobs,
        'failed_jobs': failed_jobs,
        'in_progress_jobs': in_progress_jobs,
        'pending_jobs': pending_jobs,
        'overall_success_rate': round(overall_success_rate, 1),
        'jobs_by_status': jobs_by_status,
        'jobs_timeline': jobs_timeline,
        'top_agents': top_agents,
        'recent_failures': recent_failures,
    }
    
    return render(request, 'imager/agent_performance_dashboard.html', context)


# ===== Config Stick Creation (Legacy Fallback) =====

def get_removable_usb_devices():
    """
    Detect removable USB storage devices connected to the manager.
    Returns a list of dicts with device info.
    """
    import subprocess
    import json

    devices = []
    try:
        # Use lsblk to get block devices with their properties
        result = subprocess.run(
            ['/usr/bin/lsblk', '-J', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT,RM,TRAN,MODEL,SERIAL'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for device in data.get('blockdevices', []):
                # Only include removable (RM=1) USB disks, exclude mmcblk (SD card)
                if (device.get('type') == 'disk' and
                    device.get('rm') == True and
                    device.get('tran') == 'usb' and
                    not device.get('name', '').startswith('mmcblk')):

                    dev_path = f"/dev/{device['name']}"
                    devices.append({
                        'path': dev_path,
                        'name': device.get('name'),
                        'size': device.get('size', 'Unknown'),
                        'model': device.get('model', 'Unknown').strip() if device.get('model') else 'Unknown',
                        'serial': device.get('serial', ''),
                        'mounted': any(child.get('mountpoint') for child in device.get('children', [])) if device.get('children') else False,
                    })
    except Exception as e:
        logger.error(f"Error detecting USB devices: {e}")

    return devices


@login_required
def config_stick_create(request):
    """
    Create a configuration stick for legacy/standalone imaging.
    This provides a fallback when agents can't connect to the manager.
    """
    from .models import Agent, NFSServer

    agents = Agent.objects.filter(is_approved=True)
    nfs_servers = NFSServer.objects.all()
    usb_devices = get_removable_usb_devices()

    logger.info(f"Config stick page: found {len(usb_devices)} USB devices: {usb_devices}")

    context = {
        'agents': agents,
        'nfs_servers': nfs_servers,
        'usb_devices': usb_devices,
    }

    return render(request, 'imager/config_stick_create.html', context)


@login_required
def config_stick_download(request):
    """
    Generate and download the Imager_config.yaml file.
    """
    if request.method != 'POST':
        return redirect('config_stick_create')

    # Get form data
    image_name = request.POST.get('image_name', 'IMAGE')
    case_number = request.POST.get('case_number', '')
    evidence_number = request.POST.get('evidence_number', '')
    examiner_name = request.POST.get('examiner_name', '')
    description = request.POST.get('description', 'Automated Acquisition')
    upload_method = request.POST.get('upload_method', 'disk')
    extraction_type = request.POST.get('extraction_type', 'disk')

    # Build config dictionary
    config = {
        'imager-config': {
            'base_path': '/home/pi',
            'image_name': image_name,
            'case_number': case_number,
            'evidence_number': evidence_number,
            'examiner_name': examiner_name,
            'description': description,
        },
        'system': {
            'upload_method': upload_method,
            'extraction_type': extraction_type,
        }
    }

    # Add mobile extraction config if mobile type selected
    if extraction_type == 'mobile':
        extraction_method = request.POST.get('extraction_method', 'logical')
        backup_encrypted = request.POST.get('backup_encrypted') == 'true'
        backup_password = request.POST.get('backup_password', '')

        config['system']['extraction_method'] = extraction_method
        config['system']['backup_encrypted'] = backup_encrypted
        if backup_encrypted and backup_password:
            config['system']['backup_password'] = backup_password

    # Add network config if provided
    wifi_ssid = request.POST.get('wifi_ssid', '')
    wifi_password = request.POST.get('wifi_password', '')
    if wifi_ssid:
        config['system']['network-config'] = {
            'SSID': wifi_ssid,
            'Password': wifi_password,
        }

    # Add SSH keys if provided
    ssh_keys = request.POST.get('ssh_keys', '')
    if ssh_keys.strip():
        config['system']['ssh-keys'] = ssh_keys

    # Add NFS config if NFS method selected
    if upload_method == 'nfs':
        nfs_server = request.POST.get('nfs_server', '')
        nfs_share = request.POST.get('nfs_share', '')
        nfs_mount = request.POST.get('nfs_mount_point', '/mnt/nfs-share')
        config['system']['nfs-config'] = {
            'server': nfs_server,
            'share': nfs_share,
            'mount_point': nfs_mount,
        }

    # Generate YAML content
    yaml_content = yaml.dump(config, default_flow_style=False, sort_keys=False, allow_unicode=True)

    # Create HTTP response with YAML file download
    response = HttpResponse(yaml_content, content_type='application/x-yaml')
    response['Content-Disposition'] = 'attachment; filename="Imager_config.yaml"'

    # Log the action
    from .models import AuditLog
    AuditLog.log_action(
        user=request.user,
        action='config_stick_created',
        description=f"Generated config stick YAML: {image_name} (case: {case_number})",
    )

    return response


@login_required
def config_stick_list_devices(request):
    """
    API endpoint to list available USB devices for config stick creation.
    """
    devices = get_removable_usb_devices()
    return JsonResponse({'devices': devices})


@login_required
@require_http_methods(["POST"])
def config_stick_prepare(request):
    """
    Prepare a USB stick as a config stick:
    1. Format as FAT32
    2. Set UUID to 937C-8BC2
    3. Mount and write Imager_config.yaml
    4. Unmount safely
    """
    import subprocess
    import tempfile
    import time

    device = request.POST.get('usb_device', '')
    if not device or not device.startswith('/dev/'):
        return JsonResponse({'success': False, 'error': 'Invalid device selected'}, status=400)

    # Safety check - don't allow formatting system disks (SD card on Pi)
    if 'mmcblk' in device:
        return JsonResponse({'success': False, 'error': 'Cannot format system disk'}, status=400)

    # Verify it's a removable USB device
    usb_devices = get_removable_usb_devices()
    valid_device = any(d['path'] == device for d in usb_devices)
    if not valid_device:
        return JsonResponse({'success': False, 'error': 'Device not found or not a removable USB device'}, status=400)

    # Get form data for config
    image_name = request.POST.get('image_name', 'IMAGE')
    case_number = request.POST.get('case_number', '')
    evidence_number = request.POST.get('evidence_number', '')
    examiner_name = request.POST.get('examiner_name', '')
    description = request.POST.get('description', 'Automated Acquisition')
    upload_method = request.POST.get('upload_method', 'disk')
    extraction_type = request.POST.get('extraction_type', 'disk')

    # Build config dictionary
    config = {
        'imager-config': {
            'base_path': '/home/pi',
            'image_name': image_name,
            'case_number': case_number,
            'evidence_number': evidence_number,
            'examiner_name': examiner_name,
            'description': description,
        },
        'system': {
            'upload_method': upload_method,
            'extraction_type': extraction_type,
        }
    }

    # Add mobile extraction config if mobile type selected
    if extraction_type == 'mobile':
        extraction_method = request.POST.get('extraction_method', 'logical')
        backup_encrypted = request.POST.get('backup_encrypted') == 'true'
        backup_password = request.POST.get('backup_password', '')

        config['system']['extraction_method'] = extraction_method
        config['system']['backup_encrypted'] = backup_encrypted
        if backup_encrypted and backup_password:
            config['system']['backup_password'] = backup_password

    # Add network config if provided
    wifi_ssid = request.POST.get('wifi_ssid', '')
    wifi_password = request.POST.get('wifi_password', '')
    if wifi_ssid:
        config['system']['network-config'] = {
            'SSID': wifi_ssid,
            'Password': wifi_password,
        }

    # Add SSH keys if provided
    ssh_keys = request.POST.get('ssh_keys', '')
    if ssh_keys.strip():
        config['system']['ssh-keys'] = ssh_keys

    # Add NFS config if NFS method selected
    if upload_method == 'nfs':
        nfs_server = request.POST.get('nfs_server', '')
        nfs_share = request.POST.get('nfs_share', '')
        nfs_mount = request.POST.get('nfs_mount_point', '/mnt/nfs-share')
        config['system']['nfs-config'] = {
            'server': nfs_server,
            'share': nfs_share,
            'mount_point': nfs_mount,
        }

    yaml_content = yaml.dump(config, default_flow_style=False, sort_keys=False, allow_unicode=True)

    try:
        # Step 1: Unmount any existing partitions on the device
        logger.info(f"Preparing config stick on {device}")
        subprocess.run(['/usr/bin/umount', f'{device}1'], capture_output=True)
        subprocess.run(['/usr/bin/umount', device], capture_output=True)
        time.sleep(1)

        # Step 2: Create a new partition table and partition
        logger.info(f"Creating partition table on {device}")
        # Use sfdisk to create a single FAT32 partition
        partition_script = "label: dos\ntype=c\n"  # type c = W95 FAT32 (LBA)
        result = subprocess.run(
            ['/usr/sbin/sfdisk', '--force', device],
            input=partition_script,
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            logger.error(f"sfdisk failed: {result.stderr}")
            return JsonResponse({'success': False, 'error': f'Failed to create partition: {result.stderr}'}, status=500)

        time.sleep(2)  # Wait for partition to be recognized

        # Step 3: Format partition as FAT32
        partition = f'{device}1'
        logger.info(f"Formatting {partition} as FAT32")
        result = subprocess.run(
            ['/usr/sbin/mkfs.vfat', '-F', '32', '-n', 'CONFIG', partition],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            logger.error(f"mkfs.vfat failed: {result.stderr}")
            return JsonResponse({'success': False, 'error': f'Failed to format: {result.stderr}'}, status=500)

        time.sleep(1)

        # Step 4: Set the UUID to 937C-8BC2
        # FAT32 volume ID is stored at offset 67 (0x43) in the partition boot sector
        # UUID 937C-8BC2 in little-endian is: 0xC2 0x8B 0x7C 0x93
        logger.info(f"Setting UUID on {partition}")
        uuid_bytes = bytes([0xC2, 0x8B, 0x7C, 0x93])
        with open(partition, 'r+b') as f:
            f.seek(67)  # Offset for FAT32 volume ID
            f.write(uuid_bytes)

        time.sleep(1)

        # Step 5: Mount the partition
        mount_point = tempfile.mkdtemp(prefix='configstick_')
        logger.info(f"Mounting {partition} to {mount_point}")
        result = subprocess.run(
            ['/usr/bin/mount', partition, mount_point],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            logger.error(f"mount failed: {result.stderr}")
            return JsonResponse({'success': False, 'error': f'Failed to mount: {result.stderr}'}, status=500)

        try:
            # Step 6: Write the config file
            config_path = os.path.join(mount_point, 'Imager_config.yaml')
            logger.info(f"Writing config to {config_path}")
            with open(config_path, 'w') as f:
                f.write(yaml_content)

            # Step 7: Sync and unmount
            subprocess.run(['/usr/bin/sync'], timeout=30)
            time.sleep(1)

        finally:
            # Always try to unmount
            subprocess.run(['/usr/bin/umount', mount_point], capture_output=True, timeout=30)
            try:
                os.rmdir(mount_point)
            except:
                pass

        # Log the action
        from .models import AuditLog
        AuditLog.log_action(
            user=request.user,
            action='config_stick_prepared',
            description=f"Prepared config stick on {device}: {image_name} (case: {case_number})",
        )

        logger.info(f"Config stick prepared successfully on {device}")
        return JsonResponse({
            'success': True,
            'message': f'Config stick prepared successfully on {device}. UUID set to 937C-8BC2.'
        })

    except subprocess.TimeoutExpired:
        return JsonResponse({'success': False, 'error': 'Operation timed out'}, status=500)
    except Exception as e:
        logger.error(f"Error preparing config stick: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
