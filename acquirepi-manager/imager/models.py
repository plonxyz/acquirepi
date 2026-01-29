"""
Models for acquirepi manager system.
"""
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
import json
import hashlib
import logging

logger = logging.getLogger(__name__)


class UserProfile(models.Model):
    """Extended user profile with role and permissions."""

    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('examiner', 'Examiner'),
        ('viewer', 'Viewer'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='viewer')
    department = models.CharField(max_length=255, blank=True, null=True)
    phone = models.CharField(max_length=50, blank=True, null=True)

    # Preferences
    email_notifications = models.BooleanField(default=True)
    slack_webhook_url = models.URLField(blank=True, null=True, help_text="Personal Slack webhook for notifications")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['user__username']

    def __str__(self):
        return f"{self.user.username} ({self.get_role_display()})"

    def can_approve_agents(self):
        """Check if user can approve agents."""
        return self.role in ['admin', 'examiner']

    def can_create_jobs(self):
        """Check if user can create jobs."""
        return self.role in ['admin', 'examiner']

    def can_manage_users(self):
        """Check if user can manage other users."""
        return self.role == 'admin'


class SystemSettings(models.Model):
    """
    Global system settings (Singleton pattern).
    Only one record should exist (ID=1).
    Configure forensic features through Django admin.
    """

    # Forensic Features Toggle
    enable_chain_of_custody = models.BooleanField(
        default=False,
        help_text="Enable chain of custody tracking (evidence handling events, timeline)"
    )
    enable_qa_review = models.BooleanField(
        default=False,
        help_text="Enable quality assurance review workflow"
    )
    enable_qr_codes = models.BooleanField(
        default=False,
        help_text="Enable QR code generation for evidence labels"
    )
    enable_digital_signatures = models.BooleanField(
        default=False,
        help_text="Enable digital signatures for evidence events"
    )

    # Notification Settings
    enable_webhooks = models.BooleanField(
        default=True,
        help_text="Enable webhook notifications (Slack, Teams, etc.)"
    )
    enable_email_notifications = models.BooleanField(
        default=True,
        help_text="Enable email notifications for job completion"
    )

    # Advanced Features
    enable_remote_shell = models.BooleanField(
        default=True,
        help_text="Enable SSH terminal access to agents via web UI"
    )

    # Integrity Monitoring & Tamper Alerts
    enable_integrity_monitoring = models.BooleanField(
        default=True,
        help_text="Enable periodic integrity verification of audit logs and chain of custody"
    )
    integrity_check_interval_minutes = models.PositiveIntegerField(
        default=60,
        help_text="How often to run integrity checks (in minutes)"
    )
    tamper_alert_webhook_url = models.URLField(
        blank=True,
        null=True,
        help_text="Webhook URL for tampering alerts (Slack, Discord, Teams, etc.)"
    )
    tamper_alert_email = models.EmailField(
        blank=True,
        null=True,
        help_text="Email address for tampering alerts"
    )
    last_integrity_check = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp of last integrity verification"
    )
    last_integrity_status = models.BooleanField(
        default=True,
        help_text="Result of last integrity check (True=passed, False=tampering detected)"
    )

    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Last user who modified these settings"
    )

    class Meta:
        verbose_name = "System Settings"
        verbose_name_plural = "System Settings"

    def __str__(self):
        return "acquirepi System Settings"

    @classmethod
    def get_settings(cls):
        """
        Get or create the singleton settings object.
        Always returns the settings instance (ID=1).
        """
        obj, created = cls.objects.get_or_create(pk=1)
        return obj

    def save(self, *args, **kwargs):
        """Override save to enforce singleton pattern."""
        self.pk = 1
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Prevent deletion of settings."""
        pass


class AuditLog(models.Model):
    """Audit log for tracking all user actions."""

    ACTION_CHOICES = [
        ('login', 'User Login'),
        ('logout', 'User Logout'),
        ('agent_approve', 'Agent Approved'),
        ('agent_deny', 'Agent Denied'),
        ('agent_delete', 'Agent Deleted'),
        ('job_create', 'Job Created'),
        ('job_cancel', 'Job Cancelled'),
        ('job_delete', 'Job Deleted'),
        ('ssh_create', 'SSH Key Created'),
        ('ssh_delete', 'SSH Key Deleted'),
        ('webhook_create', 'Webhook Created'),
        ('webhook_delete', 'Webhook Deleted'),
        ('user_create', 'User Created'),
        ('user_update', 'User Updated'),
        ('user_delete', 'User Deleted'),
        ('shell_access', 'Remote Shell Access'),
        ('config_change', 'Configuration Changed'),
    ]

    # Who did it
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    username = models.CharField(max_length=150, help_text="Username at time of action")

    # What they did
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    description = models.TextField(help_text="Detailed description of the action")

    # When and where
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)

    # What was affected (generic foreign key for flexibility)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')

    # Additional context
    extra_data = models.JSONField(default=dict, blank=True, help_text="Additional context as JSON")

    # Forensic immutability - cryptographic hash chain
    record_hash = models.CharField(max_length=64, blank=True, editable=False,
                                   help_text="SHA256 hash of this record for tamper detection")
    previous_hash = models.CharField(max_length=64, blank=True, editable=False,
                                     help_text="Hash of previous record in chain")

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp', 'user']),
            models.Index(fields=['action', '-timestamp']),
        ]

    def __str__(self):
        return f"[{self.timestamp}] {self.username}: {self.get_action_display()}"

    def _calculate_hash(self):
        """Calculate SHA256 hash of this record for tamper detection."""
        # Include all critical fields in hash
        hash_data = f"{self.timestamp.isoformat()}|{self.username}|{self.action}|{self.description}|{self.ip_address or ''}|{self.previous_hash}"
        return hashlib.sha256(hash_data.encode('utf-8')).hexdigest()

    def save(self, *args, **kwargs):
        """Override save to implement immutability and hash chaining."""
        if self.pk is not None:
            # Record already exists - prevent modification (immutability)
            raise ValidationError("Audit log records are immutable and cannot be modified for forensic integrity.")

        # Get previous record's hash for chain
        try:
            last_record = AuditLog.objects.order_by('-id').first()
            self.previous_hash = last_record.record_hash if last_record else '0' * 64
        except Exception as e:
            logger.warning(f"Could not get previous hash: {e}")
            self.previous_hash = '0' * 64

        # Calculate hash before saving (timestamp is set by auto_now_add)
        # We need to save first to get timestamp, then update hash
        is_new = self.pk is None
        if is_new:
            # Temporarily allow save to get timestamp
            super().save(*args, **kwargs)
            # Now calculate and update hash
            self.record_hash = self._calculate_hash()
            # Use update() to bypass save() protection
            AuditLog.objects.filter(pk=self.pk).update(
                record_hash=self.record_hash,
                previous_hash=self.previous_hash
            )
        else:
            super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Prevent deletion of audit log records for forensic integrity."""
        raise ValidationError("Audit log records cannot be deleted for forensic integrity. They are immutable.")

    def verify_hash(self):
        """Verify that this record's hash is valid."""
        calculated_hash = self._calculate_hash()
        return self.record_hash == calculated_hash

    @classmethod
    def verify_chain_integrity(cls):
        """Verify the integrity of the entire audit log chain.

        Returns:
            dict: {
                'valid': bool,
                'total_records': int,
                'broken_chains': list of record IDs with broken hashes,
                'details': str
            }
        """
        records = cls.objects.all().order_by('id')
        broken_chains = []
        total = records.count()

        prev_hash = '0' * 64
        for record in records:
            # Check if previous hash matches
            if record.previous_hash != prev_hash:
                broken_chains.append({
                    'id': record.id,
                    'reason': 'previous_hash_mismatch',
                    'expected': prev_hash,
                    'actual': record.previous_hash
                })

            # Verify record hash
            if not record.verify_hash():
                broken_chains.append({
                    'id': record.id,
                    'reason': 'invalid_hash',
                    'stored': record.record_hash,
                    'calculated': record._calculate_hash()
                })

            prev_hash = record.record_hash

        return {
            'valid': len(broken_chains) == 0,
            'total_records': total,
            'broken_chains': broken_chains,
            'details': f"Verified {total} records. {'All valid.' if len(broken_chains) == 0 else f'{len(broken_chains)} issues found.'}"
        }

    @classmethod
    def log_action(cls, user, action, description, ip_address=None, user_agent=None,
                   content_object=None, extra_data=None):
        """Helper method to create audit log entries."""
        log_entry = cls(
            user=user,
            username=user.username if user else 'system',
            action=action,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent,
            extra_data=extra_data or {}
        )

        if content_object:
            log_entry.content_object = content_object

        log_entry.save()
        return log_entry


class WebhookConfig(models.Model):
    """Configuration for webhook notifications."""

    WEBHOOK_TYPE_CHOICES = [
        ('slack', 'Slack'),
        ('teams', 'Microsoft Teams'),
        ('google_chat', 'Google Chat'),
        ('generic', 'Generic Webhook'),
    ]

    EVENT_CHOICES = [
        ('job_started', 'Job Started'),
        ('job_completed', 'Job Completed'),
        ('job_failed', 'Job Failed'),
        ('job_progress', 'Job Progress Update'),
        ('agent_registered', 'Agent Registered'),
        ('agent_online', 'Agent Online'),
        ('agent_offline', 'Agent Offline'),
        ('system_alert', 'System Alert'),
    ]

    name = models.CharField(max_length=255, help_text="Descriptive name for this webhook")
    webhook_type = models.CharField(max_length=20, choices=WEBHOOK_TYPE_CHOICES)
    url = models.URLField(help_text="Webhook URL")

    # Event filtering
    events = models.JSONField(default=list, help_text="List of events to trigger this webhook")

    # Optional filters
    agent_filter = models.ForeignKey('Agent', on_delete=models.SET_NULL, null=True, blank=True,
                                     help_text="Only trigger for specific agent (optional)")
    user_filter = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                    help_text="Only trigger for jobs created by specific user (optional)")

    # Settings
    is_active = models.BooleanField(default=True)
    send_progress_updates = models.BooleanField(default=False, help_text="Send progress updates (can be noisy)")
    progress_interval = models.IntegerField(default=10, help_text="Only send progress every N percent")

    # Metadata
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='webhooks_created')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Statistics
    last_triggered = models.DateTimeField(null=True, blank=True)
    success_count = models.IntegerField(default=0)
    failure_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.get_webhook_type_display()})"


class SSHKey(models.Model):
    """SSH public key for agent access."""

    name = models.CharField(max_length=255, unique=True, help_text="Descriptive name for this SSH key")
    public_key = models.TextField(help_text="SSH public key (will be added to agent's authorized_keys)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class NFSServer(models.Model):
    """Pre-configured NFS server for forensic image storage."""

    name = models.CharField(max_length=255, unique=True, help_text="Descriptive name for this NFS server")
    server = models.CharField(max_length=255, help_text="NFS server hostname or IP address")
    share = models.CharField(max_length=500, help_text="NFS share path (e.g., /mnt/forensics)")
    mount_point = models.CharField(max_length=500, default='/mnt/nfs-share', help_text="Local mount point on agent")

    # Optional settings
    nfs_version = models.CharField(max_length=10, default='4', blank=True,
                                   help_text="NFS version (3, 4, 4.1, etc.)")
    mount_options = models.CharField(max_length=500, blank=True, null=True,
                                     help_text="Additional mount options (e.g., rw,sync,hard)")

    # Status
    is_active = models.BooleanField(default=True, help_text="Whether this server is available for selection")

    # Metadata
    description = models.TextField(blank=True, null=True, help_text="Notes about this NFS server")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name='nfs_servers_created')

    class Meta:
        ordering = ['name']
        verbose_name = 'NFS Server'
        verbose_name_plural = 'NFS Servers'

    def __str__(self):
        return f"{self.name} ({self.server}:{self.share})"


class Agent(models.Model):
    """Represents a acquirepi imaging device."""

    STATUS_CHOICES = [
        ('pending', 'Pending Approval'),
        ('approved', 'Approved'),
        ('denied', 'Denied'),
        ('offline', 'Offline'),
        ('online', 'Online'),
        ('imaging', 'Imaging in Progress'),
    ]

    # Identification
    hostname = models.CharField(max_length=255, unique=True)
    mac_address = models.CharField(max_length=17, unique=True)
    ip_address = models.GenericIPAddressField()
    api_token = models.CharField(max_length=64, unique=True, null=True, blank=True,
                                  help_text="API token for agent authentication")

    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    is_approved = models.BooleanField(default=False)

    # Hardware info
    hardware_model = models.CharField(max_length=255, blank=True, null=True)
    serial_number = models.CharField(max_length=255, blank=True, null=True)

    # Timestamps
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    approved_at = models.DateTimeField(null=True, blank=True)

    # Capabilities
    supports_s3 = models.BooleanField(default=True)
    supports_nfs = models.BooleanField(default=True)
    supports_disk = models.BooleanField(default=True)

    # Resource monitoring
    cpu_percent = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    memory_percent = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    memory_total_mb = models.BigIntegerField(null=True, blank=True)
    memory_used_mb = models.BigIntegerField(null=True, blank=True)
    disk_percent = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    disk_total_gb = models.BigIntegerField(null=True, blank=True)
    disk_used_gb = models.BigIntegerField(null=True, blank=True)
    temperature_celsius = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)

    # Network stats
    network_sent_mb = models.BigIntegerField(null=True, blank=True, help_text="Total MB sent since boot")
    network_recv_mb = models.BigIntegerField(null=True, blank=True, help_text="Total MB received since boot")

    # Available disks (for disk-to-disk imaging)
    available_disks = models.JSONField(default=list, blank=True, help_text="List of available disks detected on agent")

    # SSH access credentials
    ssh_username = models.CharField(max_length=100, default='pi', help_text="SSH username for remote access")
    ssh_password = models.CharField(max_length=255, blank=True, null=True, help_text="SSH password (stored in plaintext - use with caution)")
    ssh_key_path = models.CharField(max_length=500, blank=True, null=True, help_text="Path to private SSH key file on manager server")

    # Remote command execution
    COMMAND_CHOICES = [
        ('none', 'No Command'),
        ('reboot', 'Reboot'),
        ('shutdown', 'Shutdown'),
    ]
    pending_command = models.CharField(max_length=20, choices=COMMAND_CHOICES, default='none', help_text="Pending command to execute on agent")
    pending_command_at = models.DateTimeField(null=True, blank=True, help_text="When the pending command was issued")

    class Meta:
        ordering = ['-last_seen']

    def __str__(self):
        return f"{self.hostname} ({self.ip_address})"

    def is_truly_online(self, extended_timeout=False):
        """
        Check if agent is actually online based on recent heartbeat.

        Args:
            extended_timeout: If True, use extended timeout for imaging operations (10 minutes)
                            If False, use normal timeout (90 seconds)

        Returns True if heartbeat received within the timeout period.
        """
        from datetime import timedelta
        if not self.is_approved:
            return False

        time_since_heartbeat = timezone.now() - self.last_seen

        # Use extended timeout for imaging operations (bandwidth may be saturated)
        if extended_timeout:
            # 2 minutes timeout for imaging operations
            return time_since_heartbeat < timedelta(minutes=2)
        else:
            # 30 seconds for normal operations (6 missed heartbeats at 5s interval)
            return time_since_heartbeat < timedelta(seconds=30)

    def get_display_status(self):
        """
        Get the actual display status based on heartbeat freshness.
        This overrides the database status field for display purposes.
        """
        if not self.is_approved:
            if self.status == 'denied':
                return 'denied'
            return 'pending'

        # Check if currently imaging
        if self.status == 'imaging':
            # Use extended timeout for imaging (bandwidth may be saturated with data transfer)
            # Still show imaging if heartbeat is recent (within 10 minutes)
            if self.is_truly_online(extended_timeout=True):
                return 'imaging'
            # If imaging but no heartbeat for 10+ minutes, show offline
            return 'offline'

        # For approved agents, determine status from heartbeat (normal 90 second timeout)
        if self.is_truly_online(extended_timeout=False):
            return 'online'
        else:
            return 'offline'

    def approve(self):
        """Approve this agent."""
        self.is_approved = True
        self.status = 'online'
        self.approved_at = timezone.now()

        # Generate API token if not exists
        if not self.api_token:
            self.generate_api_token()

        self.save()

    def generate_api_token(self):
        """Generate a new API token for this agent."""
        import secrets
        self.api_token = secrets.token_urlsafe(48)  # 64 character URL-safe token
        return self.api_token

    def deny(self):
        """Deny this agent."""
        self.is_approved = False
        self.status = 'denied'
        self.save()

    def mark_online(self):
        """Mark agent as online."""
        if self.is_approved:
            old_status = self.status
            self.status = 'online'
            self.last_seen = timezone.now()
            self.save()

            # Broadcast status change if changed
            if old_status != 'online':
                self._broadcast_agent_update()

                # Send webhook notification
                from .webhooks import WebhookNotifier
                WebhookNotifier.notify_agent_online(self)

    def mark_offline(self):
        """Mark agent as offline."""
        old_status = self.status
        self.status = 'offline'
        self.save()

        # Broadcast status change if changed
        if old_status != 'offline':
            self._broadcast_agent_update()

            # Send webhook notification
            from .webhooks import WebhookNotifier
            WebhookNotifier.notify_agent_offline(self)

    def _broadcast_agent_update(self):
        """Broadcast agent update to dashboard via WebSocket."""
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        from django.utils.timesince import timesince

        channel_layer = get_channel_layer()
        if channel_layer:
            agent_data = {
                'id': self.id,
                'hostname': self.hostname,
                'ip_address': self.ip_address,
                'status': self.get_display_status(),  # Use display status instead of raw status
                'cpu_percent': float(self.cpu_percent) if self.cpu_percent else None,
                'memory_percent': float(self.memory_percent) if self.memory_percent else None,
                'memory_used_mb': self.memory_used_mb,
                'memory_total_mb': self.memory_total_mb,
                'disk_percent': float(self.disk_percent) if self.disk_percent else None,
                'disk_used_gb': self.disk_used_gb,
                'disk_total_gb': self.disk_total_gb,
                'temperature_celsius': float(self.temperature_celsius) if self.temperature_celsius else None,
                'last_seen_text': f"{timesince(self.last_seen)} ago" if self.last_seen else "Never",
            }

            # Broadcast to dashboard group
            async_to_sync(channel_layer.group_send)(
                'dashboard',
                {
                    'type': 'agent_update',
                    'agent': agent_data
                }
            )


class ImagingJob(models.Model):
    """Represents a forensic imaging job."""

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('queued', 'Queued'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]

    UPLOAD_METHOD_CHOICES = [
        ('disk', 'Disk to Disk'),
        ('nfs', 'NFS Share'),
    ]

    # Assignment
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='jobs')
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='jobs_created')

    # Job metadata
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    upload_method = models.CharField(max_length=10, choices=UPLOAD_METHOD_CHOICES)

    # libewf parameters
    case_number = models.CharField(max_length=255)
    evidence_number = models.CharField(max_length=255)
    examiner_name = models.CharField(max_length=255)
    description = models.TextField()
    image_name = models.CharField(max_length=255)

    # Storage configuration (JSON fields for flexibility)
    base_path = models.CharField(max_length=500, default='/tmp')

    # S3 configuration
    s3_access_key = models.CharField(max_length=255, blank=True, null=True)
    s3_secret_key = models.CharField(max_length=255, blank=True, null=True)
    s3_server = models.CharField(max_length=255, blank=True, null=True)
    s3_bucket_name = models.CharField(max_length=255, blank=True, null=True)
    s3_bucket_location = models.CharField(max_length=50, default='us-east-1', blank=True, null=True)
    s3_use_https = models.BooleanField(default=True)

    # NFS configuration
    nfs_server_config = models.ForeignKey('NFSServer', on_delete=models.SET_NULL, null=True, blank=True,
                                          related_name='jobs', help_text="Pre-configured NFS server")
    # Legacy fields (for backwards compatibility or manual override)
    nfs_server = models.CharField(max_length=255, blank=True, null=True)
    nfs_share = models.CharField(max_length=500, blank=True, null=True)
    nfs_mount_point = models.CharField(max_length=500, default='/mnt/nfs-share', blank=True, null=True)

    # SSH keys - many-to-many relationship for multiple authorized keys
    ssh_keys = models.ManyToManyField(SSHKey, blank=True, related_name='jobs',
                                      help_text="SSH public keys to authorize on agent")

    # Network configuration
    network_ssid = models.CharField(max_length=255, blank=True, null=True, help_text="WiFi SSID")
    network_password = models.CharField(max_length=255, blank=True, null=True, help_text="WiFi password")

    # Source device configuration
    source_device_path = models.CharField(max_length=255, blank=True, null=True,
                                         help_text="Device path to image (e.g., /dev/sda, /dev/nvme0n1)")

    # Progress tracking
    progress_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    acquired_bytes = models.BigIntegerField(default=0)
    total_bytes = models.BigIntegerField(default=0)
    transfer_speed = models.CharField(max_length=50, blank=True, null=True)  # e.g., "150 MiB/s"

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Error tracking
    error_message = models.TextField(blank=True, null=True)

    # Result information
    output_path = models.CharField(max_length=500, blank=True, null=True)
    image_size = models.BigIntegerField(null=True, blank=True)  # Final size in bytes

    # Hash verification
    source_md5 = models.CharField(max_length=32, blank=True, null=True, help_text="MD5 hash of source device")
    source_sha1 = models.CharField(max_length=40, blank=True, null=True, help_text="SHA1 hash of source device")
    source_sha256 = models.CharField(max_length=64, blank=True, null=True, help_text="SHA256 hash of source device")
    image_md5 = models.CharField(max_length=32, blank=True, null=True, help_text="MD5 hash of image file")
    image_sha1 = models.CharField(max_length=40, blank=True, null=True, help_text="SHA1 hash of image file")
    image_sha256 = models.CharField(max_length=64, blank=True, null=True, help_text="SHA256 hash of image file")
    hash_verified = models.BooleanField(default=False, help_text="Whether hashes have been verified to match")
    hash_verified_at = models.DateTimeField(null=True, blank=True)

    # Post-acquisition verification (using ewfverify after imaging)
    post_verification_passed = models.BooleanField(null=True, blank=True, help_text="Post-acquisition ewfverify result")
    post_verification_at = models.DateTimeField(null=True, blank=True, help_text="When post-verification was performed")

    # E01/EWF Metadata extraction
    ewf_format = models.CharField(max_length=50, blank=True, null=True, help_text="EWF format (encase5, encase6, etc)")
    ewf_compression = models.CharField(max_length=50, blank=True, null=True)
    ewf_sector_count = models.BigIntegerField(null=True, blank=True)
    ewf_bytes_per_sector = models.IntegerField(null=True, blank=True)
    ewf_media_size = models.BigIntegerField(null=True, blank=True)
    ewf_chunk_size = models.IntegerField(null=True, blank=True)
    ewf_guid = models.CharField(max_length=36, blank=True, null=True, help_text="GUID from EWF metadata")
    ewf_acquiry_date = models.DateTimeField(null=True, blank=True)

    # Forensic workflow status
    forensic_documentation_complete = models.BooleanField(default=False,
                                                          help_text="All forensic documentation completed")
    qa_review_required = models.BooleanField(default=True,
                                             help_text="Does this job require QA review?")
    qa_review_completed = models.BooleanField(default=False)

    # Forensic integrity verification (performed automatically on job completion)
    integrity_verified = models.BooleanField(default=False,
                                             help_text="Cryptographic integrity verification performed")
    integrity_verified_at = models.DateTimeField(null=True, blank=True,
                                                  help_text="When integrity verification was performed")
    integrity_valid = models.BooleanField(null=True, blank=True,
                                          help_text="Result of integrity verification")
    integrity_report = models.JSONField(default=dict, blank=True,
                                        help_text="Full integrity verification report")

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Job {self.id}: {self.case_number} - {self.evidence_number} on {self.agent.hostname}"

    def start(self):
        """Mark job as started."""
        self.status = 'in_progress'
        self.started_at = timezone.now()
        self.save()

    def complete(self):
        """Mark job as completed."""
        self.status = 'completed'
        self.completed_at = timezone.now()
        self.progress_percentage = 100
        self.save()

        # Automatically verify forensic integrity
        self.verify_and_seal_integrity()

    def verify_and_seal_integrity(self):
        """
        Verify and seal the forensic integrity of this job.
        Creates an immutable snapshot of the verification state.
        This should be called immediately after job completion.
        """
        logger.info(f"Performing automatic integrity verification for Job {self.id}")

        try:
            # Verify job logs chain
            logs_result = JobLog.verify_job_chain_integrity(self)

            # Verify chain of custody
            coc_result = EvidenceHandlingEvent.verify_job_chain_integrity(self)

            # Determine overall validity
            overall_valid = logs_result['valid'] and coc_result['valid']

            # Store verification results
            self.integrity_verified = True
            self.integrity_verified_at = timezone.now()
            self.integrity_valid = overall_valid
            self.integrity_report = {
                'timestamp': timezone.now().isoformat(),
                'job_id': self.id,
                'case_number': self.case_number,
                'evidence_number': self.evidence_number,
                'overall_valid': overall_valid,
                'job_logs': logs_result,
                'chain_of_custody': coc_result
            }
            self.save(update_fields=['integrity_verified', 'integrity_verified_at',
                                    'integrity_valid', 'integrity_report'])

            # Log the verification
            logger.info(f"Job {self.id} integrity verification complete: {'VALID' if overall_valid else 'INVALID'}")

            # Create audit log entry
            AuditLog.log_action(
                user=None,
                action='job_integrity_verified',
                description=f"Automatic integrity verification for Job {self.id}: {'PASSED' if overall_valid else 'FAILED'}",
                content_object=self,
                extra_data={
                    'overall_valid': overall_valid,
                    'logs_valid': logs_result['valid'],
                    'logs_total': logs_result['total_records'],
                    'coc_valid': coc_result['valid'],
                    'coc_total': coc_result['total_records']
                }
            )

            return overall_valid

        except Exception as e:
            logger.error(f"Failed to verify integrity for Job {self.id}: {e}")
            return False

    def fail(self, error_message):
        """Mark job as failed."""
        self.status = 'failed'
        self.error_message = error_message
        self.completed_at = timezone.now()
        self.save()

    def cancel(self):
        """Cancel the job."""
        self.status = 'cancelled'
        self.completed_at = timezone.now()
        self.save()

    def restart(self):
        """Restart the job - reset to queued status and clear progress."""
        self.status = 'queued'
        self.progress_percentage = 0
        self.acquired_bytes = 0
        self.total_bytes = 0
        self.transfer_speed = None
        self.started_at = None
        self.completed_at = None
        self.error_message = None
        # Keep original hashes and verification data for comparison if job completes again
        self.save()

    def update_progress(self, percentage, acquired_bytes=None, total_bytes=None, speed=None):
        """Update job progress."""
        self.progress_percentage = percentage
        if acquired_bytes is not None:
            self.acquired_bytes = acquired_bytes
        if total_bytes is not None:
            self.total_bytes = total_bytes
        if speed is not None:
            self.transfer_speed = speed
        self.save()

    def to_yaml_config(self):
        """Generate YAML configuration for the agent."""
        config = {
            'imager-config': {
                'base_path': self.base_path,
                'image_name': self.image_name,
                'case_number': self.case_number,
                'evidence_number': self.evidence_number,
                'examiner_name': self.examiner_name,
                'description': self.description,
            },
            'system': {
                'upload_method': self.upload_method,
            }
        }

        # Add source device path if specified (for disk-to-disk imaging)
        if self.source_device_path:
            config['system']['source_device'] = self.source_device_path

        # Add network config if provided
        if self.network_ssid:
            config['system']['network-config'] = {
                'SSID': self.network_ssid,
                'Password': self.network_password or '',
            }

        # Add SSH keys if provided (as multi-line string)
        ssh_keys_list = self.ssh_keys.all()
        if ssh_keys_list.exists():
            # Join all public keys with newlines
            ssh_keys_str = '\n'.join([key.public_key for key in ssh_keys_list])
            config['system']['ssh-keys'] = ssh_keys_str

        # Add S3 config if needed
        if self.upload_method == 's3':
            config['system']['s3-config'] = {
                'access-key': self.s3_access_key,
                'secret-key': self.s3_secret_key,
                's3-server': self.s3_server,
                'bucketname': self.s3_bucket_name,
                'bucketlocation': self.s3_bucket_location,
                'use-https': str(self.s3_use_https),
            }

        # Add NFS config if needed
        if self.upload_method == 'nfs':
            # Use pre-configured NFS server if available, otherwise use manual fields
            if self.nfs_server_config:
                # Pre-configured server (saved in DB)
                config['system']['nfs-config'] = {
                    'server': self.nfs_server_config.server,
                    'share': self.nfs_server_config.share,
                    'mount_point': self.nfs_server_config.mount_point,
                }
                # Add optional fields if present
                if self.nfs_server_config.nfs_version:
                    config['system']['nfs-config']['nfs_version'] = self.nfs_server_config.nfs_version
                if self.nfs_server_config.mount_options:
                    config['system']['nfs-config']['mount_options'] = self.nfs_server_config.mount_options
            else:
                # Manual/temporary configuration
                config['system']['nfs-config'] = {
                    'server': self.nfs_server,
                    'share': self.nfs_share,
                    'mount_point': self.nfs_mount_point or '/mnt/nfs-share',
                }

        return config


class JobLog(models.Model):
    """Log entries for imaging jobs - IMMUTABLE for forensic integrity."""

    LEVEL_CHOICES = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
    ]

    job = models.ForeignKey(ImagingJob, on_delete=models.CASCADE, related_name='logs')
    level = models.CharField(max_length=10, choices=LEVEL_CHOICES, default='info')
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    # Forensic immutability - cryptographic hash chain
    record_hash = models.CharField(max_length=64, blank=True, editable=False,
                                   help_text="SHA256 hash of this record for tamper detection")
    previous_hash = models.CharField(max_length=64, blank=True, editable=False,
                                     help_text="Hash of previous record in chain for this job")

    class Meta:
        ordering = ['timestamp']

    def __str__(self):
        return f"[{self.level.upper()}] {self.timestamp}: {self.message[:50]}"

    def _calculate_hash(self):
        """Calculate SHA256 hash of this record for tamper detection."""
        hash_data = f"{self.job_id}|{self.timestamp.isoformat()}|{self.level}|{self.message}|{self.previous_hash}"
        return hashlib.sha256(hash_data.encode('utf-8')).hexdigest()

    def save(self, *args, **kwargs):
        """Override save to implement immutability and hash chaining."""
        if self.pk is not None:
            raise ValidationError("Job log records are immutable and cannot be modified for forensic integrity.")

        # Get previous record's hash for this job's chain
        try:
            last_record = JobLog.objects.filter(job=self.job).order_by('-id').first()
            self.previous_hash = last_record.record_hash if last_record else '0' * 64
        except Exception as e:
            logger.warning(f"Could not get previous hash: {e}")
            self.previous_hash = '0' * 64

        # Save first to get timestamp
        is_new = self.pk is None
        if is_new:
            super().save(*args, **kwargs)
            self.record_hash = self._calculate_hash()
            JobLog.objects.filter(pk=self.pk).update(
                record_hash=self.record_hash,
                previous_hash=self.previous_hash
            )
        else:
            super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Prevent deletion of job log records for forensic integrity."""
        raise ValidationError("Job log records cannot be deleted for forensic integrity. They are immutable.")

    def verify_hash(self):
        """Verify that this record's hash is valid."""
        calculated_hash = self._calculate_hash()
        return self.record_hash == calculated_hash

    @classmethod
    def verify_job_chain_integrity(cls, job):
        """Verify the integrity of log chain for a specific job."""
        records = cls.objects.filter(job=job).order_by('id')
        broken_chains = []
        total = records.count()

        prev_hash = '0' * 64
        for record in records:
            if record.previous_hash != prev_hash:
                broken_chains.append({
                    'id': record.id,
                    'reason': 'previous_hash_mismatch',
                    'expected': prev_hash,
                    'actual': record.previous_hash
                })

            if not record.verify_hash():
                broken_chains.append({
                    'id': record.id,
                    'reason': 'invalid_hash'
                })

            prev_hash = record.record_hash

        return {
            'valid': len(broken_chains) == 0,
            'total_records': total,
            'broken_chains': broken_chains,
            'details': f"Job {job.id}: {total} log records. {'All valid.' if len(broken_chains) == 0 else f'{len(broken_chains)} issues found.'}"
        }


class RemoteShellSession(models.Model):
    """Track remote shell sessions to agents for security auditing."""

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('closed', 'Closed'),
        ('terminated', 'Terminated'),
    ]

    # Session info
    session_id = models.CharField(max_length=64, unique=True, db_index=True)
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='shell_sessions')
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='shell_sessions')

    # Timestamps
    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    last_activity = models.DateTimeField(auto_now=True)

    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')

    # Audit info
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True, null=True)

    # Command logging
    command_count = models.IntegerField(default=0)

    # Session transcript (stored separately for performance)
    transcript_path = models.CharField(max_length=500, blank=True, null=True,
                                       help_text="Path to full session transcript")

    class Meta:
        ordering = ['-started_at']
        indexes = [
            models.Index(fields=['agent', '-started_at']),
            models.Index(fields=['user', '-started_at']),
        ]

    def __str__(self):
        username = self.user.username if self.user else 'unknown'
        return f"Shell session by {username} to {self.agent.hostname} at {self.started_at}"

    def close(self):
        """Close the session."""
        self.status = 'closed'
        self.ended_at = timezone.now()
        self.save()


class WriteBlockerVerification(models.Model):
    """Documentation of write-blocker usage and verification."""

    job = models.OneToOneField('ImagingJob', on_delete=models.CASCADE, related_name='write_blocker')

    # Write-blocker details
    write_blocker_used = models.BooleanField(default=True, help_text="Was a write-blocker used?")
    write_blocker_model = models.CharField(max_length=255, help_text="e.g., Tableau T8-R2")
    write_blocker_serial = models.CharField(max_length=255, blank=True, help_text="Serial number of device")
    write_blocker_type = models.CharField(max_length=50, choices=[
        ('hardware', 'Hardware Write Blocker'),
        ('software', 'Software Write Blocker'),
        ('none', 'No Write Blocker Used')
    ], default='hardware')

    # Pre-imaging verification test
    pre_test_performed = models.BooleanField(default=False, help_text="Was write-blocking test performed?")
    pre_test_passed = models.BooleanField(default=False, help_text="Did the test pass?")
    pre_test_timestamp = models.DateTimeField(null=True, blank=True)
    pre_test_performed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True,
                                              related_name='write_blocker_tests')
    pre_test_method = models.TextField(blank=True, help_text="How was the test performed?")

    # During imaging verification
    write_operations_detected = models.IntegerField(default=0, help_text="Number of write ops detected (should be 0)")
    write_blocker_verified = models.BooleanField(default=False, help_text="Write-blocker verified during imaging")

    # Post-imaging verification
    post_verification_performed = models.BooleanField(default=False)
    post_verification_passed = models.BooleanField(default=False)
    post_verification_notes = models.TextField(blank=True)

    # Documentation
    test_results = models.TextField(blank=True, help_text="Detailed test results")
    photos = models.JSONField(default=list, help_text="Photos of write-blocker setup")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Write Blocker Verification"
        verbose_name_plural = "Write Blocker Verifications"

    def __str__(self):
        return f"Write Blocker for Job #{self.job_id}"


class SourceDevice(models.Model):
    """Detailed documentation of the source device being imaged."""

    job = models.OneToOneField('ImagingJob', on_delete=models.CASCADE, related_name='source_device')

    # Device identification
    manufacturer = models.CharField(max_length=255, blank=True, help_text="e.g., Samsung, Western Digital")
    model_number = models.CharField(max_length=255, blank=True)
    serial_number = models.CharField(max_length=255, blank=True)
    firmware_version = models.CharField(max_length=100, blank=True)

    # Capacity
    capacity_bytes = models.BigIntegerField(null=True, blank=True)
    capacity_formatted = models.CharField(max_length=50, blank=True, help_text="e.g., 500GB")

    # Device type
    device_type = models.CharField(max_length=50, choices=[
        ('hdd', 'Hard Disk Drive'),
        ('ssd', 'Solid State Drive'),
        ('usb', 'USB Flash Drive'),
        ('sd_card', 'SD Card'),
        ('phone', 'Mobile Phone'),
        ('tablet', 'Tablet'),
        ('computer', 'Computer'),
        ('other', 'Other')
    ], default='hdd')

    # Interface
    interface_type = models.CharField(max_length=50, blank=True,
                                     help_text="SATA, USB 3.0, NVMe, etc.")

    # Physical condition
    physical_condition = models.TextField(help_text="Describe physical condition, damage, wear")
    damage_documented = models.BooleanField(default=False)
    damage_description = models.TextField(blank=True)

    # SMART data
    smart_status = models.CharField(max_length=20, choices=[
        ('passed', 'PASSED'),
        ('failed', 'FAILED'),
        ('not_available', 'N/A')
    ], default='not_available')
    power_on_hours = models.IntegerField(null=True, blank=True)
    power_cycle_count = models.IntegerField(null=True, blank=True)
    reallocated_sectors = models.IntegerField(null=True, blank=True)
    pending_sectors = models.IntegerField(null=True, blank=True)
    uncorrectable_sectors = models.IntegerField(null=True, blank=True)
    smart_data_json = models.JSONField(default=dict, help_text="Full SMART data dump")

    # Evidence tracking
    evidence_bag_number = models.CharField(max_length=100, blank=True)
    evidence_seal_number = models.CharField(max_length=100, blank=True)
    sealed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True,
                                  related_name='sealed_evidence')
    sealed_at = models.DateTimeField(null=True, blank=True)

    # Storage location
    storage_location = models.CharField(max_length=255, blank=True,
                                       help_text="Evidence locker, room number, etc.")

    # Photos and documentation
    device_photos = models.JSONField(default=list, help_text="List of device photo URLs")
    label_photos = models.JSONField(default=list, help_text="Photos of labels/serial numbers")
    damage_photos = models.JSONField(default=list, help_text="Photos of damage")

    # Additional notes
    notes = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Source Device"
        verbose_name_plural = "Source Devices"

    def __str__(self):
        return f"{self.manufacturer} {self.model_number} - Job #{self.job_id}"

    def parse_smart_data(self, smart_json):
        """
        Parse SMART data from agent and update fields.

        Args:
            smart_json: Dict containing SMART data from smartctl or similar tool
        """
        if not smart_json or not isinstance(smart_json, dict):
            return False

        try:
            # Store full JSON
            self.smart_data_json = smart_json

            # Parse device identification fields
            if 'model_name' in smart_json and not self.model_number:
                self.model_number = smart_json['model_name']
            if 'model_family' in smart_json and not self.manufacturer:
                # Extract manufacturer from model family (e.g., "Western Digital Blue")
                family = smart_json['model_family']
                if 'Western Digital' in family or 'WDC' in family:
                    self.manufacturer = 'Western Digital'
                elif 'Seagate' in family:
                    self.manufacturer = 'Seagate'
                elif 'Samsung' in family:
                    self.manufacturer = 'Samsung'
                elif 'Toshiba' in family:
                    self.manufacturer = 'Toshiba'
                elif 'Hitachi' in family or 'HGST' in family:
                    self.manufacturer = 'Hitachi/HGST'
                elif 'Crucial' in family:
                    self.manufacturer = 'Crucial'
                elif 'SanDisk' in family:
                    self.manufacturer = 'SanDisk'
                else:
                    # Use the first word as manufacturer
                    self.manufacturer = family.split()[0] if family else ''

            if 'serial_number' in smart_json and not self.serial_number:
                self.serial_number = smart_json['serial_number']

            if 'firmware_version' in smart_json and not self.firmware_version:
                self.firmware_version = smart_json['firmware_version']

            # Parse capacity
            if 'user_capacity' in smart_json and not self.capacity_bytes:
                if isinstance(smart_json['user_capacity'], dict):
                    self.capacity_bytes = smart_json['user_capacity'].get('bytes', 0)
                else:
                    self.capacity_bytes = int(smart_json['user_capacity'])

                # Generate formatted capacity
                if self.capacity_bytes:
                    gb = self.capacity_bytes / (1024**3)
                    if gb >= 1000:
                        self.capacity_formatted = f"{gb/1000:.1f} TB"
                    else:
                        self.capacity_formatted = f"{gb:.1f} GB"

            # Detect device type
            if 'rotation_rate' in smart_json and not self.device_type:
                rotation = smart_json.get('rotation_rate', 0)
                if rotation == 0 or str(rotation).lower() == 'solid state device':
                    self.device_type = 'ssd'
                else:
                    self.device_type = 'hdd'

            # Detect interface type
            if 'interface' in smart_json and not self.interface_type:
                self.interface_type = smart_json['interface']
            elif 'sata_version' in smart_json and not self.interface_type:
                if isinstance(smart_json['sata_version'], dict):
                    self.interface_type = smart_json['sata_version'].get('string', 'SATA')
                else:
                    self.interface_type = 'SATA'

            # Parse overall SMART status
            if 'smart_status' in smart_json:
                status = smart_json['smart_status']
                if isinstance(status, dict) and 'passed' in status:
                    self.smart_status = 'passed' if status['passed'] else 'failed'
                elif isinstance(status, str):
                    self.smart_status = status.lower()

            # Parse power-on hours
            if 'power_on_hours' in smart_json:
                self.power_on_hours = int(smart_json['power_on_hours'])
            elif 'power_on_time' in smart_json:
                # Convert from other formats if needed
                self.power_on_hours = int(smart_json['power_on_time'].get('hours', 0))

            # Parse power cycle count
            if 'power_cycle_count' in smart_json:
                self.power_cycle_count = int(smart_json['power_cycle_count'])

            # Parse sector information
            if 'reallocated_sectors' in smart_json:
                self.reallocated_sectors = int(smart_json['reallocated_sectors'])
            if 'pending_sectors' in smart_json:
                self.pending_sectors = int(smart_json['pending_sectors'])
            if 'uncorrectable_sectors' in smart_json:
                self.uncorrectable_sectors = int(smart_json['uncorrectable_sectors'])

            # Parse from ata_smart_attributes if present (smartctl format)
            if 'ata_smart_attributes' in smart_json:
                attrs = smart_json['ata_smart_attributes'].get('table', [])
                for attr in attrs:
                    attr_id = attr.get('id')
                    raw_value = attr.get('raw', {}).get('value', 0)

                    # Common SMART attribute IDs
                    if attr_id == 9:  # Power-On Hours
                        self.power_on_hours = int(raw_value)
                    elif attr_id == 12:  # Power Cycle Count
                        self.power_cycle_count = int(raw_value)
                    elif attr_id == 5:  # Reallocated Sector Count
                        self.reallocated_sectors = int(raw_value)
                    elif attr_id == 197:  # Current Pending Sector Count
                        self.pending_sectors = int(raw_value)
                    elif attr_id == 198:  # Uncorrectable Sector Count
                        self.uncorrectable_sectors = int(raw_value)

            self.save()
            return True

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error parsing SMART data: {e}")
            return False


class QAReview(models.Model):
    """Quality assurance review of forensic imaging job."""

    job = models.OneToOneField('ImagingJob', on_delete=models.CASCADE, related_name='qa_review')

    # Review status
    review_status = models.CharField(max_length=50, choices=[
        ('pending', 'Pending Review'),
        ('in_review', 'In Review'),
        ('approved', 'Approved'),
        ('requires_correction', 'Requires Correction'),
        ('rejected', 'Rejected')
    ], default='pending')

    # Reviewer information
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True,
                                   related_name='qa_reviews_performed')
    review_started_at = models.DateTimeField(null=True, blank=True)
    review_completed_at = models.DateTimeField(null=True, blank=True)

    # Checklist items
    hash_verification_checked = models.BooleanField(default=False, help_text="Hash values verified")
    hash_verification_passed = models.BooleanField(default=False)
    hash_verification_notes = models.TextField(blank=True)

    metadata_verified = models.BooleanField(default=False, help_text="Metadata completeness checked")
    metadata_complete = models.BooleanField(default=False)
    metadata_notes = models.TextField(blank=True)

    documentation_checked = models.BooleanField(default=False, help_text="Documentation reviewed")
    documentation_complete = models.BooleanField(default=False)
    documentation_notes = models.TextField(blank=True)

    chain_of_custody_checked = models.BooleanField(default=False)
    chain_of_custody_intact = models.BooleanField(default=False)
    chain_of_custody_notes = models.TextField(blank=True)

    write_blocker_checked = models.BooleanField(default=False)
    write_blocker_verified = models.BooleanField(default=False)
    write_blocker_notes = models.TextField(blank=True)

    image_integrity_checked = models.BooleanField(default=False)
    image_integrity_verified = models.BooleanField(default=False)
    image_integrity_notes = models.TextField(blank=True)

    # Overall assessment
    all_checks_passed = models.BooleanField(default=False)
    reviewer_comments = models.TextField(blank=True, help_text="Overall review comments")
    corrections_required = models.TextField(blank=True, help_text="List corrections needed")

    # Final approval
    final_approval = models.BooleanField(default=False)
    final_approval_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True,
                                         related_name='qa_final_approvals')
    final_approval_date = models.DateTimeField(null=True, blank=True)
    final_approval_notes = models.TextField(blank=True)

    # Correction tracking
    corrections_made = models.BooleanField(default=False)
    corrections_description = models.TextField(blank=True)
    re_review_required = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "QA Review"
        verbose_name_plural = "QA Reviews"

    def __str__(self):
        return f"QA Review for Job #{self.job_id} - {self.review_status}"


class EvidenceHandlingEvent(models.Model):
    """Timeline of evidence handling events for chain of custody."""

    job = models.ForeignKey('ImagingJob', on_delete=models.CASCADE, related_name='handling_events')

    # Event type
    event_type = models.CharField(max_length=50, choices=[
        ('received', 'Evidence Received'),
        ('examined', 'Physical Examination'),
        ('photographed', 'Photographed'),
        ('sealed', 'Evidence Sealed'),
        ('write_blocker_tested', 'Write Blocker Tested'),
        ('imaging_started', 'Imaging Started'),
        ('imaging_completed', 'Imaging Completed'),
        ('hash_verified', 'Hash Verified'),
        ('qa_reviewed', 'QA Reviewed'),
        ('checked_out', 'Checked Out'),
        ('checked_in', 'Checked In'),
        ('transferred', 'Custody Transferred'),
        ('stored', 'Stored in Evidence'),
        ('returned', 'Returned to Owner'),
        ('destroyed', 'Disposed/Destroyed'),
        ('note', 'Note/Observation')
    ])

    # Event details
    event_timestamp = models.DateTimeField(auto_now_add=True)
    performed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    location = models.CharField(max_length=255, blank=True, help_text="Where event occurred")

    # Description
    event_description = models.TextField(help_text="Detailed description of event")

    # Witnesses
    witnesses = models.ManyToManyField(User, related_name='witnessed_events', blank=True)
    witness_names = models.TextField(blank=True, help_text="Non-system user witnesses")

    # Documentation
    photos_taken = models.JSONField(default=list, help_text="Photos taken during event")
    forms_completed = models.JSONField(default=list, help_text="Forms/documents completed")

    # Transfer information (if custody transfer)
    transferred_from = models.ForeignKey(User, on_delete=models.SET_NULL, null=True,
                                        related_name='evidence_transferred_from', blank=True)
    transferred_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True,
                                      related_name='evidence_transferred_to', blank=True)
    transfer_reason = models.TextField(blank=True)

    # Additional metadata
    evidence_condition = models.CharField(max_length=255, blank=True,
                                         help_text="Condition at time of event")
    notes = models.TextField(blank=True)

    # Forensic immutability - cryptographic hash chain
    record_hash = models.CharField(max_length=64, blank=True, editable=False,
                                   help_text="SHA256 hash of this record for tamper detection")
    previous_hash = models.CharField(max_length=64, blank=True, editable=False,
                                     help_text="Hash of previous event in chain for this job")

    class Meta:
        ordering = ['event_timestamp']
        verbose_name = "Evidence Handling Event"
        verbose_name_plural = "Evidence Handling Events"

    def __str__(self):
        return f"{self.event_type} - Job #{self.job_id} at {self.event_timestamp}"

    def _calculate_hash(self):
        """Calculate SHA256 hash of this record for tamper detection."""
        performed_by_username = self.performed_by.username if self.performed_by else 'system'
        hash_data = f"{self.job_id}|{self.event_timestamp.isoformat()}|{self.event_type}|{performed_by_username}|{self.event_description}|{self.previous_hash}"
        return hashlib.sha256(hash_data.encode('utf-8')).hexdigest()

    def save(self, *args, **kwargs):
        """Override save to implement immutability and hash chaining."""
        if self.pk is not None:
            raise ValidationError("Evidence handling events are immutable and cannot be modified for chain of custody integrity.")

        # Get previous record's hash for this job's chain
        try:
            last_record = EvidenceHandlingEvent.objects.filter(job=self.job).order_by('-id').first()
            self.previous_hash = last_record.record_hash if last_record else '0' * 64
        except Exception as e:
            logger.warning(f"Could not get previous hash: {e}")
            self.previous_hash = '0' * 64

        # Save first to get timestamp
        is_new = self.pk is None
        if is_new:
            super().save(*args, **kwargs)
            self.record_hash = self._calculate_hash()
            EvidenceHandlingEvent.objects.filter(pk=self.pk).update(
                record_hash=self.record_hash,
                previous_hash=self.previous_hash
            )
        else:
            super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Prevent deletion of chain of custody events for forensic integrity."""
        raise ValidationError("Evidence handling events cannot be deleted for chain of custody integrity. They are immutable.")

    def verify_hash(self):
        """Verify that this record's hash is valid."""
        calculated_hash = self._calculate_hash()
        return self.record_hash == calculated_hash

    @classmethod
    def verify_job_chain_integrity(cls, job):
        """Verify the integrity of chain of custody for a specific job."""
        records = cls.objects.filter(job=job).order_by('id')
        broken_chains = []
        total = records.count()

        prev_hash = '0' * 64
        for record in records:
            if record.previous_hash != prev_hash:
                broken_chains.append({
                    'id': record.id,
                    'event_type': record.event_type,
                    'timestamp': record.event_timestamp.isoformat(),
                    'reason': 'previous_hash_mismatch',
                    'expected': prev_hash,
                    'actual': record.previous_hash
                })

            if not record.verify_hash():
                broken_chains.append({
                    'id': record.id,
                    'event_type': record.event_type,
                    'timestamp': record.event_timestamp.isoformat(),
                    'reason': 'invalid_hash'
                })

            prev_hash = record.record_hash

        return {
            'valid': len(broken_chains) == 0,
            'total_records': total,
            'broken_chains': broken_chains,
            'details': f"Job {job.id}: {total} CoC events. {'All valid.' if len(broken_chains) == 0 else f'{len(broken_chains)} issues found.'}"
        }


class EvidencePhoto(models.Model):
    """Photos attached to evidence handling events for documentation."""

    event = models.ForeignKey(EvidenceHandlingEvent, on_delete=models.CASCADE, related_name='photos')

    # Photo file
    photo = models.ImageField(
        upload_to='evidence_photos/%Y/%m/%d/',
        help_text="Photo of evidence, device, seals, write-blocker, etc."
    )

    # Metadata
    caption = models.CharField(max_length=255, blank=True, help_text="Brief description of photo")
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    # Photo details
    file_size = models.IntegerField(null=True, blank=True, help_text="File size in bytes")
    image_width = models.IntegerField(null=True, blank=True)
    image_height = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ['uploaded_at']
        verbose_name = "Evidence Photo"
        verbose_name_plural = "Evidence Photos"

    def __str__(self):
        return f"Photo for {self.event} - {self.caption[:50]}"

    def save(self, *args, **kwargs):
        """Auto-populate file size and dimensions on save."""
        if self.photo:
            # Get file size
            self.file_size = self.photo.size

            # Get image dimensions
            try:
                from PIL import Image
                img = Image.open(self.photo)
                self.image_width, self.image_height = img.size
            except:
                pass

        super().save(*args, **kwargs)


class DigitalSignature(models.Model):
    """Digital signatures for evidence handling events with cryptographic verification."""

    event = models.ForeignKey(EvidenceHandlingEvent, on_delete=models.CASCADE, related_name='signatures')

    # Signer information
    signer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='signatures')
    signer_role = models.CharField(max_length=100, help_text="Role of signer (e.g., Evidence Custodian, Examiner)")
    signer_name = models.CharField(max_length=255, help_text="Full name of signer for the record")

    # Signature data (base64 encoded PNG)
    signature_data = models.TextField(help_text="Base64 encoded signature image")

    # Verification and metadata
    signed_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, help_text="IP address of signer")
    signature_hash = models.CharField(max_length=64, help_text="SHA256 hash of signature data for verification")

    # What is being signed
    event_snapshot = models.JSONField(help_text="Snapshot of event data at time of signature")

    # Verification status
    is_verified = models.BooleanField(default=True, help_text="Whether signature verification passes")
    verification_notes = models.TextField(blank=True, help_text="Notes about verification failures")

    class Meta:
        ordering = ['signed_at']
        verbose_name = "Digital Signature"
        verbose_name_plural = "Digital Signatures"

    def __str__(self):
        return f"Signature by {self.signer_name} on {self.signed_at}"

    def save(self, *args, **kwargs):
        """Generate signature hash on save."""
        if self.signature_data and not self.signature_hash:
            import hashlib
            self.signature_hash = hashlib.sha256(self.signature_data.encode()).hexdigest()
        super().save(*args, **kwargs)

    def verify_signature(self):
        """Verify the signature hash matches the current data."""
        import hashlib
        current_hash = hashlib.sha256(self.signature_data.encode()).hexdigest()
        return current_hash == self.signature_hash

    def get_signature_image_url(self):
        """Return data URL for displaying signature image."""
        if self.signature_data:
            # Check if it already has the data URL prefix
            if self.signature_data.startswith('data:image/png;base64,'):
                return self.signature_data
            else:
                return f"data:image/png;base64,{self.signature_data}"
        return None


class ShellCommand(models.Model):
    """Individual commands executed in remote shell sessions."""

    session = models.ForeignKey(RemoteShellSession, on_delete=models.CASCADE, related_name='commands')
    command = models.TextField(help_text="Command executed")
    output = models.TextField(blank=True, help_text="Command output (truncated if too long)")
    exit_code = models.IntegerField(null=True, blank=True)
    executed_at = models.DateTimeField(auto_now_add=True)
    duration_ms = models.IntegerField(null=True, blank=True, help_text="Execution time in milliseconds")

    class Meta:
        ordering = ['executed_at']

    def __str__(self):
        return f"[{self.executed_at}] {self.command[:50]}"


class MobileDevice(models.Model):
    """Represents a mobile device connected for extraction (iOS/Android)."""

    DEVICE_TYPE_CHOICES = [
        ('ios', 'iOS (iPhone/iPad)'),
        ('android', 'Android'),
    ]

    CONNECTION_STATUS_CHOICES = [
        ('connected', 'Connected'),
        ('disconnected', 'Disconnected'),
        ('extracting', 'Extracting'),
    ]

    # Device identification
    device_type = models.CharField(max_length=20, choices=DEVICE_TYPE_CHOICES)
    serial_number = models.CharField(max_length=100, db_index=True,
                                    help_text="Device serial number or UDID")
    udid = models.CharField(max_length=100, blank=True,
                           help_text="iOS UDID or Android serial (same as serial_number for Android)")
    model = models.CharField(max_length=100, blank=True,
                            help_text="Device model (e.g., iPhone 13, Pixel 6)")
    manufacturer = models.CharField(max_length=100, blank=True,
                                   help_text="Apple, Samsung, Google, etc.")
    product_type = models.CharField(max_length=100, blank=True,
                                   help_text="iOS: iPhone13,2 | Android: SM-G998B")

    # Operating System
    os_version = models.CharField(max_length=50, blank=True,
                                 help_text="iOS 17.1.1 or Android 13")
    build_version = models.CharField(max_length=100, blank=True,
                                    help_text="Detailed build number")

    # Device state
    connection_status = models.CharField(max_length=20, choices=CONNECTION_STATUS_CHOICES,
                                        default='disconnected')
    is_locked = models.BooleanField(default=True,
                                    help_text="Device has passcode/pattern lock active")
    is_encrypted = models.BooleanField(default=True,
                                      help_text="Device storage is encrypted")
    is_jailbroken = models.BooleanField(default=False,
                                       help_text="iOS: Jailbroken | Android: Rooted")

    # Android specific
    usb_debugging_enabled = models.BooleanField(default=False,
                                               help_text="Android: USB debugging is enabled")
    developer_mode_enabled = models.BooleanField(default=False,
                                                help_text="Android: Developer options enabled")

    # Connection info
    connected_agent = models.ForeignKey('Agent', on_delete=models.SET_NULL, null=True, blank=True,
                                       related_name='connected_mobile_devices',
                                       help_text="Agent this device is currently connected to")
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    # Physical characteristics
    device_name = models.CharField(max_length=200, blank=True,
                                  help_text="User-assigned name (e.g., 'John's iPhone')")
    imei = models.CharField(max_length=20, blank=True,
                           help_text="International Mobile Equipment Identity")
    imei2 = models.CharField(max_length=20, blank=True,
                            help_text="Second IMEI for dual-SIM devices")
    phone_number = models.CharField(max_length=20, blank=True,
                                   help_text="Phone number if detectable")
    iccid = models.CharField(max_length=30, blank=True,
                            help_text="SIM card Integrated Circuit Card ID")
    wifi_mac = models.CharField(max_length=17, blank=True,
                               help_text="WiFi MAC address")
    bluetooth_mac = models.CharField(max_length=17, blank=True,
                                    help_text="Bluetooth MAC address")

    # Battery & storage
    battery_level = models.IntegerField(null=True, blank=True,
                                       help_text="Battery percentage (0-100)")
    battery_state = models.CharField(max_length=20, blank=True,
                                    help_text="charging, full, unplugged")
    storage_total_bytes = models.BigIntegerField(null=True, blank=True,
                                                 help_text="Total storage in bytes")
    storage_used_bytes = models.BigIntegerField(null=True, blank=True,
                                                help_text="Used storage in bytes")

    # Device info (iOS specific)
    ios_device_class = models.CharField(max_length=50, blank=True,
                                       help_text="iPhone, iPad, iPod")
    ios_hardware_model = models.CharField(max_length=50, blank=True,
                                         help_text="N71mAP (internal model)")
    ios_device_color = models.CharField(max_length=50, blank=True)
    ios_region_info = models.CharField(max_length=10, blank=True,
                                      help_text="LL/A (US), etc.")

    # Device info (Android specific)
    android_sdk_version = models.IntegerField(null=True, blank=True,
                                             help_text="Android SDK API level")
    android_security_patch = models.CharField(max_length=20, blank=True,
                                             help_text="Security patch level date")
    android_fingerprint = models.CharField(max_length=500, blank=True,
                                          help_text="Build fingerprint")

    # Complete device info JSON
    device_info_json = models.JSONField(default=dict, blank=True,
                                       help_text="Complete raw device information")

    class Meta:
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['device_type', 'connection_status']),
            models.Index(fields=['serial_number']),
        ]

    def __str__(self):
        name = self.device_name or f"{self.manufacturer} {self.model}".strip() or "Unknown Device"
        return f"{name} ({self.serial_number[:8]}...)"

    def get_storage_free_bytes(self):
        """Calculate free storage in bytes."""
        if self.storage_total_bytes and self.storage_used_bytes:
            return self.storage_total_bytes - self.storage_used_bytes
        return None

    def get_storage_free_formatted(self):
        """Get free storage as formatted string."""
        free_bytes = self.get_storage_free_bytes()
        if free_bytes is None:
            return "Unknown"

        gb = free_bytes / (1024**3)
        if gb >= 1000:
            return f"{gb/1000:.1f} TB"
        else:
            return f"{gb:.1f} GB"

    def get_storage_total_formatted(self):
        """Get total storage as formatted string."""
        if not self.storage_total_bytes:
            return "Unknown"

        gb = self.storage_total_bytes / (1024**3)
        if gb >= 1000:
            return f"{gb/1000:.1f} TB"
        else:
            return f"{gb:.0f} GB"


class MobileExtractionJob(models.Model):
    """Mobile device extraction job - links to ImagingJob."""

    EXTRACTION_METHOD_CHOICES = [
        ('logical', 'Logical Backup'),
        # Only legitimate, consensual extraction methods for stock devices
        # No jailbreak/root required, works with user consent (device unlocked & trusted)
    ]

    # Link to parent imaging job
    imaging_job = models.OneToOneField('ImagingJob', on_delete=models.CASCADE,
                                      related_name='mobile_extraction',
                                      help_text="Parent imaging job")

    # Device info
    mobile_device = models.ForeignKey(MobileDevice, on_delete=models.CASCADE,
                                     related_name='extraction_jobs',
                                     help_text="Mobile device being extracted")

    # Extraction settings
    extraction_method = models.CharField(max_length=30, choices=EXTRACTION_METHOD_CHOICES,
                                        default='logical',
                                        help_text="Extraction method to use")

    # iOS specific settings
    backup_encrypted = models.BooleanField(default=False,
                                          help_text="iOS: Backup is encrypted")
    backup_password = models.CharField(max_length=200, blank=True,
                                      help_text="iOS: Encrypted backup password (stored temporarily)")
    include_app_data = models.BooleanField(default=True,
                                          help_text="Include application data")
    include_photos = models.BooleanField(default=True,
                                        help_text="Include photos/videos")
    include_messages = models.BooleanField(default=True,
                                          help_text="Include messages (SMS/iMessage)")

    # Android specific settings
    include_internal_storage = models.BooleanField(default=True,
                                                   help_text="Android: Include internal storage")
    include_sd_card = models.BooleanField(default=False,
                                         help_text="Android: Include SD card if present")
    include_system_partition = models.BooleanField(default=False,
                                                   help_text="Android: Include /system partition")

    # Extraction results
    extraction_started_at = models.DateTimeField(null=True, blank=True)
    extraction_completed_at = models.DateTimeField(null=True, blank=True)
    extraction_size_bytes = models.BigIntegerField(null=True, blank=True,
                                                   help_text="Total size of extraction")
    files_extracted = models.IntegerField(null=True, blank=True,
                                         help_text="Number of files extracted")

    # Extracted content inventory
    apps_extracted = models.JSONField(default=list, blank=True,
                                     help_text="List of apps/packages extracted")
    databases_found = models.JSONField(default=list, blank=True,
                                      help_text="SQLite databases found")

    # Parsing results
    contacts_count = models.IntegerField(null=True, blank=True)
    messages_count = models.IntegerField(null=True, blank=True)
    call_logs_count = models.IntegerField(null=True, blank=True)
    photos_count = models.IntegerField(null=True, blank=True)
    videos_count = models.IntegerField(null=True, blank=True)

    # Metadata and documentation
    device_owner = models.CharField(max_length=255, blank=True,
                                   help_text="Person or entity who owns/uses this device")
    device_context = models.CharField(max_length=500, blank=True,
                                     help_text="How this device relates to the investigation")
    extraction_notes = models.TextField(blank=True,
                                       help_text="Notes about the extraction process, consent, circumstances")
    backup_name = models.CharField(max_length=255, blank=True,
                                  help_text="Custom name for the backup directory")

    class Meta:
        ordering = ['-extraction_started_at']

    def __str__(self):
        return f"Mobile Extraction - Job #{self.imaging_job.id} - {self.mobile_device}"

    def get_extraction_duration(self):
        """Calculate extraction duration."""
        if self.extraction_started_at and self.extraction_completed_at:
            duration = self.extraction_completed_at - self.extraction_started_at
            return duration
        return None
