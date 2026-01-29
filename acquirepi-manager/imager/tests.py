"""
Comprehensive unit tests for acquirepi manager.

Tests cover:
- SystemSettings model (singleton, feature flags)
- AgentSerializer (available_disks field)
- Feature flag checks in views
- Job creation workflow with different storage methods
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from unittest.mock import patch, MagicMock
import json

from .models import (
    Agent, ImagingJob, JobLog, AuditLog, EvidenceHandlingEvent,
    MobileDevice, MobileExtractionJob, NFSServer, SystemSettings
)
from .serializers import AgentSerializer, ImagingJobSerializer


class SystemSettingsModelTests(TestCase):
    """Test SystemSettings singleton model and feature flags."""

    def setUp(self):
        """Clean up any existing settings before each test."""
        SystemSettings.objects.all().delete()

    def test_singleton_creation(self):
        """Test that only one SystemSettings instance can exist."""
        settings1 = SystemSettings.get_settings()
        settings2 = SystemSettings.get_settings()

        self.assertEqual(settings1.id, settings2.id)
        self.assertEqual(settings1.pk, 1)
        self.assertEqual(SystemSettings.objects.count(), 1)

    def test_default_feature_flags(self):
        """Test that all forensic features are disabled by default."""
        settings = SystemSettings.get_settings()

        self.assertFalse(settings.enable_chain_of_custody)
        self.assertFalse(settings.enable_qa_review)
        self.assertFalse(settings.enable_qr_codes)
        self.assertFalse(settings.enable_digital_signatures)
        # Notifications and remote shell enabled by default
        self.assertTrue(settings.enable_webhooks)
        self.assertTrue(settings.enable_email_notifications)
        self.assertTrue(settings.enable_remote_shell)

    def test_enable_chain_of_custody(self):
        """Test enabling chain of custody feature."""
        settings = SystemSettings.get_settings()
        settings.enable_chain_of_custody = True
        settings.save()

        # Reload from database
        settings = SystemSettings.get_settings()
        self.assertTrue(settings.enable_chain_of_custody)

    def test_enable_qr_codes(self):
        """Test enabling QR code generation."""
        settings = SystemSettings.get_settings()
        settings.enable_qr_codes = True
        settings.save()

        settings = SystemSettings.get_settings()
        self.assertTrue(settings.enable_qr_codes)

    def test_multiple_feature_flags(self):
        """Test enabling multiple features simultaneously."""
        settings = SystemSettings.get_settings()
        settings.enable_chain_of_custody = True
        settings.enable_qa_review = True
        settings.enable_webhooks = True
        settings.save()

        settings = SystemSettings.get_settings()
        self.assertTrue(settings.enable_chain_of_custody)
        self.assertTrue(settings.enable_qa_review)
        self.assertTrue(settings.enable_webhooks)
        self.assertFalse(settings.enable_qr_codes)


class AgentSerializerTests(APITestCase):
    """Test AgentSerializer includes available_disks field."""

    def setUp(self):
        """Create test agent."""
        self.agent = Agent.objects.create(
            hostname='test-agent',
            mac_address='AA:BB:CC:DD:EE:FF',
            ip_address='192.168.1.100',
            status='online',
            is_approved=True,
            available_disks=[
                {
                    'device': '/dev/sda',
                    'model': 'SanDisk 3.2Gen1',
                    'size_human': '14.3 GB',
                    'serial': '03041315122220125551',
                    'fstype': 'vfat',
                    'mounted': False
                }
            ]
        )

    def test_serializer_includes_available_disks(self):
        """Test that AgentSerializer includes available_disks field."""
        serializer = AgentSerializer(self.agent)
        data = serializer.data

        self.assertIn('available_disks', data)
        self.assertIsNotNone(data['available_disks'])
        self.assertEqual(len(data['available_disks']), 1)
        self.assertEqual(data['available_disks'][0]['device'], '/dev/sda')
        self.assertEqual(data['available_disks'][0]['model'], 'SanDisk 3.2Gen1')

    def test_serializer_with_empty_disks(self):
        """Test serializer with no available disks."""
        self.agent.available_disks = []
        self.agent.save()

        serializer = AgentSerializer(self.agent)
        data = serializer.data

        self.assertIn('available_disks', data)
        self.assertEqual(data['available_disks'], [])

    def test_serializer_with_multiple_disks(self):
        """Test serializer with multiple disks."""
        self.agent.available_disks = [
            {'device': '/dev/sda', 'model': 'USB Disk 1', 'size_human': '16 GB'},
            {'device': '/dev/sdb', 'model': 'USB Disk 2', 'size_human': '32 GB'}
        ]
        self.agent.save()

        serializer = AgentSerializer(self.agent)
        data = serializer.data

        self.assertEqual(len(data['available_disks']), 2)
        self.assertEqual(data['available_disks'][0]['device'], '/dev/sda')
        self.assertEqual(data['available_disks'][1]['device'], '/dev/sdb')


class FeatureFlagViewTests(TestCase):
    """Test that views respect feature flags for chain of custody."""

    def setUp(self):
        """Create test user, agent, and job."""
        self.client = Client()
        self.user = User.objects.create_user('testuser', 'test@example.com', 'testpass')
        self.client.login(username='testuser', password='testpass')

        self.agent = Agent.objects.create(
            hostname='test-agent',
            mac_address='AA:BB:CC:DD:EE:FF',
            ip_address='192.168.1.100',
            status='approved',
            is_approved=True
        )

        self.job = ImagingJob.objects.create(
            agent=self.agent,
            upload_method='disk',
            case_number='CASE-001',
            evidence_number='EV-001',
            examiner_name='Test Examiner',
            status='pending',
            created_by=self.user
        )

        # Ensure settings exist
        SystemSettings.objects.all().delete()

    def test_chain_of_custody_disabled_by_default(self):
        """Test that chain of custody events are NOT created when disabled."""
        settings = SystemSettings.get_settings()
        self.assertFalse(settings.enable_chain_of_custody)

        # Start the job
        response = self.client.post(reverse('job_start', args=[self.job.id]))

        # No EvidenceHandlingEvent should be created
        event_count = EvidenceHandlingEvent.objects.filter(job=self.job).count()
        self.assertEqual(event_count, 0)

    def test_chain_of_custody_enabled(self):
        """Test that chain of custody events ARE created when enabled."""
        settings = SystemSettings.get_settings()
        settings.enable_chain_of_custody = True
        settings.save()

        # Start the job
        response = self.client.post(reverse('job_start', args=[self.job.id]))

        # EvidenceHandlingEvent should be created
        event_count = EvidenceHandlingEvent.objects.filter(job=self.job).count()
        self.assertGreater(event_count, 0)

        event = EvidenceHandlingEvent.objects.filter(job=self.job).first()
        self.assertEqual(event.event_type, 'imaging_started')

    def test_qr_code_display_disabled(self):
        """Test that QR code section is hidden when disabled."""
        settings = SystemSettings.get_settings()
        settings.enable_qr_codes = False
        settings.save()

        response = self.client.get(reverse('job_detail', args=[self.job.id]))

        self.assertEqual(response.status_code, 200)
        # QR code section should not be present
        self.assertNotContains(response, 'QR Code')

    def test_qr_code_display_enabled(self):
        """Test that QR code section is shown when enabled."""
        settings = SystemSettings.get_settings()
        settings.enable_qr_codes = True
        settings.save()

        response = self.client.get(reverse('job_detail', args=[self.job.id]))

        self.assertEqual(response.status_code, 200)
        # QR code section should be present
        self.assertContains(response, 'QR Code')


class JobCreationWorkflowTests(TestCase):
    """Test job creation wizard with different storage methods."""

    def setUp(self):
        """Create test user and agent."""
        self.client = Client()
        self.user = User.objects.create_user('testuser', 'test@example.com', 'testpass')
        self.client.login(username='testuser', password='testpass')

        self.agent = Agent.objects.create(
            hostname='test-agent',
            mac_address='AA:BB:CC:DD:EE:FF',
            ip_address='192.168.1.100',
            status='approved',
            is_approved=True,
            available_disks=[
                {'device': '/dev/sda', 'model': 'Source Disk', 'size_human': '500 GB'},
                {'device': '/dev/sdb', 'model': 'Destination Disk', 'size_human': '1 TB'}
            ]
        )

    def test_disk_to_disk_job_creation(self):
        """Test creating a disk-to-disk imaging job."""
        data = {
            'source_type': 'disk',
            'agent': self.agent.id,
            'upload_method': 'disk',
            'source_device_path': '/dev/sda',
            'destination_device': '/dev/sdb',
            'case_number': 'CASE-001',
            'evidence_number': 'EV-001',
            'examiner_name': 'Test Examiner',
            'description': 'Test disk imaging'
        }

        response = self.client.post(reverse('job_create'), data)

        # Should redirect on success
        self.assertEqual(response.status_code, 302)

        # Job should be created
        job = ImagingJob.objects.filter(case_number='CASE-001').first()
        self.assertIsNotNone(job)
        self.assertEqual(job.upload_method, 'disk')
        self.assertEqual(job.source_device_path, '/dev/sda')
        self.assertEqual(job.agent, self.agent)

    def test_nfs_job_creation_without_destination(self):
        """Test creating an NFS job without destination device."""
        # Create NFS server
        nfs_server = NFSServer.objects.create(
            name='Test NFS Server',
            server='192.168.1.200',
            share_path='/forensics',
            mount_point='/mnt/nfs-share'
        )

        data = {
            'source_type': 'disk',
            'agent': self.agent.id,
            'upload_method': 'nfs',
            'source_device_path': '/dev/sda',
            # No destination_device for NFS
            'nfs_server': nfs_server.id,
            'case_number': 'CASE-002',
            'evidence_number': 'EV-002',
            'examiner_name': 'Test Examiner',
            'description': 'Test NFS imaging'
        }

        response = self.client.post(reverse('job_create'), data)

        # Should succeed without destination device
        self.assertEqual(response.status_code, 302)

        job = ImagingJob.objects.filter(case_number='CASE-002').first()
        self.assertIsNotNone(job)
        self.assertEqual(job.upload_method, 'nfs')
        self.assertEqual(job.nfs_server, nfs_server)

    def test_nfs_job_with_manual_config(self):
        """Test creating NFS job with manual configuration."""
        data = {
            'source_type': 'disk',
            'agent': self.agent.id,
            'upload_method': 'nfs',
            'source_device_path': '/dev/sda',
            'nfs_server_manual': '192.168.1.250',
            'nfs_share': '/exports/forensics',
            'nfs_mount_point': '/mnt/custom-nfs',
            'case_number': 'CASE-003',
            'evidence_number': 'EV-003',
            'examiner_name': 'Test Examiner',
            'description': 'Test manual NFS'
        }

        response = self.client.post(reverse('job_create'), data)

        self.assertEqual(response.status_code, 302)

        job = ImagingJob.objects.filter(case_number='CASE-003').first()
        self.assertIsNotNone(job)
        self.assertEqual(job.upload_method, 'nfs')
        self.assertEqual(job.nfs_server_manual, '192.168.1.250')

    def test_mobile_device_extraction(self):
        """Test creating a mobile device extraction job."""
        # Create mobile device
        mobile_device = MobileDevice.objects.create(
            device_type='iOS',
            serial_number='TESTSERIAL123',
            udid='00008030-001234567890001E',
            model='iPhone 13',
            os_version='17.0',
            connected_agent=self.agent,
            connection_status='connected'
        )

        data = {
            'source_type': 'mobile',
            'agent': self.agent.id,
            'mobile_device': mobile_device.id,
            'upload_method': 'disk',
            'destination_device': '/dev/sdb',
            'extraction_method': 'logical',
            'case_number': 'CASE-004',
            'evidence_number': 'EV-004',
            'examiner_name': 'Test Examiner',
            'description': 'Test iOS extraction'
        }

        response = self.client.post(reverse('job_create'), data)

        self.assertEqual(response.status_code, 302)

        job = ImagingJob.objects.filter(case_number='CASE-004').first()
        self.assertIsNotNone(job)

        # Check mobile extraction job was created
        mobile_extraction = MobileExtractionJob.objects.filter(imaging_job=job).first()
        self.assertIsNotNone(mobile_extraction)
        self.assertEqual(mobile_extraction.mobile_device, mobile_device)


class JobProgressAPITests(APITestCase):
    """Test job progress updates via API."""

    def setUp(self):
        """Create test agent and job."""
        self.agent = Agent.objects.create(
            hostname='test-agent',
            mac_address='AA:BB:CC:DD:EE:FF',
            ip_address='192.168.1.100',
            status='approved',
            is_approved=True,
            api_token='test-token-12345'
        )

        self.user = User.objects.create_user('testuser', 'test@example.com', 'testpass')

        self.job = ImagingJob.objects.create(
            agent=self.agent,
            upload_method='disk',
            case_number='CASE-001',
            evidence_number='EV-001',
            examiner_name='Test Examiner',
            status='in_progress',
            created_by=self.user
        )

        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.agent.api_token)

    def test_progress_update(self):
        """Test updating job progress."""
        data = {
            'progress_percentage': 45.50,
            'acquired_bytes': 500000000,
            'total_bytes': 1000000000,
            'transfer_speed': '50 MB/s'
        }

        response = self.client.post(
            reverse('api_job_progress', args=[self.job.id]),
            data,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Reload job
        self.job.refresh_from_db()
        self.assertEqual(float(self.job.progress_percentage), 45.50)
        self.assertEqual(self.job.acquired_bytes, 500000000)
        self.assertEqual(self.job.total_bytes, 1000000000)

    def test_job_completion(self):
        """Test marking job as complete."""
        data = {
            'status': 'completed',
            'output_path': '/mnt/destination/CASE-001.E01',
            'image_size': 1000000000,
            'source_md5': 'abc123',
            'source_sha1': 'def456',
            'source_sha256': 'ghi789',
            'image_md5': 'abc123',
            'image_sha1': 'def456',
            'image_sha256': 'ghi789'
        }

        response = self.client.post(
            reverse('api_job_complete', args=[self.job.id]),
            data,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.job.refresh_from_db()
        self.assertEqual(self.job.status, 'completed')
        self.assertEqual(self.job.source_md5, 'abc123')
        self.assertEqual(self.job.image_md5, 'abc123')


class HashChainIntegrityTests(TestCase):
    """Test cryptographic hash chain integrity for immutable models."""

    def setUp(self):
        """Create test user and job."""
        self.user = User.objects.create_user('testuser', 'test@example.com', 'testpass')

        self.agent = Agent.objects.create(
            hostname='test-agent',
            mac_address='AA:BB:CC:DD:EE:FF',
            ip_address='192.168.1.100'
        )

        self.job = ImagingJob.objects.create(
            agent=self.agent,
            upload_method='disk',
            case_number='CASE-001',
            evidence_number='EV-001',
            examiner_name='Test Examiner',
            created_by=self.user
        )

    def test_job_log_chain_integrity(self):
        """Test JobLog hash chain."""
        # Create multiple log entries
        log1 = JobLog.objects.create(
            job=self.job,
            level='INFO',
            message='Job started'
        )

        log2 = JobLog.objects.create(
            job=self.job,
            level='INFO',
            message='Progress: 50%'
        )

        log3 = JobLog.objects.create(
            job=self.job,
            level='INFO',
            message='Job completed'
        )

        # Verify chain integrity
        is_valid, message = JobLog.verify_job_chain_integrity(self.job)
        self.assertTrue(is_valid, message)

    def test_evidence_handling_chain(self):
        """Test EvidenceHandlingEvent hash chain."""
        # Enable chain of custody
        settings = SystemSettings.get_settings()
        settings.enable_chain_of_custody = True
        settings.save()

        event1 = EvidenceHandlingEvent.objects.create(
            job=self.job,
            event_type='received',
            performed_by=self.user,
            event_description='Evidence received'
        )

        event2 = EvidenceHandlingEvent.objects.create(
            job=self.job,
            event_type='imaging_started',
            performed_by=self.user,
            event_description='Imaging started'
        )

        # Verify chain
        is_valid, message = EvidenceHandlingEvent.verify_job_chain_integrity(self.job)
        self.assertTrue(is_valid, message)

    def test_audit_log_chain(self):
        """Test AuditLog hash chain."""
        AuditLog.log_action(
            user=self.user,
            action='test_action_1',
            description='First test action',
            ip_address='192.168.1.50'
        )

        AuditLog.log_action(
            user=self.user,
            action='test_action_2',
            description='Second test action',
            ip_address='192.168.1.50'
        )

        # Verify chain
        is_valid, message = AuditLog.verify_chain_integrity()
        self.assertTrue(is_valid, message)


class NFSConfigurationTests(TestCase):
    """Test NFS server configuration and selection."""

    def setUp(self):
        """Create test NFS servers."""
        self.nfs1 = NFSServer.objects.create(
            name='Primary NFS',
            server='192.168.1.200',
            share='/forensics',
            mount_point='/mnt/nfs-primary',
            is_active=True
        )

        self.nfs2 = NFSServer.objects.create(
            name='Secondary NFS',
            server='192.168.1.201',
            share='/backup',
            mount_point='/mnt/nfs-backup',
            is_active=False
        )

    def test_active_nfs_servers_only(self):
        """Test that only active NFS servers are listed."""
        active_servers = NFSServer.objects.filter(is_active=True)
        self.assertEqual(active_servers.count(), 1)
        self.assertEqual(active_servers.first().name, 'Primary NFS')

    def test_nfs_server_str_representation(self):
        """Test string representation of NFS server."""
        self.assertEqual(str(self.nfs1), 'Primary NFS (192.168.1.200:/forensics)')


# Run tests with: python manage.py test imager.tests
