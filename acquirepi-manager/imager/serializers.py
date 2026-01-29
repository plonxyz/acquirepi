"""
Serializers for acquirepi manager API.
"""
from rest_framework import serializers
from .models import Agent, ImagingJob, JobLog, MobileDevice, MobileExtractionJob


class AgentSerializer(serializers.ModelSerializer):
    """Serializer for Agent model."""

    class Meta:
        model = Agent
        fields = [
            'id', 'hostname', 'mac_address', 'ip_address', 'status',
            'is_approved', 'hardware_model', 'serial_number',
            'first_seen', 'last_seen', 'approved_at',
            'supports_nfs', 'supports_disk',
            'available_disks'
        ]
        read_only_fields = ['first_seen', 'last_seen', 'approved_at']


class AgentRegistrationSerializer(serializers.Serializer):
    """Serializer for agent registration."""

    hostname = serializers.CharField(max_length=255)
    mac_address = serializers.CharField(max_length=17)
    ip_address = serializers.IPAddressField()
    hardware_model = serializers.CharField(max_length=255, required=False, allow_blank=True)
    serial_number = serializers.CharField(max_length=255, required=False, allow_blank=True)
    supports_nfs = serializers.BooleanField(default=True)
    supports_disk = serializers.BooleanField(default=True)


class JobLogSerializer(serializers.ModelSerializer):
    """Serializer for JobLog model."""

    class Meta:
        model = JobLog
        fields = ['id', 'level', 'message', 'timestamp']


class ImagingJobSerializer(serializers.ModelSerializer):
    """Serializer for ImagingJob model."""

    agent_hostname = serializers.CharField(source='agent.hostname', read_only=True)
    logs = JobLogSerializer(many=True, read_only=True)
    mobile_extraction = serializers.SerializerMethodField()

    class Meta:
        model = ImagingJob
        fields = [
            'id', 'agent', 'agent_hostname', 'status', 'upload_method',
            'case_number', 'evidence_number', 'examiner_name', 'description',
            'image_name', 'base_path',
            's3_access_key', 's3_secret_key', 's3_server', 's3_bucket_name',
            's3_bucket_location', 's3_use_https',
            'nfs_server', 'nfs_share', 'nfs_mount_point',
            'progress_percentage', 'acquired_bytes', 'total_bytes', 'transfer_speed',
            'created_at', 'started_at', 'completed_at',
            'error_message', 'output_path', 'image_size',
            'source_md5', 'source_sha1', 'source_sha256',
            'image_md5', 'image_sha1', 'image_sha256',
            'hash_verified', 'post_verification_passed', 'post_verification_at',
            'logs', 'mobile_extraction'
        ]
        read_only_fields = ['created_at', 'started_at', 'completed_at']

    def get_mobile_extraction(self, obj):
        """Include mobile extraction data if this is a mobile job."""
        try:
            mobile_extraction = obj.mobile_extraction
            return {
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
            return None


class JobProgressSerializer(serializers.Serializer):
    """Serializer for job progress updates."""

    job_id = serializers.IntegerField(required=False)
    progress_percentage = serializers.DecimalField(max_digits=5, decimal_places=2)
    acquired_bytes = serializers.IntegerField(required=False)
    total_bytes = serializers.IntegerField(required=False)
    transfer_speed = serializers.CharField(required=False, allow_blank=True)
    status = serializers.CharField(required=False)
    error_message = serializers.CharField(required=False, allow_blank=True)


class MobileDeviceSerializer(serializers.ModelSerializer):
    """Serializer for MobileDevice model."""

    connected_agent_hostname = serializers.CharField(source='connected_agent.hostname', read_only=True)

    class Meta:
        model = MobileDevice
        fields = [
            'id', 'device_type', 'serial_number', 'udid', 'model', 'manufacturer',
            'product_type', 'os_version', 'build_version', 'connection_status',
            'is_locked', 'is_encrypted', 'is_jailbroken', 'usb_debugging_enabled',
            'developer_mode_enabled', 'first_seen', 'last_seen', 'device_name',
            'imei', 'imei2', 'phone_number', 'iccid', 'wifi_mac', 'bluetooth_mac',
            'battery_level', 'battery_state', 'storage_total_bytes', 'storage_used_bytes',
            'ios_device_class', 'ios_hardware_model', 'ios_device_color', 'ios_region_info',
            'android_sdk_version', 'android_security_patch', 'android_fingerprint',
            'device_info_json', 'connected_agent', 'connected_agent_hostname'
        ]
        read_only_fields = ['first_seen', 'last_seen']


class MobileExtractionJobSerializer(serializers.ModelSerializer):
    """Serializer for MobileExtractionJob model."""

    device_serial = serializers.CharField(source='mobile_device.serial_number', read_only=True)
    device_name = serializers.CharField(source='mobile_device.device_name', read_only=True)

    class Meta:
        model = MobileExtractionJob
        fields = [
            'id', 'imaging_job', 'mobile_device', 'device_serial', 'device_name',
            'extraction_method', 'backup_encrypted', 'backup_password',
            'include_app_data', 'include_photos', 'include_messages',
            'include_internal_storage', 'include_sd_card', 'include_system_partition',
            'extraction_started_at', 'extraction_completed_at', 'extraction_size_bytes',
            'files_extracted', 'apps_extracted', 'databases_found',
            'contacts_count', 'messages_count', 'call_logs_count',
            'photos_count', 'videos_count', 'extraction_notes'
        ]
        read_only_fields = ['extraction_started_at', 'extraction_completed_at']
