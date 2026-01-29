"""
Admin configuration for imager app.
"""
from django.contrib import admin
from .models import (
    UserProfile, SystemSettings, AuditLog, WebhookConfig, SSHKey, NFSServer, Agent, ImagingJob, JobLog,
    RemoteShellSession, ShellCommand, WriteBlockerVerification, SourceDevice, QAReview,
    EvidenceHandlingEvent, EvidencePhoto, DigitalSignature
)


@admin.register(SystemSettings)
class SystemSettingsAdmin(admin.ModelAdmin):
    """Admin interface for system settings (singleton)."""

    fieldsets = (
        ('Forensic Features', {
            'fields': (
                'enable_chain_of_custody',
                'enable_qa_review',
                'enable_qr_codes',
                'enable_digital_signatures',
            ),
            'description': 'Toggle advanced forensic features. Disable these for simpler deployments.'
        }),
        ('Notifications', {
            'fields': (
                'enable_webhooks',
                'enable_email_notifications',
            )
        }),
        ('Integrity Monitoring & Tamper Alerts', {
            'fields': (
                'enable_integrity_monitoring',
                'integrity_check_interval_minutes',
                'tamper_alert_webhook_url',
                'tamper_alert_email',
                'last_integrity_check',
                'last_integrity_status',
            ),
            'description': 'Configure periodic integrity verification and tamper alerts.'
        }),
        ('Advanced Features', {
            'fields': (
                'enable_remote_shell',
            )
        }),
        ('Metadata', {
            'fields': ('updated_at', 'updated_by'),
            'classes': ('collapse',)
        }),
    )

    readonly_fields = ('updated_at', 'updated_by', 'last_integrity_check', 'last_integrity_status')

    def has_add_permission(self, request):
        # Singleton - only one record allowed (ID=1)
        return not SystemSettings.objects.filter(pk=1).exists()

    def has_delete_permission(self, request, obj=None):
        # Cannot delete system settings
        return False

    def save_model(self, request, obj, form, change):
        """Track who last modified settings."""
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(SSHKey)
class SSHKeyAdmin(admin.ModelAdmin):
    list_display = ['name', 'created_at', 'get_key_preview']
    search_fields = ['name', 'public_key']
    readonly_fields = ['created_at', 'updated_at']

    def get_key_preview(self, obj):
        return obj.public_key[:50] + '...' if len(obj.public_key) > 50 else obj.public_key
    get_key_preview.short_description = 'Public Key Preview'


@admin.register(NFSServer)
class NFSServerAdmin(admin.ModelAdmin):
    """Admin interface for NFS servers."""
    list_display = ('name', 'server', 'share', 'mount_point', 'is_active', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'server', 'share', 'description')
    readonly_fields = ('created_at', 'updated_at', 'created_by')
    fieldsets = (
        ('Server Information', {
            'fields': ('name', 'server', 'share', 'mount_point')
        }),
        ('NFS Options', {
            'fields': ('nfs_version', 'mount_options')
        }),
        ('Status', {
            'fields': ('is_active', 'description')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at', 'created_by'),
            'classes': ('collapse',)
        }),
    )

    def save_model(self, request, obj, form, change):
        """Set created_by on creation."""
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(Agent)
class AgentAdmin(admin.ModelAdmin):
    list_display = ['hostname', 'ip_address', 'mac_address', 'status', 'is_approved', 'last_seen']
    list_filter = ['status', 'is_approved']
    search_fields = ['hostname', 'ip_address', 'mac_address']
    readonly_fields = ['first_seen', 'last_seen', 'approved_at']


@admin.register(ImagingJob)
class ImagingJobAdmin(admin.ModelAdmin):
    list_display = ['id', 'agent', 'case_number', 'evidence_number', 'status', 'progress_percentage', 'created_at']
    list_filter = ['status', 'upload_method', 'created_at']
    search_fields = ['case_number', 'evidence_number', 'examiner_name']
    readonly_fields = ['created_at', 'started_at', 'completed_at']


@admin.register(JobLog)
class JobLogAdmin(admin.ModelAdmin):
    list_display = ['job', 'level', 'message', 'timestamp', 'record_hash']
    list_filter = ['level', 'timestamp']
    search_fields = ['message']
    readonly_fields = ['job', 'level', 'message', 'timestamp', 'record_hash', 'previous_hash']

    def has_add_permission(self, request):
        # Job logs should only be created programmatically by agents
        return False

    def has_change_permission(self, request, obj=None):
        # Job logs are immutable for forensic integrity
        return False

    def has_delete_permission(self, request, obj=None):
        # Job logs cannot be deleted for forensic integrity
        return False


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'role', 'department', 'email_notifications']
    list_filter = ['role', 'email_notifications']
    search_fields = ['user__username', 'user__email', 'department']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'username', 'action', 'description', 'ip_address', 'record_hash']
    list_filter = ['action', 'timestamp']
    search_fields = ['username', 'description', 'ip_address']
    readonly_fields = ['timestamp', 'user', 'username', 'action', 'description', 'ip_address',
                       'user_agent', 'content_type', 'object_id', 'extra_data', 'record_hash', 'previous_hash']
    date_hierarchy = 'timestamp'

    def has_add_permission(self, request):
        # Audit logs should only be created programmatically
        return False

    def has_change_permission(self, request, obj=None):
        # Audit logs are immutable for forensic integrity
        return False

    def has_delete_permission(self, request, obj=None):
        # Audit logs cannot be deleted for forensic integrity
        return False


@admin.register(WebhookConfig)
class WebhookConfigAdmin(admin.ModelAdmin):
    list_display = ['name', 'webhook_type', 'is_active', 'success_count', 'failure_count', 'last_triggered']
    list_filter = ['webhook_type', 'is_active', 'created_at']
    search_fields = ['name', 'url']
    readonly_fields = ['created_at', 'updated_at', 'last_triggered', 'success_count', 'failure_count']
    filter_horizontal = []


@admin.register(RemoteShellSession)
class RemoteShellSessionAdmin(admin.ModelAdmin):
    list_display = ['session_id', 'user', 'agent', 'started_at', 'ended_at', 'status', 'command_count']
    list_filter = ['status', 'started_at']
    search_fields = ['session_id', 'user__username', 'agent__hostname', 'ip_address']
    readonly_fields = ['session_id', 'started_at', 'ended_at', 'last_activity', 'command_count']
    date_hierarchy = 'started_at'


@admin.register(ShellCommand)
class ShellCommandAdmin(admin.ModelAdmin):
    list_display = ['executed_at', 'session', 'command_preview', 'exit_code', 'duration_ms']
    list_filter = ['executed_at', 'exit_code']
    search_fields = ['command', 'output']
    readonly_fields = ['session', 'command', 'output', 'executed_at', 'exit_code', 'duration_ms']
    date_hierarchy = 'executed_at'

    def command_preview(self, obj):
        return obj.command[:100] + '...' if len(obj.command) > 100 else obj.command
    command_preview.short_description = 'Command'


@admin.register(WriteBlockerVerification)
class WriteBlockerVerificationAdmin(admin.ModelAdmin):
    """Admin interface for write-blocker verification records."""
    list_display = ['job', 'write_blocker_model', 'write_blocker_type', 'pre_test_passed',
                    'write_blocker_verified', 'created_at']
    list_filter = ['write_blocker_type', 'write_blocker_verified', 'pre_test_passed', 'created_at']
    search_fields = ['job__case_number', 'job__evidence_number', 'write_blocker_model', 'write_blocker_serial']
    readonly_fields = ['created_at', 'updated_at']
    fieldsets = (
        ('Job Reference', {
            'fields': ('job',)
        }),
        ('Write Blocker Information', {
            'fields': ('write_blocker_used', 'write_blocker_type', 'write_blocker_model', 'write_blocker_serial')
        }),
        ('Pre-Imaging Test', {
            'fields': ('pre_test_performed', 'pre_test_passed', 'pre_test_timestamp',
                      'pre_test_method', 'pre_test_performed_by', 'write_operations_detected')
        }),
        ('During Imaging Verification', {
            'fields': ('write_blocker_verified',)
        }),
        ('Post-Imaging Verification', {
            'fields': ('post_verification_performed', 'post_verification_passed', 'post_verification_notes')
        }),
        ('Additional Documentation', {
            'fields': ('test_results', 'photos')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(SourceDevice)
class SourceDeviceAdmin(admin.ModelAdmin):
    """Admin interface for source device documentation."""
    list_display = ['job', 'manufacturer', 'model_number', 'serial_number', 'device_type',
                    'capacity_formatted', 'smart_status', 'created_at']
    list_filter = ['device_type', 'smart_status', 'interface_type', 'created_at']
    search_fields = ['job__case_number', 'job__evidence_number', 'manufacturer', 'model_number',
                    'serial_number', 'evidence_bag_number']
    readonly_fields = ['created_at', 'updated_at']
    fieldsets = (
        ('Job Reference', {
            'fields': ('job',)
        }),
        ('Device Information', {
            'fields': ('manufacturer', 'model_number', 'serial_number', 'firmware_version',
                      'capacity_bytes', 'capacity_formatted', 'device_type', 'interface_type')
        }),
        ('Physical Condition', {
            'fields': ('physical_condition', 'damage_documented', 'damage_description')
        }),
        ('SMART Data', {
            'fields': ('smart_status', 'power_on_hours', 'power_cycle_count',
                      'reallocated_sectors', 'pending_sectors', 'uncorrectable_sectors', 'smart_data_json')
        }),
        ('Evidence Handling', {
            'fields': ('evidence_bag_number', 'evidence_seal_number', 'sealed_at',
                      'sealed_by', 'storage_location')
        }),
        ('Documentation Photos', {
            'fields': ('device_photos', 'label_photos', 'damage_photos')
        }),
        ('Additional Notes', {
            'fields': ('notes',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(QAReview)
class QAReviewAdmin(admin.ModelAdmin):
    """Admin interface for QA review records."""
    list_display = ['job', 'review_status', 'reviewed_by', 'all_checks_passed',
                    'final_approval', 'review_completed_at']
    list_filter = ['review_status', 'all_checks_passed', 'final_approval',
                  'hash_verification_passed', 'created_at']
    search_fields = ['job__case_number', 'job__evidence_number', 'reviewed_by__username',
                    'reviewer_comments', 'corrections_required']
    readonly_fields = ['created_at', 'updated_at', 'review_started_at', 'review_completed_at',
                      'final_approval_date']
    fieldsets = (
        ('Job Reference', {
            'fields': ('job',)
        }),
        ('Review Status', {
            'fields': ('review_status', 'reviewed_by', 'review_started_at', 'review_completed_at')
        }),
        ('Hash Verification', {
            'fields': ('hash_verification_checked', 'hash_verification_passed', 'hash_verification_notes')
        }),
        ('Metadata Review', {
            'fields': ('metadata_verified', 'metadata_complete', 'metadata_notes')
        }),
        ('Documentation Review', {
            'fields': ('documentation_checked', 'documentation_complete', 'documentation_notes')
        }),
        ('Chain of Custody', {
            'fields': ('chain_of_custody_checked', 'chain_of_custody_intact', 'chain_of_custody_notes')
        }),
        ('Write Blocker Review', {
            'fields': ('write_blocker_checked', 'write_blocker_verified', 'write_blocker_notes')
        }),
        ('Image Integrity', {
            'fields': ('image_integrity_checked', 'image_integrity_verified', 'image_integrity_notes')
        }),
        ('Final Review', {
            'fields': ('all_checks_passed', 'reviewer_comments', 'corrections_required')
        }),
        ('Final Approval', {
            'fields': ('final_approval', 'final_approval_date', 'final_approval_by', 'final_approval_notes')
        }),
        ('Corrections', {
            'fields': ('corrections_made', 'corrections_description', 're_review_required')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(EvidenceHandlingEvent)
class EvidenceHandlingEventAdmin(admin.ModelAdmin):
    """Admin interface for evidence handling events (chain of custody) - IMMUTABLE."""
    list_display = ['job', 'event_type', 'event_timestamp', 'performed_by', 'location', 'record_hash']
    list_filter = ['event_type', 'event_timestamp']
    search_fields = ['job__case_number', 'job__evidence_number', 'performed_by__username',
                    'event_description', 'location']
    readonly_fields = ['job', 'event_type', 'event_timestamp', 'performed_by', 'location', 'event_description',
                      'witnesses', 'witness_names', 'transferred_from', 'transferred_to', 'transfer_reason',
                      'photos_taken', 'forms_completed', 'evidence_condition', 'notes',
                      'record_hash', 'previous_hash']
    date_hierarchy = 'event_timestamp'
    fieldsets = (
        ('Job Reference', {
            'fields': ('job',)
        }),
        ('Event Information', {
            'fields': ('event_type', 'event_timestamp', 'performed_by', 'location', 'event_description')
        }),
        ('Witnesses', {
            'fields': ('witnesses', 'witness_names')
        }),
        ('Custody Transfer', {
            'fields': ('transferred_from', 'transferred_to', 'transfer_reason'),
            'classes': ('collapse',)
        }),
        ('Documentation', {
            'fields': ('photos_taken', 'forms_completed', 'evidence_condition')
        }),
        ('Additional Notes', {
            'fields': ('notes',)
        }),
        ('Forensic Integrity', {
            'fields': ('record_hash', 'previous_hash'),
            'classes': ('collapse',)
        }),
    )

    def has_change_permission(self, request, obj=None):
        # Chain of custody events are immutable for forensic integrity
        return False

    def has_delete_permission(self, request, obj=None):
        # Chain of custody events cannot be deleted for forensic integrity
        return False
    filter_horizontal = ['witnesses']


@admin.register(EvidencePhoto)
class EvidencePhotoAdmin(admin.ModelAdmin):
    list_display = ['id', 'event', 'caption', 'uploaded_by', 'uploaded_at', 'file_size_kb']
    list_filter = ['uploaded_at', 'uploaded_by']
    search_fields = ['caption', 'event__event_description']
    readonly_fields = ['uploaded_at', 'file_size', 'image_width', 'image_height']

    def file_size_kb(self, obj):
        if obj.file_size:
            return f"{obj.file_size / 1024:.1f} KB"
        return "-"
    file_size_kb.short_description = "File Size"


@admin.register(DigitalSignature)
class DigitalSignatureAdmin(admin.ModelAdmin):
    list_display = ['id', 'signer_name', 'signer_role', 'event', 'signed_at', 'is_verified']
    list_filter = ['signed_at', 'signer_role', 'is_verified']
    search_fields = ['signer_name', 'signer_role', 'event__event_description']
    readonly_fields = ['signed_at', 'signature_hash', 'ip_address', 'event_snapshot']

    fieldsets = (
        ('Signer Information', {
            'fields': ('signer', 'signer_name', 'signer_role')
        }),
        ('Event Reference', {
            'fields': ('event', 'event_snapshot')
        }),
        ('Signature Data', {
            'fields': ('signature_data', 'signature_hash')
        }),
        ('Metadata', {
            'fields': ('signed_at', 'ip_address')
        }),
        ('Verification', {
            'fields': ('is_verified', 'verification_notes')
        }),
    )
