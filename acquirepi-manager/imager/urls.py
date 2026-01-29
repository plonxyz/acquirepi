"""
URL configuration for imager app.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# API router
router = DefaultRouter()
router.register(r'agents', views.AgentViewSet)
router.register(r'jobs', views.ImagingJobViewSet)
router.register(r'mobile-devices', views.MobileDeviceViewSet)

urlpatterns = [
    # Web views
    path('', views.dashboard, name='dashboard'),
    path('api/dashboard/', views.dashboard_api, name='dashboard_api'),
    path('performance/', views.agent_performance_dashboard, name='agent_performance_dashboard'),
    path('agents/', views.agent_list, name='agent_list'),
    path('api/agents/', views.agent_list_api, name='agent_list_api'),
    path('agents/<int:agent_id>/', views.agent_detail, name='agent_detail'),
    path('agents/<int:agent_id>/terminal/', views.agent_terminal, name='agent_terminal'),
    path('agents/<int:agent_id>/approve/', views.agent_approve, name='agent_approve'),
    path('agents/<int:agent_id>/deny/', views.agent_deny, name='agent_deny'),
    path('agents/<int:agent_id>/delete/', views.agent_delete, name='agent_delete'),
    path('jobs/', views.job_list, name='job_list'),
    path('api/jobs/', views.job_list_api, name='job_list_api'),
    path('jobs/create/', views.job_create, name='job_create'),
    path('jobs/<int:job_id>/', views.job_detail, name='job_detail'),
    path('jobs/<int:job_id>/cancel/', views.job_cancel, name='job_cancel'),
    path('jobs/<int:job_id>/restart/', views.job_restart, name='job_restart'),

    # SSH Key management
    path('ssh-keys/', views.sshkey_list, name='sshkey_list'),
    path('ssh-keys/create/', views.sshkey_create, name='sshkey_create'),
    path('ssh-keys/<int:key_id>/edit/', views.sshkey_edit, name='sshkey_edit'),
    path('ssh-keys/<int:key_id>/delete/', views.sshkey_delete, name='sshkey_delete'),

    # Webhooks
    path('webhooks/', views.webhook_list, name='webhook_list'),
    path('webhooks/create/', views.webhook_create, name='webhook_create'),
    path('webhooks/<int:webhook_id>/edit/', views.webhook_edit, name='webhook_edit'),
    path('webhooks/<int:webhook_id>/delete/', views.webhook_delete, name='webhook_delete'),
    path('webhooks/<int:webhook_id>/test/', views.webhook_test, name='webhook_test'),

    # Audit logs
    path('audit-logs/', views.audit_log_list, name='audit_log_list'),

    # Forensic integrity verification
    path('forensic-integrity/', views.forensic_integrity_verification, name='forensic_integrity_verification'),

    # Mobile devices
    path('mobile-devices/', views.mobile_device_list, name='mobile_device_list'),
    path('mobile-devices/<int:device_id>/', views.mobile_device_detail, name='mobile_device_detail'),

    # Shell sessions
    path('shell-sessions/', views.shell_session_list, name='shell_session_list'),
    path('shell-sessions/<int:session_id>/', views.shell_session_detail, name='shell_session_detail'),

    # Chain of custody
    path('jobs/<int:job_id>/coc-report/', views.job_coc_report, name='job_coc_report'),
    path('jobs/<int:job_id>/send-coc-webhook/', views.job_send_coc_webhook, name='job_send_coc_webhook'),

    # QR codes and evidence labels
    path('jobs/<int:job_id>/qr-code/', views.job_qr_code, name='job_qr_code'),
    path('jobs/<int:job_id>/evidence-label/', views.job_evidence_label, name='job_evidence_label'),
    path('jobs/<int:job_id>/custody-scan/', views.job_custody_scan, name='job_custody_scan'),

    # Forensic documentation
    path('jobs/<int:job_id>/write-blocker/', views.write_blocker_verification, name='write_blocker_verification'),
    path('jobs/<int:job_id>/source-device/', views.source_device_documentation, name='source_device_documentation'),
    path('jobs/<int:job_id>/qa-review/', views.qa_review, name='qa_review'),
    path('jobs/<int:job_id>/qa-approval/', views.qa_review_approval, name='qa_review_approval'),
    path('jobs/<int:job_id>/evidence-event/', views.evidence_event_log, name='evidence_event_log'),
    path('jobs/<int:job_id>/evidence-timeline/', views.evidence_timeline, name='evidence_timeline'),
    path('evidence-event/<int:event_id>/upload-photos/', views.upload_event_photos, name='upload_event_photos'),
    path('evidence-event/<int:event_id>/sign/', views.sign_evidence_event, name='sign_evidence_event'),

    # Config Stick (legacy fallback)
    path('config-stick/', views.config_stick_create, name='config_stick_create'),
    path('config-stick/download/', views.config_stick_download, name='config_stick_download'),
    path('config-stick/devices/', views.config_stick_list_devices, name='config_stick_list_devices'),
    path('config-stick/prepare/', views.config_stick_prepare, name='config_stick_prepare'),

    # API endpoints
    path('api/', include(router.urls)),
    path('api/stats/', views.api_stats, name='api_stats'),
]
