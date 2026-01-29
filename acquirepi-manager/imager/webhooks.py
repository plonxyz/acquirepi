"""
Webhook notification system for acquirepi Manager.
Sends notifications to Slack, Teams, Google Chat, and generic webhooks.
"""
import requests
import logging
from django.utils import timezone
from django.db.models import Q
from .models import WebhookConfig

logger = logging.getLogger(__name__)


class WebhookNotifier:
    """Handles sending webhook notifications."""

    @staticmethod
    def format_slack_message(title, message, color="good", fields=None):
        """Format message for Slack."""
        payload = {
            "attachments": [{
                "color": color,
                "title": title,
                "text": message,
                "ts": int(timezone.now().timestamp())
            }]
        }

        if fields:
            payload["attachments"][0]["fields"] = fields

        return payload

    @staticmethod
    def format_teams_message(title, message, color="00FF00", facts=None):
        """Format message for Microsoft Teams."""
        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": title,
            "themeColor": color,
            "title": title,
            "text": message
        }

        if facts:
            payload["sections"] = [{
                "facts": facts
            }]

        return payload

    @staticmethod
    def format_google_chat_message(title, message, fields=None, report_text=None):
        """Format message for Google Chat."""
        payload = {
            "text": f"*{title}*\n\n{message}"
        }

        if fields or report_text:
            sections = []

            # Add fields section if provided
            if fields:
                widgets = []
                for field in fields:
                    widgets.append({
                        "keyValue": {
                            "topLabel": field.get("title", ""),
                            "content": field.get("value", "")
                        }
                    })
                sections.append({"widgets": widgets})

            # Add report text section if provided (for CoC reports)
            if report_text:
                # Google Chat has a limit, so we'll show first 4000 chars with note if truncated
                max_chars = 4000
                display_text = report_text if len(report_text) <= max_chars else report_text[:max_chars] + "\n\n... (Report truncated at 4000 characters. Download full report from job details page)"

                sections.append({
                    "widgets": [{
                        "textParagraph": {
                            "text": f"<font color='#666666'><pre>{display_text}</pre></font>"
                        }
                    }]
                })

            payload["cards"] = [{"sections": sections}]

        return payload

    @classmethod
    def send_notification(cls, event_type, title, message, context=None):
        """
        Send notification to all matching webhooks.

        Args:
            event_type: Type of event (e.g., 'job_started', 'job_completed')
            title: Notification title
            message: Notification message
            context: Dict with optional fields like 'agent', 'job', 'user', 'color', 'fields'
        """
        context = context or {}

        # Get all active webhooks (SQLite-compatible)
        all_webhooks = WebhookConfig.objects.filter(is_active=True)

        # Apply filters
        if 'agent' in context:
            all_webhooks = all_webhooks.filter(
                Q(agent_filter=None) | Q(agent_filter=context['agent'])
            )

        if 'user' in context:
            all_webhooks = all_webhooks.filter(
                Q(user_filter=None) | Q(user_filter=context['user'])
            )

        # Filter by event type in Python (SQLite doesn't support JSONField contains)
        webhooks = [w for w in all_webhooks if event_type in (w.events or [])]

        # Determine color based on event type
        color = context.get('color', cls._get_color_for_event(event_type))
        fields = context.get('fields', [])

        for webhook in webhooks:
            try:
                # Format payload based on webhook type
                if webhook.webhook_type == 'slack':
                    payload = cls.format_slack_message(title, message, color, fields)
                    # Add report text for CoC events
                    if event_type == 'coc_report' and 'report_text' in context:
                        payload['report'] = context['report_text']
                elif webhook.webhook_type == 'teams':
                    # Convert hex color
                    teams_color = color.replace('#', '') if color.startswith('#') else cls._status_to_hex(color)
                    teams_facts = [{"name": f["title"], "value": f["value"]} for f in fields]
                    payload = cls.format_teams_message(title, message, teams_color, teams_facts)
                    # Add report text for CoC events
                    if event_type == 'coc_report' and 'report_text' in context:
                        payload['report'] = context['report_text']
                elif webhook.webhook_type == 'google_chat':
                    # Pass report_text directly to formatter for CoC events
                    report_text = context.get('report_text') if event_type == 'coc_report' else None
                    payload = cls.format_google_chat_message(title, message, fields, report_text)

                    if event_type == 'coc_report' and report_text:
                        logger.info(f"CoC report added to Google Chat card - Length: {len(report_text)} chars")
                else:  # generic
                    # Create serializable context (exclude Django model objects)
                    serializable_context = {}
                    if 'job' in context:
                        job = context['job']
                        serializable_context['job'] = {
                            'id': job.id,
                            'case_number': job.case_number,
                            'evidence_number': job.evidence_number,
                            'status': job.status,
                        }
                    if 'agent' in context:
                        agent = context['agent']
                        serializable_context['agent'] = {
                            'id': agent.id,
                            'hostname': agent.hostname,
                            'ip_address': agent.ip_address,
                        }
                    if 'user' in context and context['user']:
                        user = context['user']
                        serializable_context['user'] = {
                            'username': user.username,
                        }

                    payload = {
                        "title": title,
                        "message": message,
                        "event_type": event_type,
                        "timestamp": timezone.now().isoformat(),
                        "context": serializable_context,
                        "fields": fields
                    }

                    # Include full report text for CoC reports
                    if event_type == 'coc_report' and 'report_text' in context:
                        payload['report'] = context['report_text']

                # Log payload info for CoC reports
                if event_type == 'coc_report':
                    logger.info(f"Sending CoC webhook - Payload keys: {list(payload.keys())}")
                    if 'report' in payload:
                        logger.info(f"  ✓ 'report' field present - Length: {len(payload['report'])} chars")
                    else:
                        logger.warning(f"  ✗ 'report' field MISSING from payload!")

                # Send the webhook
                response = requests.post(
                    webhook.url,
                    json=payload,
                    timeout=10,
                    headers={'Content-Type': 'application/json'}
                )
                response.raise_for_status()

                # Update statistics
                webhook.last_triggered = timezone.now()
                webhook.success_count += 1
                webhook.save(update_fields=['last_triggered', 'success_count'])

                logger.info(f"Webhook '{webhook.name}' sent successfully for event '{event_type}'")

            except Exception as e:
                logger.error(f"Failed to send webhook '{webhook.name}': {e}")
                webhook.failure_count += 1
                webhook.save(update_fields=['failure_count'])

    @staticmethod
    def _get_color_for_event(event_type):
        """Get color code based on event type."""
        color_map = {
            'job_started': 'good',  # green
            'job_completed': 'good',
            'job_failed': 'danger',  # red
            'job_progress': 'warning',  # yellow
            'agent_registered': '#36a64f',
            'agent_online': 'good',
            'agent_offline': 'warning',
            'system_alert': 'danger',
            'coc_report': '#439FE0',  # blue
        }
        return color_map.get(event_type, '#439FE0')  # blue default

    @staticmethod
    def _status_to_hex(status):
        """Convert status string to hex color."""
        status_map = {
            'good': '00FF00',
            'warning': 'FFA500',
            'danger': 'FF0000',
        }
        return status_map.get(status, '439FE0')

    @classmethod
    def notify_job_started(cls, job):
        """Send notification when job starts."""
        fields = [
            {"title": "Agent", "value": job.agent.hostname, "short": True},
            {"title": "Case Number", "value": job.case_number, "short": True},
            {"title": "Evidence Number", "value": job.evidence_number, "short": True},
            {"title": "Upload Method", "value": job.get_upload_method_display(), "short": True},
        ]

        if job.created_by:
            fields.append({"title": "Created By", "value": job.created_by.username, "short": True})

        cls.send_notification(
            'job_started',
            f"🔵 Imaging Job Started - {job.case_number}",
            f"Evidence {job.evidence_number} imaging has started on agent {job.agent.hostname}",
            {
                'job': job,
                'agent': job.agent,
                'user': job.created_by,
                'fields': fields
            }
        )

    @classmethod
    def notify_job_completed(cls, job):
        """Send notification when job completes."""
        duration = ""
        if job.started_at and job.completed_at:
            delta = job.completed_at - job.started_at
            hours, remainder = divmod(int(delta.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            duration = f"{hours}h {minutes}m {seconds}s"

        fields = [
            {"title": "Agent", "value": job.agent.hostname, "short": True},
            {"title": "Case Number", "value": job.case_number, "short": True},
            {"title": "Evidence Number", "value": job.evidence_number, "short": True},
            {"title": "Duration", "value": duration, "short": True},
        ]

        if job.image_size:
            size_gb = job.image_size / (1024**3)
            fields.append({"title": "Image Size", "value": f"{size_gb:.2f} GB", "short": True})

        if job.source_md5:
            fields.append({"title": "MD5 Hash", "value": job.source_md5, "short": False})

        if job.hash_verified:
            fields.append({"title": "Hash Verification", "value": "✅ Verified", "short": True})

        cls.send_notification(
            'job_completed',
            f"✅ Imaging Job Completed - {job.case_number}",
            f"Evidence {job.evidence_number} has been successfully imaged",
            {
                'job': job,
                'agent': job.agent,
                'user': job.created_by,
                'fields': fields
            }
        )

    @classmethod
    def notify_job_failed(cls, job):
        """Send notification when job fails."""
        fields = [
            {"title": "Agent", "value": job.agent.hostname, "short": True},
            {"title": "Case Number", "value": job.case_number, "short": True},
            {"title": "Evidence Number", "value": job.evidence_number, "short": True},
            {"title": "Error", "value": job.error_message or "Unknown error", "short": False},
        ]

        cls.send_notification(
            'job_failed',
            f"❌ Imaging Job Failed - {job.case_number}",
            f"Evidence {job.evidence_number} imaging failed on agent {job.agent.hostname}",
            {
                'job': job,
                'agent': job.agent,
                'user': job.created_by,
                'fields': fields,
                'color': 'danger'
            }
        )

    @classmethod
    def notify_job_progress(cls, job, force=False):
        """Send notification for job progress (throttled)."""
        # This should be called sparingly due to the volume
        # Only send at certain percentages or if forced
        if not force:
            # Only send at 25%, 50%, 75%
            progress = float(job.progress_percentage)
            if progress not in [25, 50, 75]:
                return

        fields = [
            {"title": "Agent", "value": job.agent.hostname, "short": True},
            {"title": "Case Number", "value": job.case_number, "short": True},
            {"title": "Progress", "value": f"{job.progress_percentage}%", "short": True},
        ]

        if job.transfer_speed:
            fields.append({"title": "Speed", "value": job.transfer_speed, "short": True})

        cls.send_notification(
            'job_progress',
            f"⏳ Job Progress - {job.case_number}",
            f"Evidence {job.evidence_number} is {job.progress_percentage}% complete",
            {
                'job': job,
                'agent': job.agent,
                'user': job.created_by,
                'fields': fields
            }
        )

    @classmethod
    def notify_agent_registered(cls, agent):
        """Send notification when new agent registers."""
        fields = [
            {"title": "Hostname", "value": agent.hostname, "short": True},
            {"title": "IP Address", "value": agent.ip_address, "short": True},
            {"title": "MAC Address", "value": agent.mac_address, "short": True},
            {"title": "Hardware", "value": agent.hardware_model or "Unknown", "short": True},
        ]

        cls.send_notification(
            'agent_registered',
            f"🆕 New Agent Registered - {agent.hostname}",
            f"A new agent has registered and is pending approval",
            {
                'agent': agent,
                'fields': fields
            }
        )

    @classmethod
    def notify_agent_online(cls, agent):
        """Send notification when agent comes online."""
        cls.send_notification(
            'agent_online',
            f"✅ Agent Online - {agent.hostname}",
            f"Agent {agent.hostname} is now online and ready for imaging jobs",
            {'agent': agent}
        )

    @classmethod
    def notify_agent_offline(cls, agent):
        """Send notification when agent goes offline."""
        cls.send_notification(
            'agent_offline',
            f"⚠️ Agent Offline - {agent.hostname}",
            f"Agent {agent.hostname} has gone offline",
            {'agent': agent, 'color': 'warning'}
        )

    @classmethod
    def notify_coc_report(cls, job, report_text):
        """
        Send Chain of Custody report to webhook.

        Args:
            job: The ImagingJob instance
            report_text: The full CoC report text
        """
        fields = [
            {"title": "Case Number", "value": job.case_number, "short": True},
            {"title": "Evidence Number", "value": job.evidence_number, "short": True},
            {"title": "Agent", "value": job.agent.hostname, "short": True},
            {"title": "Status", "value": job.get_status_display(), "short": True},
        ]

        if job.forensic_documentation_complete:
            fields.append({"title": "Documentation Status", "value": "✅ Court-Ready", "short": True})

        # Include report as message for smaller webhooks or as a field for others
        cls.send_notification(
            'coc_report',
            f"📋 Chain of Custody Report - {job.case_number}",
            f"Forensic documentation report for evidence {job.evidence_number}",
            {
                'job': job,
                'agent': job.agent,
                'user': job.created_by,
                'fields': fields,
                'report_text': report_text,  # Include full report in context
            }
        )
