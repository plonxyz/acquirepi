"""
Django management command for periodic integrity monitoring with tamper alerts.
Usage: python manage.py integrity_monitor
       python manage.py integrity_monitor --daemon  (run continuously)

This command verifies the cryptographic hash chains and sends alerts if tampering is detected.
"""
import time
import json
import logging
import requests
from datetime import datetime
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.conf import settings
from imager.models import AuditLog, JobLog, EvidenceHandlingEvent, ImagingJob, SystemSettings

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Monitor integrity of forensic records and alert on tampering'

    def add_arguments(self, parser):
        parser.add_argument(
            '--daemon',
            action='store_true',
            help='Run continuously as a daemon (uses interval from settings)',
        )
        parser.add_argument(
            '--interval',
            type=int,
            help='Override check interval in minutes (default: from settings)',
        )
        parser.add_argument(
            '--quiet',
            action='store_true',
            help='Only output on errors/tampering',
        )

    def handle(self, *args, **options):
        if options['daemon']:
            self.run_daemon(options)
        else:
            self.run_single_check(options)

    def run_daemon(self, options):
        """Run continuously, checking at configured intervals."""
        self.stdout.write(self.style.SUCCESS('Starting integrity monitoring daemon...'))

        while True:
            try:
                settings_obj = SystemSettings.get_settings()

                if not settings_obj.enable_integrity_monitoring:
                    self.stdout.write('Integrity monitoring disabled in settings. Sleeping...')
                    time.sleep(300)  # Check again in 5 minutes
                    continue

                interval = options['interval'] or settings_obj.integrity_check_interval_minutes

                # Run the check
                self.run_single_check(options)

                # Sleep until next check
                self.stdout.write(f'Next check in {interval} minutes...')
                time.sleep(interval * 60)

            except KeyboardInterrupt:
                self.stdout.write(self.style.WARNING('\nDaemon stopped by user.'))
                break
            except Exception as e:
                logger.error(f'Error in integrity monitor daemon: {e}')
                self.stderr.write(self.style.ERROR(f'Error: {e}'))
                time.sleep(60)  # Wait a minute before retrying

    def run_single_check(self, options):
        """Run a single integrity check."""
        quiet = options.get('quiet', False)

        if not quiet:
            self.stdout.write(self.style.SUCCESS('='*60))
            self.stdout.write(self.style.SUCCESS(f'INTEGRITY CHECK - {timezone.now().isoformat()}'))
            self.stdout.write(self.style.SUCCESS('='*60))

        all_valid = True
        issues = []

        # Check Audit Log chain
        if not quiet:
            self.stdout.write('Checking Audit Log chain...')
        result = AuditLog.verify_chain_integrity()
        if not result['valid']:
            all_valid = False
            issues.append({
                'chain': 'Audit Log',
                'details': result['details'],
                'broken_chains': result['broken_chains']
            })
            self.stdout.write(self.style.ERROR(f"  TAMPERING DETECTED: {result['details']}"))
        elif not quiet:
            self.stdout.write(self.style.SUCCESS(f"  OK: {result['details']}"))

        # Check Job Log chains for recent jobs
        recent_jobs = ImagingJob.objects.order_by('-id')[:50]
        for job in recent_jobs:
            result = JobLog.verify_job_chain_integrity(job)
            if not result['valid']:
                all_valid = False
                issues.append({
                    'chain': f'Job {job.id} Logs',
                    'details': result['details'],
                    'broken_chains': result['broken_chains']
                })
                self.stdout.write(self.style.ERROR(f"  TAMPERING DETECTED in Job {job.id} logs"))

            # Check Chain of Custody
            result = EvidenceHandlingEvent.verify_job_chain_integrity(job)
            if not result['valid']:
                all_valid = False
                issues.append({
                    'chain': f'Job {job.id} Chain of Custody',
                    'details': result['details'],
                    'broken_chains': result['broken_chains']
                })
                self.stdout.write(self.style.ERROR(f"  TAMPERING DETECTED in Job {job.id} CoC"))

        # Update settings with check result
        try:
            settings_obj = SystemSettings.get_settings()
            SystemSettings.objects.filter(pk=1).update(
                last_integrity_check=timezone.now(),
                last_integrity_status=all_valid
            )
        except Exception as e:
            logger.error(f'Could not update settings: {e}')

        # Send alerts if tampering detected
        if not all_valid:
            self.stdout.write(self.style.ERROR('\n' + '!'*60))
            self.stdout.write(self.style.ERROR('TAMPERING DETECTED - SENDING ALERTS'))
            self.stdout.write(self.style.ERROR('!'*60))
            self.send_alerts(issues)
        elif not quiet:
            self.stdout.write(self.style.SUCCESS('\nAll integrity checks passed.'))

    def send_alerts(self, issues):
        """Send tampering alerts via configured channels."""
        try:
            settings_obj = SystemSettings.get_settings()
        except Exception as e:
            logger.error(f'Could not get settings for alerts: {e}')
            return

        # Prepare alert message
        alert_data = self.prepare_alert_data(issues)

        # Send webhook alert
        if settings_obj.tamper_alert_webhook_url:
            self.send_webhook_alert(settings_obj.tamper_alert_webhook_url, alert_data)

        # Send email alert
        if settings_obj.tamper_alert_email:
            self.send_email_alert(settings_obj.tamper_alert_email, alert_data)

        # Log to file
        self.log_tampering_event(alert_data)

    def prepare_alert_data(self, issues):
        """Prepare alert data structure."""
        import socket

        return {
            'timestamp': timezone.now().isoformat(),
            'hostname': socket.gethostname(),
            'alert_type': 'TAMPERING_DETECTED',
            'severity': 'CRITICAL',
            'message': f'Forensic integrity violation detected! {len(issues)} chain(s) compromised.',
            'issues': issues,
            'action_required': 'Immediate investigation required. Evidence integrity may be compromised.',
        }

    def send_webhook_alert(self, webhook_url, alert_data):
        """Send alert to webhook (supports Slack, Discord, Teams, generic)."""
        try:
            # Detect webhook type and format accordingly
            if 'slack.com' in webhook_url or 'hooks.slack.com' in webhook_url:
                payload = self.format_slack_alert(alert_data)
            elif 'discord.com' in webhook_url:
                payload = self.format_discord_alert(alert_data)
            elif 'office.com' in webhook_url or 'webhook.office' in webhook_url:
                payload = self.format_teams_alert(alert_data)
            else:
                # Generic webhook - send raw JSON
                payload = alert_data

            response = requests.post(
                webhook_url,
                json=payload,
                timeout=30,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code in [200, 201, 204]:
                self.stdout.write(self.style.SUCCESS(f'Webhook alert sent successfully'))
                logger.info(f'Tampering alert sent to webhook')
            else:
                self.stdout.write(self.style.ERROR(f'Webhook failed: {response.status_code} - {response.text}'))
                logger.error(f'Webhook alert failed: {response.status_code}')

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Webhook error: {e}'))
            logger.error(f'Webhook alert error: {e}')

    def format_slack_alert(self, alert_data):
        """Format alert for Slack webhook."""
        issues_text = '\n'.join([f"• {i['chain']}: {i['details']}" for i in alert_data['issues']])

        return {
            'text': f":rotating_light: *CRITICAL: TAMPERING DETECTED* :rotating_light:",
            'attachments': [{
                'color': 'danger',
                'title': 'Forensic Integrity Violation',
                'text': alert_data['message'],
                'fields': [
                    {
                        'title': 'Hostname',
                        'value': alert_data['hostname'],
                        'short': True
                    },
                    {
                        'title': 'Timestamp',
                        'value': alert_data['timestamp'],
                        'short': True
                    },
                    {
                        'title': 'Affected Chains',
                        'value': issues_text,
                        'short': False
                    },
                    {
                        'title': 'Action Required',
                        'value': alert_data['action_required'],
                        'short': False
                    }
                ],
                'footer': 'AcquirePi Integrity Monitor'
            }]
        }

    def format_discord_alert(self, alert_data):
        """Format alert for Discord webhook."""
        issues_text = '\n'.join([f"• {i['chain']}: {i['details']}" for i in alert_data['issues']])

        return {
            'content': ':rotating_light: **CRITICAL: TAMPERING DETECTED** :rotating_light:',
            'embeds': [{
                'title': 'Forensic Integrity Violation',
                'description': alert_data['message'],
                'color': 15158332,  # Red
                'fields': [
                    {'name': 'Hostname', 'value': alert_data['hostname'], 'inline': True},
                    {'name': 'Timestamp', 'value': alert_data['timestamp'], 'inline': True},
                    {'name': 'Affected Chains', 'value': issues_text, 'inline': False},
                    {'name': 'Action Required', 'value': alert_data['action_required'], 'inline': False}
                ],
                'footer': {'text': 'AcquirePi Integrity Monitor'}
            }]
        }

    def format_teams_alert(self, alert_data):
        """Format alert for Microsoft Teams webhook."""
        issues_text = '\n\n'.join([f"**{i['chain']}**: {i['details']}" for i in alert_data['issues']])

        return {
            '@type': 'MessageCard',
            '@context': 'http://schema.org/extensions',
            'themeColor': 'FF0000',
            'summary': 'TAMPERING DETECTED',
            'sections': [{
                'activityTitle': '🚨 CRITICAL: TAMPERING DETECTED',
                'activitySubtitle': alert_data['hostname'],
                'facts': [
                    {'name': 'Timestamp', 'value': alert_data['timestamp']},
                    {'name': 'Severity', 'value': 'CRITICAL'},
                ],
                'text': f"{alert_data['message']}\n\n**Affected Chains:**\n{issues_text}\n\n**Action Required:** {alert_data['action_required']}",
                'markdown': True
            }]
        }

    def send_email_alert(self, email_address, alert_data):
        """Send alert via email."""
        try:
            from django.core.mail import send_mail

            issues_text = '\n'.join([f"- {i['chain']}: {i['details']}" for i in alert_data['issues']])

            subject = f"[CRITICAL] Tampering Detected - {alert_data['hostname']}"
            message = f"""
FORENSIC INTEGRITY VIOLATION DETECTED

Timestamp: {alert_data['timestamp']}
Hostname: {alert_data['hostname']}
Severity: CRITICAL

{alert_data['message']}

AFFECTED CHAINS:
{issues_text}

ACTION REQUIRED:
{alert_data['action_required']}

---
This is an automated alert from AcquirePi Integrity Monitor.
"""

            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'noreply@acquirepi.local',
                [email_address],
                fail_silently=False,
            )

            self.stdout.write(self.style.SUCCESS(f'Email alert sent to {email_address}'))
            logger.info(f'Tampering alert emailed to {email_address}')

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Email error: {e}'))
            logger.error(f'Email alert error: {e}')

    def log_tampering_event(self, alert_data):
        """Log tampering event to a dedicated log file."""
        import os

        log_dir = '/var/log/acquirepi'
        log_file = os.path.join(log_dir, 'tampering.log')

        try:
            os.makedirs(log_dir, exist_ok=True)

            with open(log_file, 'a') as f:
                f.write(json.dumps(alert_data) + '\n')

            self.stdout.write(f'Tampering event logged to {log_file}')

        except Exception as e:
            logger.error(f'Could not write to tampering log: {e}')
