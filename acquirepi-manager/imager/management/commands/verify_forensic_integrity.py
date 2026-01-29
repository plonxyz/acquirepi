"""
Django management command to verify forensic integrity of immutable records.
Usage: python manage.py verify_forensic_integrity
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from imager.models import AuditLog, JobLog, EvidenceHandlingEvent, ImagingJob


class Command(BaseCommand):
    help = 'Verify cryptographic hash chain integrity of audit logs, job logs, and chain of custody records'

    def add_arguments(self, parser):
        parser.add_argument(
            '--job',
            type=int,
            help='Verify only logs for a specific job ID',
        )
        parser.add_argument(
            '--export',
            type=str,
            help='Export verification report to file',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('='*80))
        self.stdout.write(self.style.SUCCESS('FORENSIC INTEGRITY VERIFICATION'))
        self.stdout.write(self.style.SUCCESS(f'Timestamp: {timezone.now().isoformat()}'))
        self.stdout.write(self.style.SUCCESS('='*80))
        self.stdout.write('')

        report = []
        all_valid = True

        # Verify Audit Log chain
        if not options['job']:
            self.stdout.write(self.style.WARNING('[1] Verifying Audit Log Chain...'))
            result = AuditLog.verify_chain_integrity()
            self.display_result(result)
            report.append(('Audit Log', result))
            all_valid = all_valid and result['valid']
            self.stdout.write('')

        # Verify Job-specific chains
        if options['job']:
            jobs = [ImagingJob.objects.get(id=options['job'])]
        else:
            jobs = ImagingJob.objects.all()[:20]  # Latest 20 jobs

        job_count = 0
        for job in jobs:
            job_count += 1

            # Verify Job Logs
            self.stdout.write(self.style.WARNING(f'[{job_count if not options["job"] else 2}] Verifying Job #{job.id} Log Chain...'))
            result = JobLog.verify_job_chain_integrity(job)
            self.display_result(result)
            report.append((f'Job {job.id} Logs', result))
            all_valid = all_valid and result['valid']

            # Verify Chain of Custody
            self.stdout.write(self.style.WARNING(f'[{job_count if not options["job"] else 3}] Verifying Job #{job.id} Chain of Custody...'))
            result = EvidenceHandlingEvent.verify_job_chain_integrity(job)
            self.display_result(result)
            report.append((f'Job {job.id} CoC', result))
            all_valid = all_valid and result['valid']

            self.stdout.write('')

        # Summary
        self.stdout.write(self.style.SUCCESS('='*80))
        if all_valid:
            self.stdout.write(self.style.SUCCESS('✓ ALL CHAINS VALID - NO TAMPERING DETECTED'))
        else:
            self.stdout.write(self.style.ERROR('✗ TAMPERING DETECTED - SOME CHAINS BROKEN'))
            self.stdout.write(self.style.ERROR('Review details above for specific issues.'))
        self.stdout.write(self.style.SUCCESS('='*80))

        # Export report if requested
        if options['export']:
            self.export_report(options['export'], report, all_valid)

    def display_result(self, result):
        """Display verification result."""
        if result['valid']:
            self.stdout.write(self.style.SUCCESS(f"  ✓ {result['details']}"))
        else:
            self.stdout.write(self.style.ERROR(f"  ✗ {result['details']}"))
            for issue in result['broken_chains']:
                self.stdout.write(self.style.ERROR(f"    - Record ID {issue['id']}: {issue['reason']}"))
                if 'expected' in issue and 'actual' in issue:
                    self.stdout.write(self.style.ERROR(f"      Expected: {issue['expected'][:16]}..."))
                    self.stdout.write(self.style.ERROR(f"      Actual:   {issue['actual'][:16]}..."))

    def export_report(self, filename, report, all_valid):
        """Export verification report to file."""
        import json

        report_data = {
            'timestamp': timezone.now().isoformat(),
            'all_valid': all_valid,
            'results': {}
        }

        for name, result in report:
            report_data['results'][name] = result

        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)

        self.stdout.write(self.style.SUCCESS(f'\nReport exported to: {filename}'))
