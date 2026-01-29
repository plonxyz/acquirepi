"""
Forensic utilities for hash verification and metadata extraction.
Supports E01/EWF image format analysis.
"""
import subprocess
import re
import logging
from datetime import datetime
from django.utils import timezone

logger = logging.getLogger(__name__)


class HashVerifier:
    """Verify forensic image hashes."""

    @staticmethod
    def verify_hashes(job):
        """
        Verify that source and image hashes match.
        Returns True if all available hashes match, False otherwise.
        """
        verified = True

        if job.source_md5 and job.image_md5:
            if job.source_md5.lower() != job.image_md5.lower():
                logger.error(f"MD5 hash mismatch for job {job.id}: {job.source_md5} != {job.image_md5}")
                verified = False
            else:
                logger.info(f"MD5 hash verified for job {job.id}")

        if job.source_sha1 and job.image_sha1:
            if job.source_sha1.lower() != job.image_sha1.lower():
                logger.error(f"SHA1 hash mismatch for job {job.id}: {job.source_sha1} != {job.image_sha1}")
                verified = False
            else:
                logger.info(f"SHA1 hash verified for job {job.id}")

        if job.source_sha256 and job.image_sha256:
            if job.source_sha256.lower() != job.image_sha256.lower():
                logger.error(f"SHA256 hash mismatch for job {job.id}: {job.source_sha256} != {job.image_sha256}")
                verified = False
            else:
                logger.info(f"SHA256 hash verified for job {job.id}")

        # Update job
        job.hash_verified = verified
        job.hash_verified_at = timezone.now()
        job.save(update_fields=['hash_verified', 'hash_verified_at'])

        # Automatically log hash verification event to Chain of Custody
        from .models import EvidenceHandlingEvent

        if verified:
            hash_details = "Cryptographic hash verification completed successfully."
            hash_list = []
            if job.source_md5 and job.image_md5:
                hash_list.append("MD5")
            if job.source_sha1 and job.image_sha1:
                hash_list.append("SHA1")
            if job.source_sha256 and job.image_sha256:
                hash_list.append("SHA256")

            if hash_list:
                hash_details += f" Verified hashes: {', '.join(hash_list)}."
        else:
            hash_details = "Hash verification FAILED - source and image hashes do not match!"

        EvidenceHandlingEvent.objects.create(
            job=job,
            event_type='hash_verified',
            performed_by=None,  # System-generated
            event_description=hash_details
        )

        return verified


class EWFMetadataExtractor:
    """Extract metadata from E01/EWF forensic images."""

    @staticmethod
    def extract_metadata(image_path):
        """
        Extract metadata from E01 image using ewfinfo.

        Args:
            image_path: Path to the E01 image file

        Returns:
            Dict containing extracted metadata, or None if extraction fails
        """
        try:
            # Run ewfinfo command
            result = subprocess.run(
                ['ewfinfo', image_path],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                logger.error(f"ewfinfo failed with return code {result.returncode}: {result.stderr}")
                return None

            output = result.stdout
            metadata = EWFMetadataExtractor._parse_ewfinfo_output(output)
            return metadata

        except FileNotFoundError:
            logger.error("ewfinfo command not found. Install libewf-tools package.")
            return None
        except subprocess.TimeoutExpired:
            logger.error(f"ewfinfo timed out while processing {image_path}")
            return None
        except Exception as e:
            logger.error(f"Error extracting EWF metadata: {e}")
            return None

    @staticmethod
    def _parse_ewfinfo_output(output):
        """Parse ewfinfo output and extract metadata."""
        metadata = {}

        # Common patterns in ewfinfo output
        patterns = {
            'ewf_format': r'Format:\s+(.+)',
            'ewf_compression': r'Compression method:\s+(.+)',
            'ewf_sector_count': r'Number of sectors:\s+(\d+)',
            'ewf_bytes_per_sector': r'Bytes per sector:\s+(\d+)',
            'ewf_media_size': r'Media size:\s+(\d+)',
            'ewf_chunk_size': r'Chunk size:\s+(\d+)',
            'ewf_guid': r'GUID:\s+([0-9a-f\-]+)',
            'source_md5': r'MD5 hash:\s+([0-9a-f]{32})',
            'source_sha1': r'SHA1 hash:\s+([0-9a-f]{40})',
            'source_sha256': r'SHA256 hash:\s+([0-9a-f]{64})',
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
            if match:
                value = match.group(1).strip()

                # Convert numeric fields
                if key in ['ewf_sector_count', 'ewf_bytes_per_sector', 'ewf_media_size', 'ewf_chunk_size']:
                    try:
                        metadata[key] = int(value)
                    except ValueError:
                        metadata[key] = None
                else:
                    metadata[key] = value

        # Try to extract acquisition date
        date_match = re.search(r'Acquiry date:\s+(.+)', output, re.IGNORECASE)
        if date_match:
            date_str = date_match.group(1).strip()
            try:
                # Try common date formats
                for fmt in ['%Y-%m-%d %H:%M:%S', '%a %b %d %H:%M:%S %Y', '%Y/%m/%d %H:%M:%S']:
                    try:
                        dt = datetime.strptime(date_str, fmt)
                        metadata['ewf_acquiry_date'] = timezone.make_aware(dt)
                        break
                    except ValueError:
                        continue
            except Exception as e:
                logger.warning(f"Could not parse acquisition date '{date_str}': {e}")

        # Extract additional case metadata
        case_patterns = {
            'case_number': r'Case number:\s+(.+)',
            'evidence_number': r'Evidence number:\s+(.+)',
            'examiner_name': r'Examiner name:\s+(.+)',
            'description': r'Description:\s+(.+)',
        }

        for key, pattern in case_patterns.items():
            match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
            if match:
                metadata[key] = match.group(1).strip()

        return metadata

    @staticmethod
    def update_job_metadata(job, metadata):
        """
        Update job with extracted metadata.

        Args:
            job: ImagingJob instance
            metadata: Dict of metadata from extract_metadata()
        """
        if not metadata:
            return False

        # Update job fields
        for key, value in metadata.items():
            if hasattr(job, key) and value is not None:
                setattr(job, key, value)

        job.save()
        logger.info(f"Updated job {job.id} with EWF metadata")
        return True

    @staticmethod
    def extract_and_update(job):
        """
        Convenience method to extract metadata and update job in one call.

        Args:
            job: ImagingJob instance

        Returns:
            True if successful, False otherwise
        """
        if not job.output_path:
            logger.warning(f"Job {job.id} has no output path set")
            return False

        metadata = EWFMetadataExtractor.extract_metadata(job.output_path)
        if metadata:
            return EWFMetadataExtractor.update_job_metadata(job, metadata)

        return False


class ChainOfCustody:
    """Generate chain of custody documentation."""

    @staticmethod
    def generate_report(job):
        """
        Generate chain of custody report for a job.

        Returns:
            String containing formatted CoC report
        """
        report = []
        report.append("=" * 80)
        report.append("CHAIN OF CUSTODY REPORT")
        report.append("=" * 80)
        report.append("")

        # Case Information
        report.append("CASE INFORMATION")
        report.append("-" * 40)
        report.append(f"Case Number:       {job.case_number}")
        report.append(f"Evidence Number:   {job.evidence_number}")
        report.append(f"Examiner:          {job.examiner_name}")
        report.append(f"Description:       {job.description}")
        report.append("")

        # Acquisition Information
        report.append("ACQUISITION INFORMATION")
        report.append("-" * 40)
        report.append(f"Agent:             {job.agent.hostname} ({job.agent.ip_address})")
        report.append(f"Agent MAC:         {job.agent.mac_address}")
        report.append(f"Method:            {job.get_upload_method_display()}")
        report.append(f"Image Name:        {job.image_name}")
        report.append(f"Created:           {job.created_at.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        report.append(f"Started:           {job.started_at.strftime('%Y-%m-%d %H:%M:%S %Z') if job.started_at else 'N/A'}")
        report.append(f"Completed:         {job.completed_at.strftime('%Y-%m-%d %H:%M:%S %Z') if job.completed_at else 'N/A'}")

        if job.created_by:
            report.append(f"Created By:        {job.created_by.username} ({job.created_by.email})")

        report.append("")

        # Image Information
        report.append("IMAGE INFORMATION")
        report.append("-" * 40)
        if job.output_path:
            report.append(f"Output Path:       {job.output_path}")
        if job.image_size:
            size_gb = job.image_size / (1024**3)
            report.append(f"Image Size:        {size_gb:.2f} GB ({job.image_size:,} bytes)")

        # EWF Metadata
        if job.ewf_format:
            report.append(f"EWF Format:        {job.ewf_format}")
        if job.ewf_compression:
            report.append(f"Compression:       {job.ewf_compression}")
        if job.ewf_sector_count:
            report.append(f"Sector Count:      {job.ewf_sector_count:,}")
        if job.ewf_bytes_per_sector:
            report.append(f"Bytes per Sector:  {job.ewf_bytes_per_sector}")
        if job.ewf_guid:
            report.append(f"GUID:              {job.ewf_guid}")

        report.append("")

        # Hash Verification
        report.append("HASH VERIFICATION")
        report.append("-" * 40)

        if job.source_md5:
            report.append(f"Source MD5:        {job.source_md5}")
        if job.image_md5:
            report.append(f"Image MD5:         {job.image_md5}")
            if job.source_md5:
                match = "✓ MATCH" if job.source_md5.lower() == job.image_md5.lower() else "✗ MISMATCH"
                report.append(f"                   {match}")

        if job.source_sha1:
            report.append(f"Source SHA1:       {job.source_sha1}")
        if job.image_sha1:
            report.append(f"Image SHA1:        {job.image_sha1}")
            if job.source_sha1:
                match = "✓ MATCH" if job.source_sha1.lower() == job.image_sha1.lower() else "✗ MISMATCH"
                report.append(f"                   {match}")

        if job.source_sha256:
            report.append(f"Source SHA256:     {job.source_sha256}")
        if job.image_sha256:
            report.append(f"Image SHA256:      {job.image_sha256}")
            if job.source_sha256:
                match = "✓ MATCH" if job.source_sha256.lower() == job.image_sha256.lower() else "✗ MISMATCH"
                report.append(f"                   {match}")

        if job.hash_verified:
            report.append("")
            report.append(f"Hash Verification: ✓ VERIFIED at {job.hash_verified_at.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        else:
            report.append("")
            report.append(f"Hash Verification: ✗ NOT VERIFIED")

        report.append("")

        # Write-Blocker Verification
        try:
            wb = job.write_blocker
            report.append("WRITE-BLOCKER VERIFICATION")
            report.append("-" * 40)
            report.append(f"Write-Blocker Used:    {wb.write_blocker_used}")
            if wb.write_blocker_used:
                report.append(f"Model:                 {wb.write_blocker_model}")
                if wb.write_blocker_serial:
                    report.append(f"Serial Number:         {wb.write_blocker_serial}")
                report.append(f"Type:                  {wb.get_write_blocker_type_display()}")
                report.append("")
                report.append("Pre-Imaging Test:")
                report.append(f"  Performed:           {wb.pre_test_performed}")
                if wb.pre_test_performed:
                    report.append(f"  Passed:              {wb.pre_test_passed}")
                    if wb.pre_test_timestamp:
                        report.append(f"  Timestamp:           {wb.pre_test_timestamp.strftime('%Y-%m-%d %H:%M:%S %Z')}")
                    if wb.pre_test_performed_by:
                        report.append(f"  Performed By:        {wb.pre_test_performed_by.username}")
                    report.append(f"  Write Ops Detected:  {wb.write_operations_detected}")
                report.append("")
                report.append(f"Verified During Imaging: {wb.write_blocker_verified}")
                report.append(f"Post-Verification:       {wb.post_verification_performed}")
                if wb.post_verification_performed:
                    report.append(f"  Passed:              {wb.post_verification_passed}")
            report.append("")
        except:
            pass

        # Source Device Documentation
        try:
            sd = job.source_device
            report.append("SOURCE DEVICE DOCUMENTATION")
            report.append("-" * 40)
            report.append(f"Manufacturer:          {sd.manufacturer}")
            report.append(f"Model:                 {sd.model_number}")
            if sd.serial_number:
                report.append(f"Serial Number:         {sd.serial_number}")
            if sd.firmware_version:
                report.append(f"Firmware:              {sd.firmware_version}")
            report.append(f"Device Type:           {sd.get_device_type_display()}")
            if sd.interface_type:
                report.append(f"Interface:             {sd.interface_type}")
            if sd.capacity_formatted:
                report.append(f"Capacity:              {sd.capacity_formatted}")
            report.append("")
            report.append(f"Physical Condition:    {sd.physical_condition[:100]}")
            if sd.damage_documented:
                report.append(f"Damage Documented:     Yes")
            report.append("")
            if sd.smart_status != 'not_available':
                report.append("SMART Status:")
                report.append(f"  Status:              {sd.get_smart_status_display()}")
                if sd.power_on_hours:
                    report.append(f"  Power-On Hours:      {sd.power_on_hours}")
                if sd.reallocated_sectors:
                    report.append(f"  Reallocated Sectors: {sd.reallocated_sectors}")
                if sd.pending_sectors:
                    report.append(f"  Pending Sectors:     {sd.pending_sectors}")
                report.append("")
            if sd.evidence_bag_number:
                report.append(f"Evidence Bag:          {sd.evidence_bag_number}")
            if sd.evidence_seal_number:
                report.append(f"Evidence Seal:         {sd.evidence_seal_number}")
            if sd.storage_location:
                report.append(f"Storage Location:      {sd.storage_location}")
            report.append("")
        except:
            pass

        # QA Review
        try:
            qa = job.qa_review
            report.append("QUALITY ASSURANCE REVIEW")
            report.append("-" * 40)
            report.append(f"Review Status:         {qa.get_review_status_display()}")
            if qa.reviewed_by:
                report.append(f"Reviewed By:           {qa.reviewed_by.username}")
            if qa.review_started_at:
                report.append(f"Review Started:        {qa.review_started_at.strftime('%Y-%m-%d %H:%M:%S %Z')}")
            if qa.review_completed_at:
                report.append(f"Review Completed:      {qa.review_completed_at.strftime('%Y-%m-%d %H:%M:%S %Z')}")
            report.append("")
            report.append("Checklist Items:")
            report.append(f"  Hash Verification:   {'✓ PASS' if qa.hash_verification_passed else '✗ FAIL'}")
            report.append(f"  Metadata Complete:   {'✓ PASS' if qa.metadata_complete else '✗ FAIL'}")
            report.append(f"  Documentation:       {'✓ PASS' if qa.documentation_complete else '✗ FAIL'}")
            report.append(f"  Chain of Custody:    {'✓ PASS' if qa.chain_of_custody_intact else '✗ FAIL'}")
            report.append(f"  Write-Blocker:       {'✓ PASS' if qa.write_blocker_verified else '✗ FAIL'}")
            report.append(f"  Image Integrity:     {'✓ PASS' if qa.image_integrity_verified else '✗ FAIL'}")
            report.append("")
            report.append(f"All Checks Passed:     {qa.all_checks_passed}")
            report.append(f"Final Approval:        {qa.final_approval}")
            if qa.final_approval and qa.final_approval_by:
                report.append(f"Approved By:           {qa.final_approval_by.username}")
                report.append(f"Approval Date:         {qa.final_approval_date.strftime('%Y-%m-%d %H:%M:%S %Z')}")
            report.append("")
        except:
            pass

        # Evidence Timeline (Chain of Custody Events)
        events = job.handling_events.all().order_by('event_timestamp')
        if events.exists():
            report.append("EVIDENCE HANDLING TIMELINE")
            report.append("-" * 40)
            for i, event in enumerate(events, 1):
                report.append(f"{i}. {event.get_event_type_display()}")
                report.append(f"   Date/Time:    {event.event_timestamp.strftime('%Y-%m-%d %H:%M:%S %Z')}")
                if event.performed_by:
                    report.append(f"   Performed By: {event.performed_by.username}")
                if event.location:
                    report.append(f"   Location:     {event.location}")
                report.append(f"   Description:  {event.event_description[:100]}")
                if event.event_type == 'transferred':
                    if event.transferred_from:
                        report.append(f"   From:         {event.transferred_from.username}")
                    if event.transferred_to:
                        report.append(f"   To:           {event.transferred_to.username}")
                report.append("")
            report.append("")

        # Forensic Documentation Status
        report.append("FORENSIC DOCUMENTATION STATUS")
        report.append("-" * 40)
        report.append(f"QA Review Required:    {job.qa_review_required}")
        report.append(f"QA Review Completed:   {job.qa_review_completed}")
        report.append(f"Forensic Doc Complete: {job.forensic_documentation_complete}")
        if job.forensic_documentation_complete:
            report.append("")
            report.append("✓ This evidence is COURT-READY")

        report.append("")
        report.append("=" * 80)
        report.append("END OF CHAIN OF CUSTODY REPORT")
        report.append("=" * 80)

        return "\n".join(report)
