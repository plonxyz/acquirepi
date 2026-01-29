"""
QR Code utilities for evidence tracking and chain of custody.
"""
import qrcode
from io import BytesIO
from django.conf import settings


class QRCodeGenerator:
    """Generate QR codes for imaging jobs."""

    @staticmethod
    def generate_job_qr(job, base_url=None):
        """
        Generate QR code for a job that links to its detail page.

        Args:
            job: ImagingJob instance
            base_url: Optional base URL (e.g., 'http://192.168.1.100:8000')
                     If not provided, will be constructed from settings

        Returns:
            BytesIO object containing PNG image data
        """
        # Construct the job detail URL
        if not base_url:
            # Try to get from settings, fallback to localhost
            base_url = getattr(settings, 'SITE_URL', 'http://localhost:8000')

        job_url = f"{base_url}/jobs/{job.id}/"

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,  # Size (1-40, higher = more data)
            error_correction=qrcode.constants.ERROR_CORRECT_H,  # High error correction for forensic use
            box_size=10,  # Size of each box in pixels
            border=4,  # Border size in boxes
        )

        qr.add_data(job_url)
        qr.make(fit=True)

        # Create image
        img = qr.make_image(fill_color="black", back_color="white")

        # Save to BytesIO
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)

        return buffer

    @staticmethod
    def generate_custody_transfer_qr(job, base_url=None):
        """
        Generate QR code for logging custody transfers.
        Links to custody transfer page.

        Args:
            job: ImagingJob instance
            base_url: Optional base URL

        Returns:
            BytesIO object containing PNG image data
        """
        if not base_url:
            base_url = getattr(settings, 'SITE_URL', 'http://localhost:8000')

        # Link to custody transfer logging page
        transfer_url = f"{base_url}/jobs/{job.id}/custody-scan/"

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )

        qr.add_data(transfer_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)

        return buffer

    @staticmethod
    def generate_evidence_data_qr(job):
        """
        Generate QR code containing evidence metadata (not a URL).
        Useful for offline scanning and verification.

        Args:
            job: ImagingJob instance

        Returns:
            BytesIO object containing PNG image data
        """
        # Format: CASE:1234|EVIDENCE:001|EXAMINER:JDoe|DATE:2025-10-27
        data = (
            f"ACQUIREPI-EVIDENCE\n"
            f"Case: {job.case_number}\n"
            f"Evidence: {job.evidence_number}\n"
            f"Examiner: {job.created_by.username if job.created_by else 'N/A'}\n"
            f"Created: {job.created_at.strftime('%Y-%m-%d %H:%M')}\n"
            f"Job ID: {job.id}"
        )

        qr = qrcode.QRCode(
            version=2,  # Slightly larger for more text
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )

        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)

        return buffer
