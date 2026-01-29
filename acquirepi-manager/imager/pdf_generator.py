"""
PDF generation for Chain of Custody reports.
Creates professional, court-ready PDF documents.
"""
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus import Image as RLImage
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from io import BytesIO
from datetime import datetime
from django.utils import timezone
import base64


class CoC_PDF_Generator:
    """Generate PDF Chain of Custody reports."""

    @staticmethod
    def generate(job):
        """
        Generate a professional PDF Chain of Custody report.

        Args:
            job: ImagingJob instance

        Returns:
            BytesIO object containing PDF data
        """
        buffer = BytesIO()

        # Create PDF document
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=1*inch,
            bottomMargin=0.75*inch
        )

        # Container for PDF elements
        elements = []

        # Define styles
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#003366'),
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#003366'),
            spaceAfter=10,
            spaceBefore=15,
            fontName='Helvetica-Bold',
            borderWidth=1,
            borderColor=colors.HexColor('#003366'),
            borderPadding=5,
            backColor=colors.HexColor('#E6F2FF')
        )

        subheading_style = ParagraphStyle(
            'CustomSubheading',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#003366'),
            spaceAfter=8,
            fontName='Helvetica-Bold'
        )

        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=6,
            fontName='Helvetica'
        )

        mono_style = ParagraphStyle(
            'Mono',
            parent=styles['Code'],
            fontSize=9,
            fontName='Courier',
            leftIndent=20
        )

        # Add header
        elements.append(Paragraph("CHAIN OF CUSTODY REPORT", title_style))
        elements.append(Paragraph("Digital Forensics Laboratory", styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))

        # Add generation info
        gen_text = f"<i>Report Generated: {timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z')}</i>"
        elements.append(Paragraph(gen_text, styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))

        # === CASE INFORMATION ===
        elements.append(Paragraph("CASE INFORMATION", heading_style))

        case_data = [
            ["Case Number:", job.case_number],
            ["Evidence Number:", job.evidence_number],
            ["Examiner:", job.examiner_name],
            ["Agency:", job.agency_name if hasattr(job, 'agency_name') and job.agency_name else "N/A"],
            ["Date Created:", job.created_at.strftime("%Y-%m-%d %H:%M:%S")],
        ]

        case_table = Table(case_data, colWidths=[2*inch, 4*inch])
        case_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F0F0F0')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        elements.append(case_table)
        elements.append(Spacer(1, 0.2*inch))

        # === JOB DETAILS ===
        elements.append(Paragraph("JOB DETAILS", heading_style))

        job_data = [
            ["Job ID:", f"#{job.id}"],
            ["Agent:", job.agent.hostname if job.agent else "N/A"],
            ["Status:", job.get_status_display()],
            ["Upload Method:", job.get_upload_method_display()],
            ["Created:", job.created_at.strftime("%Y-%m-%d %H:%M:%S")],
        ]

        if job.started_at:
            job_data.append(["Started:", job.started_at.strftime("%Y-%m-%d %H:%M:%S")])
        if job.completed_at:
            job_data.append(["Completed:", job.completed_at.strftime("%Y-%m-%d %H:%M:%S")])
        if job.started_at and job.completed_at:
            duration = job.completed_at - job.started_at
            hours, remainder = divmod(int(duration.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            job_data.append(["Duration:", f"{hours}h {minutes}m {seconds}s"])

        job_table = Table(job_data, colWidths=[2*inch, 4*inch])
        job_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F0F0F0')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        elements.append(job_table)
        elements.append(Spacer(1, 0.2*inch))

        # === HASH VERIFICATION ===
        if job.source_md5 or job.source_sha1 or job.source_sha256:
            elements.append(Paragraph("HASH VERIFICATION", heading_style))

            hash_data = []
            if job.source_md5:
                hash_data.append(["Source MD5:", job.source_md5])
            if job.image_md5:
                hash_data.append(["Image MD5:", job.image_md5])
            if job.source_sha1:
                hash_data.append(["Source SHA1:", job.source_sha1])
            if job.image_sha1:
                hash_data.append(["Image SHA1:", job.image_sha1])
            if job.source_sha256:
                hash_data.append(["Source SHA256:", job.source_sha256])
            if job.image_sha256:
                hash_data.append(["Image SHA256:", job.image_sha256])

            # Verification status
            if job.hash_verified:
                status_text = "✓ VERIFIED - Hashes Match"
                status_color = colors.green
            elif job.source_md5 and job.image_md5:
                status_text = "✗ FAILED - Hashes Do Not Match"
                status_color = colors.red
            else:
                status_text = "⚠ PENDING - Incomplete Hash Data"
                status_color = colors.orange

            hash_data.append(["Verification Status:", status_text])

            hash_table = Table(hash_data, colWidths=[2*inch, 4*inch])
            hash_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F0F0F0')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -2), 'Courier'),
                ('FONTNAME', (1, -1), (1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TEXTCOLOR', (1, -1), (1, -1), status_color),
            ]))

            elements.append(hash_table)
            elements.append(Spacer(1, 0.2*inch))

        # === WRITE-BLOCKER VERIFICATION ===
        try:
            wb = job.write_blocker
            elements.append(Paragraph("WRITE-BLOCKER VERIFICATION", heading_style))

            wb_data = [
                ["Write-Blocker Used:", "Yes" if wb.write_blocker_used else "No"],
            ]

            if wb.write_blocker_used:
                wb_data.extend([
                    ["Model:", wb.write_blocker_model],
                    ["Serial Number:", wb.write_blocker_serial],
                    ["Type:", wb.get_write_blocker_type_display()],
                    ["Pre-Imaging Test:", "✓ PASS" if wb.pre_imaging_test_passed else "✗ FAIL"],
                    ["Post-Imaging Test:", "✓ PASS" if wb.post_imaging_test_passed else "✗ FAIL"],
                ])

            wb_table = Table(wb_data, colWidths=[2*inch, 4*inch])
            wb_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F0F0F0')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))

            elements.append(wb_table)
            elements.append(Spacer(1, 0.2*inch))
        except:
            pass

        # === SOURCE DEVICE ===
        try:
            sd = job.source_device
            elements.append(Paragraph("SOURCE DEVICE DOCUMENTATION", heading_style))

            sd_data = [
                ["Manufacturer:", sd.manufacturer],
                ["Model:", sd.model_number],
                ["Serial Number:", sd.serial_number],
                ["Capacity:", sd.capacity],
                ["Interface:", sd.get_interface_type_display()],
                ["Device Condition:", sd.device_condition],
            ]

            sd_table = Table(sd_data, colWidths=[2*inch, 4*inch])
            sd_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F0F0F0')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))

            elements.append(sd_table)
            elements.append(Spacer(1, 0.2*inch))
        except:
            pass

        # === QA REVIEW ===
        try:
            qa = job.qa_review
            elements.append(Paragraph("QUALITY ASSURANCE REVIEW", heading_style))

            qa_data = [
                ["QA Status:", qa.get_qa_status_display()],
                ["Reviewed By:", qa.reviewed_by.username if qa.reviewed_by else "N/A"],
                ["Review Date:", qa.reviewed_at.strftime("%Y-%m-%d %H:%M:%S") if qa.reviewed_at else "N/A"],
            ]

            elements.append(Paragraph("<b>Checklist Items:</b>", normal_style))
            checklist_data = [
                ["Hash Verification", "✓ PASS" if qa.hash_verification_passed else "✗ FAIL"],
                ["Image Integrity", "✓ PASS" if qa.image_integrity_passed else "✗ FAIL"],
                ["Metadata Complete", "✓ PASS" if qa.metadata_complete else "✗ FAIL"],
                ["Documentation Complete", "✓ PASS" if qa.documentation_complete else "✗ FAIL"],
                ["Write Protection Verified", "✓ PASS" if qa.write_protection_verified else "✗ FAIL"],
                ["Chain of Custody Complete", "✓ PASS" if qa.chain_of_custody_complete else "✗ FAIL"],
            ]

            qa_table = Table(qa_data, colWidths=[2*inch, 4*inch])
            qa_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F0F0F0')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))

            elements.append(qa_table)
            elements.append(Spacer(1, 0.1*inch))

            checklist_table = Table(checklist_data, colWidths=[3*inch, 3*inch])
            checklist_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E0E0E0')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))

            elements.append(checklist_table)
            elements.append(Spacer(1, 0.2*inch))
        except:
            pass

        # === EVIDENCE TIMELINE ===
        events = job.handling_events.all().order_by('event_timestamp')
        if events.exists():
            elements.append(Paragraph("EVIDENCE HANDLING TIMELINE", heading_style))

            timeline_data = [["#", "Event", "Date/Time", "Performed By"]]

            for i, event in enumerate(events, 1):
                timeline_data.append([
                    str(i),
                    event.get_event_type_display(),
                    event.event_timestamp.strftime("%Y-%m-%d %H:%M"),
                    event.performed_by.username if event.performed_by else "System"
                ])

            timeline_table = Table(timeline_data, colWidths=[0.5*inch, 2*inch, 2*inch, 1.5*inch])
            timeline_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#003366')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F9F9F9')]),
            ]))

            elements.append(timeline_table)
            elements.append(Spacer(1, 0.2*inch))

            # Add digital signatures section
            has_signatures = any(event.signatures.exists() for event in events)
            if has_signatures:
                elements.append(Paragraph("DIGITAL SIGNATURES", heading_style))

                for i, event in enumerate(events, 1):
                    if event.signatures.exists():
                        # Event header
                        event_header = f"Event #{i}: {event.get_event_type_display()} - {event.event_timestamp.strftime('%Y-%m-%d %H:%M')}"
                        elements.append(Paragraph(event_header, ParagraphStyle(
                            'EventHeader',
                            parent=styles['Normal'],
                            fontSize=10,
                            textColor=colors.HexColor('#003366'),
                            fontName='Helvetica-Bold',
                            spaceAfter=6
                        )))

                        # Signatures for this event
                        for signature in event.signatures.all():
                            sig_data = []

                            # Signature info row
                            sig_info = f"<b>Signed by:</b> {signature.signer_name}<br/>"
                            sig_info += f"<b>Role:</b> {signature.signer_role}<br/>"
                            sig_info += f"<b>Date/Time:</b> {signature.signed_at.strftime('%Y-%m-%d %H:%M:%S')}<br/>"
                            sig_info += f"<b>Verification:</b> "

                            if signature.verify_signature():
                                sig_info += "<font color='green'>✓ Verified</font>"
                            else:
                                sig_info += "<font color='red'>✗ Failed</font>"

                            sig_info_para = Paragraph(sig_info, styles['Normal'])

                            # Try to include signature image
                            sig_image = None
                            try:
                                # Extract base64 data
                                sig_data_str = signature.signature_data
                                if sig_data_str.startswith('data:image/png;base64,'):
                                    sig_data_str = sig_data_str.replace('data:image/png;base64,', '')

                                # Decode base64 to image
                                img_data = base64.b64decode(sig_data_str)
                                img_buffer = BytesIO(img_data)
                                sig_image = RLImage(img_buffer, width=2*inch, height=0.8*inch)
                            except:
                                # If signature image fails, just show text
                                pass

                            if sig_image:
                                sig_table = Table([[sig_info_para, sig_image]], colWidths=[3.5*inch, 2*inch])
                            else:
                                sig_table = Table([[sig_info_para]], colWidths=[5.5*inch])

                            sig_table.setStyle(TableStyle([
                                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F9F9F9')),
                                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                                ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
                                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                                ('TOPPADDING', (0, 0), (-1, -1), 8),
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                                ('BOX', (0, 0), (-1, -1), 0.5, colors.grey),
                            ]))

                            elements.append(sig_table)
                            elements.append(Spacer(1, 0.1*inch))

                        elements.append(Spacer(1, 0.1*inch))

                elements.append(Spacer(1, 0.1*inch))

        # === FORENSIC STATUS ===
        elements.append(Paragraph("FORENSIC DOCUMENTATION STATUS", heading_style))

        status_data = [
            ["QA Review Required:", "Yes" if job.qa_review_required else "No"],
            ["QA Review Completed:", "Yes" if job.qa_review_completed else "No"],
            ["Forensic Documentation Complete:", "Yes" if job.forensic_documentation_complete else "No"],
        ]

        if job.forensic_documentation_complete:
            status_data.append(["Court-Ready Status:", "✓ APPROVED FOR COURT USE"])

        status_table = Table(status_data, colWidths=[3*inch, 3*inch])
        status_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F0F0F0')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        elements.append(status_table)

        # Add footer note
        elements.append(Spacer(1, 0.3*inch))
        footer_text = f"""
        <para alignment="center">
        <i>This report was automatically generated by the acquirepi Digital Forensics System.<br/>
        Report ID: JOB-{job.id} | Generated: {timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z')}</i>
        </para>
        """
        elements.append(Paragraph(footer_text, normal_style))

        # Build PDF
        doc.build(elements)

        buffer.seek(0)
        return buffer
