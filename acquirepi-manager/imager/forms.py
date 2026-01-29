"""
Forms for forensic documentation and evidence handling.
"""
from django import forms
from django.contrib.auth.models import User
from .models import (
    WriteBlockerVerification, SourceDevice, QAReview,
    EvidenceHandlingEvent, EvidencePhoto, ImagingJob, DigitalSignature
)


class WriteBlockerVerificationForm(forms.ModelForm):
    """Form for documenting write-blocker verification."""

    class Meta:
        model = WriteBlockerVerification
        fields = [
            'write_blocker_used', 'write_blocker_type', 'write_blocker_model',
            'write_blocker_serial', 'pre_test_performed', 'pre_test_passed',
            'pre_test_timestamp', 'pre_test_method', 'pre_test_performed_by',
            'write_operations_detected', 'write_blocker_verified',
            'post_verification_performed', 'post_verification_passed',
            'post_verification_notes', 'test_results'
        ]
        widgets = {
            'write_blocker_model': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., Tableau T8-R2'
            }),
            'write_blocker_serial': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Serial number'
            }),
            'write_blocker_type': forms.Select(attrs={'class': 'form-select'}),
            'pre_test_timestamp': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local'
            }),
            'pre_test_method': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Describe how the write-blocker test was performed'
            }),
            'pre_test_performed_by': forms.Select(attrs={'class': 'form-select'}),
            'write_operations_detected': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 0
            }),
            'post_verification_notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3
            }),
            'test_results': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 5,
                'placeholder': 'Detailed test results and observations'
            }),
            'write_blocker_used': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'pre_test_performed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'pre_test_passed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'write_blocker_verified': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'post_verification_performed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'post_verification_passed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }
        labels = {
            'write_blocker_used': 'Write-blocker used?',
            'write_blocker_type': 'Write-blocker type',
            'write_blocker_model': 'Model',
            'write_blocker_serial': 'Serial number',
            'pre_test_performed': 'Pre-imaging test performed?',
            'pre_test_passed': 'Test passed?',
            'pre_test_timestamp': 'Test date/time',
            'pre_test_method': 'Test method',
            'pre_test_performed_by': 'Tested by',
            'write_operations_detected': 'Write operations detected',
            'write_blocker_verified': 'Verified during imaging',
            'post_verification_performed': 'Post-verification performed?',
            'post_verification_passed': 'Post-verification passed?',
            'post_verification_notes': 'Post-verification notes',
            'test_results': 'Detailed test results'
        }


class SourceDeviceForm(forms.ModelForm):
    """Form for documenting source device details."""

    class Meta:
        model = SourceDevice
        fields = [
            'manufacturer', 'model_number', 'serial_number', 'firmware_version',
            'capacity_bytes', 'capacity_formatted', 'device_type', 'interface_type',
            'physical_condition', 'damage_documented', 'damage_description',
            'smart_status', 'power_on_hours', 'power_cycle_count',
            'reallocated_sectors', 'pending_sectors', 'uncorrectable_sectors',
            'evidence_bag_number', 'evidence_seal_number', 'sealed_at',
            'sealed_by', 'storage_location', 'notes'
        ]
        widgets = {
            'manufacturer': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., Samsung, Western Digital'
            }),
            'model_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Model number'
            }),
            'serial_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Serial number'
            }),
            'firmware_version': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Firmware version'
            }),
            'capacity_bytes': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Capacity in bytes'
            }),
            'capacity_formatted': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., 500GB, 1TB'
            }),
            'device_type': forms.Select(attrs={'class': 'form-select'}),
            'interface_type': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., SATA, USB 3.0, NVMe'
            }),
            'physical_condition': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Describe physical condition, visible damage, wear and tear'
            }),
            'damage_documented': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'damage_description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3
            }),
            'smart_status': forms.Select(attrs={'class': 'form-select'}),
            'power_on_hours': forms.NumberInput(attrs={'class': 'form-control'}),
            'power_cycle_count': forms.NumberInput(attrs={'class': 'form-control'}),
            'reallocated_sectors': forms.NumberInput(attrs={'class': 'form-control'}),
            'pending_sectors': forms.NumberInput(attrs={'class': 'form-control'}),
            'uncorrectable_sectors': forms.NumberInput(attrs={'class': 'form-control'}),
            'evidence_bag_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Evidence bag number'
            }),
            'evidence_seal_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Evidence seal number'
            }),
            'sealed_at': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local'
            }),
            'sealed_by': forms.Select(attrs={'class': 'form-select'}),
            'storage_location': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Evidence locker, room number, etc.'
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3
            }),
        }


class QAReviewForm(forms.ModelForm):
    """Form for QA review checklist."""

    class Meta:
        model = QAReview
        fields = [
            'review_status', 'hash_verification_checked', 'hash_verification_passed',
            'hash_verification_notes', 'metadata_verified', 'metadata_complete',
            'metadata_notes', 'documentation_checked', 'documentation_complete',
            'documentation_notes', 'chain_of_custody_checked', 'chain_of_custody_intact',
            'chain_of_custody_notes', 'write_blocker_checked', 'write_blocker_verified',
            'write_blocker_notes', 'image_integrity_checked', 'image_integrity_verified',
            'image_integrity_notes', 'all_checks_passed', 'reviewer_comments',
            'corrections_required'
        ]
        widgets = {
            'review_status': forms.Select(attrs={'class': 'form-select'}),
            'reviewer_comments': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Overall review comments'
            }),
            'corrections_required': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'List any corrections needed'
            }),
            'hash_verification_notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2
            }),
            'metadata_notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2
            }),
            'documentation_notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2
            }),
            'chain_of_custody_notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2
            }),
            'write_blocker_notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2
            }),
            'image_integrity_notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2
            }),
        }


class QAReviewApprovalForm(forms.ModelForm):
    """Form for final QA approval."""

    class Meta:
        model = QAReview
        fields = [
            'final_approval', 'final_approval_notes', 'corrections_made',
            'corrections_description', 're_review_required'
        ]
        widgets = {
            'final_approval': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'final_approval_notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Final approval notes'
            }),
            'corrections_made': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'corrections_description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Describe corrections made'
            }),
            're_review_required': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }


class EvidenceHandlingEventForm(forms.ModelForm):
    """Form for logging evidence handling events."""

    class Meta:
        model = EvidenceHandlingEvent
        fields = [
            'event_type', 'location', 'event_description', 'witnesses',
            'witness_names', 'transferred_from', 'transferred_to',
            'transfer_reason', 'evidence_condition', 'notes'
        ]
        widgets = {
            'event_type': forms.Select(attrs={'class': 'form-select'}),
            'location': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Where the event occurred'
            }),
            'event_description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Detailed description of the event'
            }),
            'witnesses': forms.SelectMultiple(attrs={
                'class': 'form-select',
                'size': 5
            }),
            'witness_names': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2,
                'placeholder': 'Names of non-system user witnesses'
            }),
            'transferred_from': forms.Select(attrs={'class': 'form-select'}),
            'transferred_to': forms.Select(attrs={'class': 'form-select'}),
            'transfer_reason': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2,
                'placeholder': 'Reason for custody transfer'
            }),
            'evidence_condition': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Condition at time of event'
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3
            }),
        }


class EvidencePhotoForm(forms.ModelForm):
    """Form for uploading evidence photos."""

    class Meta:
        model = EvidencePhoto
        fields = ['photo', 'caption']
        widgets = {
            'photo': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': 'image/*'
            }),
            'caption': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Brief description of this photo (optional)'
            }),
        }


class DigitalSignatureForm(forms.ModelForm):
    """Form for capturing digital signatures on evidence handling events."""

    class Meta:
        model = DigitalSignature
        fields = ['signer_role', 'signer_name']
        widgets = {
            'signer_role': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., Evidence Custodian, Forensic Examiner'
            }),
            'signer_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Full legal name'
            }),
        }
