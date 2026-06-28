"""
MediCore HMS - Patient Models
SECURITY TRAINING PROJECT - Intentionally vulnerable
"""
from django.db import models
from django.contrib.auth.models import User


class Patient(models.Model):
    """Core patient model with intentional security issues"""
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    date_of_birth = models.DateField()
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20)

    # VULN-PHI-001: SSN stored in plaintext - should be encrypted
    ssn = models.CharField(max_length=11)  # Stored as XXX-XX-XXXX plaintext

    # VULN-PHI-002: Insurance number in plaintext
    insurance_id = models.CharField(max_length=50)
    insurance_provider = models.CharField(max_length=100)

    address = models.TextField()
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=50)
    zip_code = models.CharField(max_length=10)

    # Medical information
    blood_type = models.CharField(max_length=5)
    allergies = models.TextField(blank=True)
    medical_history = models.TextField(blank=True)

    # VULN-PHI-003: Emergency contact with full PII
    emergency_contact_name = models.CharField(max_length=100)
    emergency_contact_phone = models.CharField(max_length=20)
    emergency_contact_relationship = models.CharField(max_length=50)

    # VULN-AUTH-001: No field-level access control on sensitive fields
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_patients')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # VULN-PHI-004: Patient photo stored with predictable filename
    photo = models.ImageField(upload_to='patient_photos/', null=True, blank=True)

    class Meta:
        db_table = 'patients'

    def __str__(self):
        return f"{self.first_name} {self.last_name} (ID: {self.id})"


class MedicalRecord(models.Model):
    """Medical records - highly sensitive PHI"""
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='medical_records')
    doctor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    record_date = models.DateTimeField()
    chief_complaint = models.TextField()
    diagnosis = models.TextField()
    treatment_plan = models.TextField()
    notes = models.TextField(blank=True)

    # VULN-PHI-005: Sensitive diagnosis codes stored without encryption
    icd10_codes = models.JSONField(default=list)  # e.g. ["F32.1", "E11.9"]

    # VULN-FILE-001: File stored with original filename - path traversal risk
    document = models.FileField(upload_to='medical_records/', null=True, blank=True)

    is_confidential = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'medical_records'


class VitalSigns(models.Model):
    """Patient vital signs"""
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    recorded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    recorded_at = models.DateTimeField(auto_now_add=True)
    blood_pressure_systolic = models.IntegerField()
    blood_pressure_diastolic = models.IntegerField()
    heart_rate = models.IntegerField()
    temperature = models.DecimalField(max_digits=5, decimal_places=2)
    weight = models.DecimalField(max_digits=6, decimal_places=2)
    height = models.DecimalField(max_digits=5, decimal_places=2)
    oxygen_saturation = models.IntegerField()
    notes = models.TextField(blank=True)

    class Meta:
        db_table = 'vital_signs'


class PatientDocument(models.Model):
    """Patient uploaded documents"""
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    document_type = models.CharField(max_length=50)
    # VULN-FILE-002: Original filename used without sanitization
    original_filename = models.CharField(max_length=255)
    # VULN-FILE-003: File stored in predictable path
    file = models.FileField(upload_to='patient_documents/')
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'patient_documents'
