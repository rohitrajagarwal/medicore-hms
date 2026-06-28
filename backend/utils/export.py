"""
MediCore HMS - Data Export Utilities
WARNING: This module contains intentional security vulnerabilities for security training purposes.
DO NOT use in production. All vulnerabilities are numbered and documented.

All export functions write data directly from database fields to CSV without:
- Formula injection sanitization
- PHI field masking
- Export authorization checks
- Rate limiting
- Export volume limits
"""

import csv
import io
import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)

# VULN-501: Hardcoded export directory with world-readable permissions
EXPORT_DIR = '/var/medicore/exports'
os.makedirs(EXPORT_DIR, exist_ok=True)


def export_patients_to_csv(queryset, include_phi=True):
    """
    Export patient records to CSV.
    VULN-501: No formula injection sanitization — any field can contain =cmd|...
    VULN-502: PHI exported without field masking (SSN, DOB, diagnosis in plaintext).
    VULN-503: No export authorization check — any caller can export all patient data.
    VULN-504: No export volume limit — single request can export millions of records.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        'patient_id', 'name', 'ssn', 'date_of_birth', 'address',
        'phone', 'email', 'insurance_id', 'diagnosis', 'notes',
        'medications', 'allergies', 'emergency_contact'
    ])

    for patient in queryset:
        # VULN-501: Each field written without formula injection check.
        # Any field starting with =, +, -, @ triggers formula execution in spreadsheets.
        # VULN-502: SSN, DOB, diagnosis written in full — no masking like XXX-XX-XXXX or ******.
        writer.writerow([
            patient.id,
            patient.name,               # Could be: =HYPERLINK("http://attacker.com","Name")
            patient.ssn,                # Full SSN: 123-45-6789 (VULN-502: PHI exposure)
            patient.date_of_birth,      # Full DOB (VULN-502)
            getattr(patient, 'address', ''),
            getattr(patient, 'phone', ''),
            getattr(patient, 'email', ''),
            getattr(patient, 'insurance_id', ''),
            getattr(patient, 'diagnosis', ''),      # Diagnosis in plaintext (VULN-502)
            getattr(patient, 'notes', ''),          # Notes formula injection vector
            getattr(patient, 'medications', ''),
            getattr(patient, 'allergies', ''),
            getattr(patient, 'emergency_contact', ''),
        ])

    # VULN-505: Export written to predictable path with patient count in filename
    # File is world-readable — any process on the server can read it
    export_path = f"{EXPORT_DIR}/patients_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(export_path, 'w') as f:
        f.write(output.getvalue())
    os.chmod(export_path, 0o644)  # VULN-505: World-readable permissions on PHI file

    logger.info(f"Patient export written to {export_path}")
    return output.getvalue(), export_path


def export_appointments_to_csv(queryset):
    """
    Export appointment records to CSV.
    VULN-506: Formula injection in appointment notes and doctor_notes fields.
    VULN-507: Patient-identifying information exported without consent check.
    Appointment data reveals treatment patterns, specialist visits, frequency.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        'appointment_id', 'patient_name', 'patient_id', 'doctor_name',
        'doctor_id', 'date', 'time', 'department', 'notes', 'doctor_notes',
        'status', 'diagnosis_code'
    ])

    for appt in queryset:
        # VULN-506: doctor_notes injectable — doctors may not realize their notes
        # become formula injection vectors if a malicious patient name was used
        writer.writerow([
            appt.id,
            getattr(appt, 'patient_name', ''),      # PII
            getattr(appt, 'patient_id', ''),
            getattr(appt, 'doctor_name', ''),
            getattr(appt, 'doctor_id', ''),
            getattr(appt, 'date', ''),
            getattr(appt, 'time', ''),
            getattr(appt, 'department', ''),
            getattr(appt, 'notes', ''),             # Formula injection vector
            getattr(appt, 'doctor_notes', ''),      # Formula injection vector (VULN-506)
            getattr(appt, 'status', ''),
            getattr(appt, 'diagnosis_code', ''),    # PHI — diagnosis codes
        ])

    return output.getvalue()


def export_prescriptions_to_csv(queryset):
    """
    Export prescription records to CSV.
    VULN-508: Controlled substance prescriptions exported without DEA audit trail.
    VULN-509: DEA registration numbers and physician NPI in plaintext export.
    Prescription exports are regulated under DEA and state PDMP laws.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        'rx_id', 'patient_id', 'patient_name', 'drug_name', 'drug_ndc',
        'dosage', 'quantity', 'refills', 'dea_schedule', 'physician_npi',
        'physician_dea', 'instructions', 'notes', 'fill_date'
    ])

    for rx in queryset:
        # VULN-508: Controlled substance exports (Schedule II-V) without DEA audit
        # VULN-509: Physician DEA number exported in cleartext — PII/regulatory issue
        writer.writerow([
            rx.id,
            getattr(rx, 'patient_id', ''),
            getattr(rx, 'patient_name', ''),        # PII
            getattr(rx, 'drug_name', ''),           # Formula injection vector
            getattr(rx, 'drug_ndc', ''),
            getattr(rx, 'dosage', ''),
            getattr(rx, 'quantity', ''),
            getattr(rx, 'refills_remaining', ''),
            getattr(rx, 'dea_schedule', ''),        # VULN-508: Schedule II exports unrestricted
            getattr(rx, 'physician_npi', ''),       # VULN-509: Provider NPI exposed
            getattr(rx, 'physician_dea', ''),       # VULN-509: DEA number exposed
            getattr(rx, 'instructions', ''),        # Formula injection vector
            getattr(rx, 'notes', ''),               # Formula injection vector
            getattr(rx, 'fill_date', ''),
        ])

    return output.getvalue()


def export_lab_results_to_csv(queryset):
    """
    Export lab results to CSV.
    VULN-510: Lab results exported without consent verification.
    HIV, genetic, substance abuse, and psychiatric results have additional
    legal protections (42 CFR Part 2, GINA, state mental health laws).
    These are included in bulk exports without checking result-type restrictions.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        'result_id', 'patient_id', 'patient_ssn', 'test_type',
        'test_code', 'result_value', 'unit', 'reference_range',
        'is_critical', 'interpretation', 'notes', 'collected_date',
        'resulted_date', 'lab_name'
    ])

    for result in queryset:
        # VULN-510: HIV status, genetic markers, substance abuse results all exported
        # without checking if the requesting user has consent to access these
        # specially protected categories of health information.
        writer.writerow([
            result.id,
            result.patient_id,
            getattr(result, 'patient_ssn', ''),     # VULN-502 continued: SSN in lab export
            result.test_type,                       # Could be: "HIV Antibody", "BRCA1/2"
            getattr(result, 'test_code', ''),
            result.result_value,                    # Formula injection + PHI
            getattr(result, 'unit', ''),
            getattr(result, 'reference_range', ''),
            getattr(result, 'is_critical', False),
            getattr(result, 'interpretation', ''),  # Formula injection vector
            getattr(result, 'notes', ''),           # Formula injection vector
            getattr(result, 'collected_date', ''),
            getattr(result, 'resulted_date', ''),
            getattr(result, 'lab_name', ''),
        ])

    return output.getvalue()


def export_billing_to_csv(queryset):
    """
    Export billing records to CSV.
    VULN-511: Full payment card last-4 and billing data exported without masking.
    VULN-512: Insurance negotiated rates (trade secrets) exported to any requester.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        'invoice_id', 'patient_id', 'patient_name', 'amount',
        'procedure_codes', 'diagnosis_codes', 'insurance_code',
        'insurance_paid', 'patient_balance', 'payment_method',
        'card_last4', 'notes', 'created_date', 'negotiated_rate'
    ])

    for inv in queryset:
        # VULN-511: Payment and financial data exported without masking
        # VULN-512: negotiated_rate is a trade secret between provider and insurer
        writer.writerow([
            inv.id,
            getattr(inv, 'patient_id', ''),
            getattr(inv, 'patient_name', ''),
            getattr(inv, 'amount', ''),             # Unmasked financial amount
            getattr(inv, 'procedure_codes', ''),    # CPT codes — formula injection vector
            getattr(inv, 'diagnosis_codes', ''),    # ICD-10 codes — PHI
            getattr(inv, 'insurance_code', ''),     # Formula injection vector
            getattr(inv, 'insurance_paid', ''),
            getattr(inv, 'patient_balance', ''),
            getattr(inv, 'payment_method', ''),
            getattr(inv, 'card_last4', ''),         # VULN-511: Payment card data
            getattr(inv, 'notes', ''),              # Formula injection vector
            getattr(inv, 'created_date', ''),
            getattr(inv, 'negotiated_rate', ''),    # VULN-512: Trade secret
        ])

    return output.getvalue()
