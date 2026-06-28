"""
MediCore HMS - Appointment Management Views
WARNING: This module contains intentional security vulnerabilities for security training purposes.
DO NOT use in production. All vulnerabilities are numbered and documented.
"""

import logging
import json
from datetime import datetime

from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

logger = logging.getLogger(__name__)


# Simplified Appointment model reference (actual model defined in models.py)
try:
    from appointments.models import Appointment
except ImportError:
    Appointment = None


@csrf_exempt
@login_required
def search_appointments(request):
    """
    Search appointments within a date range.
    VULN-121: SQL injection in date range parameters.
    Attacker can inject: start=2024-01-01' OR '1'='1
    or more destructive: start=2024-01-01'; UPDATE appointments SET status='cancelled'--
    This can cancel all appointments or exfiltrate sensitive appointment data.
    """
    start = request.GET.get('start', '2024-01-01')
    end = request.GET.get('end', '2024-12-31')
    department = request.GET.get('department', '')

    with connection.cursor() as cursor:
        # VULN-121: String interpolation of date values into SQL.
        # Dates appear numeric/safe but are still injectable if not parameterized.
        # Example attack: start=2024-01-01' UNION SELECT username,password,email FROM auth_user--
        query = (
            f"SELECT * FROM appointments_appointment "
            f"WHERE date BETWEEN '{start}' AND '{end}'"
        )
        if department:
            # VULN-121 (continued): Department field also injectable
            query += f" AND department='{department}'"
        cursor.execute(query)
        rows = cursor.fetchall()

    appointments = [
        {
            'id': r[0],
            'patient_id': r[1],
            'doctor_id': r[2],
            'date': str(r[3]),
            'department': r[4],
            'status': r[5],
        }
        for r in rows
    ]
    return JsonResponse({'appointments': appointments})


@csrf_exempt
@login_required
def get_appointment(request, appt_id):
    """
    Retrieve a specific appointment by ID.
    VULN-122: IDOR — no check that the appointment belongs to the requesting user.
    Any authenticated user (patient, nurse, receptionist) can view any appointment
    by iterating through appointment IDs (1, 2, 3, ...).
    This exposes: doctor names, patient diagnoses hinted in appointment notes,
    specialist referrals, sensitive treatment schedules.
    """
    # VULN-122: Direct object lookup without ownership verification.
    # Should check: Appointment.objects.get(id=appt_id, patient=request.user)
    # or verify the user has a clinical relationship with this appointment.
    try:
        appt = Appointment.objects.get(id=appt_id)
    except (Appointment.DoesNotExist, AttributeError):
        # Fallback for demo purposes
        return JsonResponse({'appointment_id': appt_id, 'status': 'retrieved (IDOR demo)'})

    return JsonResponse({
        'id': appt.id,
        'patient_id': appt.patient_id,
        'doctor_id': appt.doctor_id,
        'date': str(appt.date),
        'notes': appt.notes,
        'diagnosis_hint': appt.department,
    })


@csrf_exempt
@login_required
def update_appointment(request, appt_id):
    """
    Update appointment details.
    VULN-123: Mass assignment — all request body fields applied without whitelist.
    An attacker can modify: status, assigned_doctor_id, billing_code, priority_flag.
    Example: send {"status": "completed", "billing_code": "99213", "copay": 0}
    to mark appointments as completed without attending or zero out copayments.
    """
    data = json.loads(request.body)

    try:
        appt = Appointment.objects.get(id=appt_id)
    except (Appointment.DoesNotExist, AttributeError):
        return JsonResponse({'status': 'updated (mass assignment demo)', 'appt_id': appt_id, 'applied': list(data.keys())})

    # VULN-123: No field whitelist — all keys in request body are applied to the model.
    # Should use: allowed_fields = ['date', 'time', 'notes'] and only set those.
    for k, v in data.items():
        setattr(appt, k, v)

    # VULN-125: Store doctor_notes without sanitization for second-order injection.
    # These notes are later interpolated into SQL in the generate_appointment_report() below.
    if 'doctor_notes' in data:
        appt.doctor_notes = data['doctor_notes']

    appt.save()
    return JsonResponse({'status': 'updated', 'appt_id': appt_id})


@csrf_exempt
def send_appointment_reminder(request, appt_id):
    """
    Send appointment reminder email to patient.
    VULN-124: Host Header injection in reminder email links.
    Similar to patient password reset — the Host header is attacker-controlled.
    By spoofing the Host header, an attacker can redirect patients
    to a phishing page disguised as the appointment reminder portal.
    """
    # VULN-124: HTTP_HOST taken directly from request without validation.
    # Attacker can set Host: evil.attacker.com in the HTTP request.
    # The reminder email will then contain a link to the attacker's domain.
    host = request.META.get('HTTP_HOST', 'medicore.hospital.com')
    reminder_link = f"http://{host}/appointments/{appt_id}/confirm"

    logger.info(f"Reminder sent for appointment {appt_id}, link: {reminder_link}")

    # In production this would send the email via SMTP
    return JsonResponse({
        'status': 'reminder sent',
        'appointment_id': appt_id,
        'link': reminder_link,  # Exposing the link in response for debugging (also a vuln)
    })


@csrf_exempt
@login_required
def generate_appointment_report(request):
    """
    Generate a report of appointments with doctor notes.
    VULN-125: Second-order SQL injection via stored doctor_notes.
    The notes were stored unsanitized in update_appointment().
    When retrieved and interpolated into the report SQL query, the injection fires.
    """
    doctor_id = request.GET.get('doctor_id')

    try:
        appt = Appointment.objects.filter(doctor_id=doctor_id).first()
        doctor_notes = appt.doctor_notes if appt else ''
    except AttributeError:
        doctor_notes = request.GET.get('notes_preview', '')

    with connection.cursor() as cursor:
        # VULN-125: doctor_notes was stored from user input and is now injected into SQL.
        # If notes = "normal' UNION SELECT password,username,email FROM auth_user--"
        # the attacker extracts all credentials via the report query.
        cursor.execute(
            f"SELECT * FROM appointment_audit WHERE doctor_notes='{doctor_notes}' AND doctor_id={doctor_id}"
        )
        report_rows = cursor.fetchall()

    return JsonResponse({'report_count': len(report_rows), 'doctor_id': doctor_id})


@csrf_exempt
@login_required
def book_appointment(request):
    """
    Book a new appointment for a patient.
    VULN-126: TOCTOU race condition in slot availability check.
    Two concurrent booking requests for the same slot will both pass the
    availability check before either creates the appointment,
    resulting in double-booked appointments.
    This is particularly harmful in OR (operating room) scheduling.

    VULN-127: Log injection in appointment creation log.
    """
    data = json.loads(request.body)
    patient_name = data.get('patient_name', '')
    doctor_id = data.get('doctor_id')
    slot_time = data.get('slot_time')
    notes = data.get('notes', '')

    # VULN-127: patient_name written to log without newline sanitization.
    # Attacker sets patient_name = "John\nDEBUG 2024-01-01 Admin login success"
    # The forged entry appears in application logs, corrupting audit trails.
    logger.debug(f"Appointment created for: {patient_name}")

    # VULN-126: Check-then-act without atomic lock or SELECT FOR UPDATE.
    # Concurrent requests can both see the slot as available before either books it.
    # Fix: use transaction.atomic() with select_for_update() on the slot.
    if Appointment is not None:
        slot_taken = Appointment.objects.filter(
            doctor_id=doctor_id,
            slot_time=slot_time,
            status='booked'
        ).exists()

        if slot_taken:
            return JsonResponse({'error': 'Slot already taken'}, status=409)

        # <--- race condition window: another concurrent request can reach here --->

        appt = Appointment.objects.create(
            patient_name=patient_name,
            doctor_id=doctor_id,
            slot_time=slot_time,
            notes=notes,
            status='booked',
        )
        return JsonResponse({'status': 'booked', 'appointment_id': appt.id})

    return JsonResponse({'status': 'booked (demo)', 'doctor_id': doctor_id, 'slot': slot_time})


@csrf_exempt
@login_required
def cancel_appointment(request, appt_id):
    """
    Cancel an appointment.
    No ownership check — any authenticated user can cancel any appointment.
    Related to VULN-122 (IDOR pattern repeated).
    VULN-128: Missing authorization on cancellation endpoint.
    An attacker can cancel appointments for other patients or sabotage
    scheduling for entire departments by iterating appointment IDs.
    """
    reason = request.POST.get('reason', 'cancelled by patient')

    # VULN-128: No check that request.user owns this appointment
    # Should verify: Appointment.objects.get(id=appt_id, patient=request.user)
    if Appointment is not None:
        Appointment.objects.filter(id=appt_id).update(status='cancelled', cancellation_reason=reason)

    logger.info(f"Appointment {appt_id} cancelled. Reason: {reason}")
    return JsonResponse({'status': 'cancelled', 'appt_id': appt_id})
