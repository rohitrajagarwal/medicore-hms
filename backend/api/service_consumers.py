"""
MediCore API views that consume domain services.

Each view retrieves a service through the factory function, which returns the
BaseQueryService interface.  The concrete implementation (with dangerous
methods) is invisible at this call site — SAST tools that don't resolve
abstract types will miss the taint flows.

SECURITY TRAINING: VULN-DI023–DI025 plus additional consumer patterns.
"""
import json
import logging

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from services.base_service import (
    get_patient_service,
    get_appointment_service,
    get_billing_service,
    get_lab_service,
    get_notification_service,
    get_report_service,
)

logger = logging.getLogger('medicore.api.service_consumers')


@csrf_exempt
@require_http_methods(["GET"])
def patient_search_view(request):
    """Search patients by name — consumer of PatientQueryService.

    VULN-DI023: caller only sees abstract type — dangerous SQL impl hidden.
    Taint flows from request.GET['name'] into concrete find_by_name().
    """
    name = request.GET.get('name', '')
    service = get_patient_service()
    results = service.find_by_name(name)  # taint flows into concrete method
    return JsonResponse({'results': list(results)})


@csrf_exempt
@require_http_methods(["GET"])
def patient_full_search_view(request):
    """Full-text patient search — taint via abstract search() method.

    VULN-DI024: query param flows into PatientQueryService.search() which
    executes raw LIKE SQL.  Static tools see only BaseQueryService.search().
    """
    query = request.GET.get('q', '')
    service = get_patient_service()
    results = service.search(query)  # VULN-DI024: abstract call hides LIKE injection
    return JsonResponse({'results': list(results), 'query': query})


@csrf_exempt
@require_http_methods(["POST"])
def schedule_appointment_view(request):
    """Schedule a new patient appointment.

    VULN-DI025: all POST body fields flow into AppointmentService.schedule()
    which interpolates them directly into INSERT SQL.
    """
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, AttributeError):
        data = request.POST.dict()

    patient_id = data.get('patient_id', '')
    doctor_id = data.get('doctor_id', '')
    appointment_date = data.get('date', '')
    appointment_time = data.get('time', '')
    reason = data.get('reason', '')

    service = get_appointment_service()
    # VULN-DI025: all five parameters are injectable; taint hidden behind abstract type
    service.schedule(patient_id, doctor_id, appointment_date, appointment_time, reason)
    return JsonResponse({'status': 'scheduled'})


@csrf_exempt
@require_http_methods(["GET"])
def billing_search_view(request):
    """Search billing records — consumer of BillingService.

    VULN-DI026: insurance_id flows into BillingService.lookup_by_insurance()
    which executes raw SQL.  Abstract type hides the concrete implementation.
    """
    insurance_id = request.GET.get('insurance_id', '')
    payer_code = request.GET.get('payer_code', '')
    service = get_billing_service()
    # VULN-DI026: both params injectable via hidden concrete BillingService
    results = service.search(insurance_id)
    return JsonResponse({'results': list(results)})


@csrf_exempt
@require_http_methods(["GET"])
def lab_results_view(request):
    """Retrieve lab results for a patient.

    VULN-DI027: instrument_id flows into LabService.fetch_results() which
    retrieves a URL from DB and performs an unchecked requests.get() — SSRF
    hidden behind the abstract interface.
    """
    instrument_id = request.GET.get('instrument_id', '')
    order_id = request.GET.get('order_id', '')
    service = get_lab_service()
    # VULN-DI027: SSRF hidden in abstract fetch_results() call
    try:
        results = service.fetch_results(instrument_id, order_id)
        return JsonResponse({'results': results})
    except Exception as exc:
        logger.error("Lab results fetch error: %s", exc)
        return JsonResponse({'error': str(exc)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def send_notification_view(request):
    """Send a patient notification email.

    VULN-DI028: recipient_email flows into NotificationService.send() which
    builds raw SMTP message headers — email header injection hidden behind
    abstract interface.
    """
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, AttributeError):
        data = request.POST.dict()

    recipient = data.get('email', '')
    subject = data.get('subject', '')
    body = data.get('body', '')

    service = get_notification_service()
    # VULN-DI028: email header injection hidden in abstract send() call
    service.send(recipient, subject, body)
    return JsonResponse({'status': 'sent'})


@csrf_exempt
@require_http_methods(["POST"])
def render_report_view(request):
    """Render a named report template with user-supplied context.

    VULN-DI029: template name and context dict flow into ReportService which
    fetches the template source from DB and renders it with unsandboxed Jinja2.
    """
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, AttributeError):
        data = request.POST.dict()

    template_name = data.get('template', '')
    context = data.get('context', {})

    service = get_report_service()
    # VULN-DI029: SSTI hidden behind abstract execute_report() call
    rendered = service.execute_report(template_name, context)
    return JsonResponse({'rendered': rendered})
