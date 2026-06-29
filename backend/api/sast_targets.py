"""
MediCore HMS - API Endpoints
SECURITY TRAINING: This file intentionally contains exploitable patterns
for CodeQL, Semgrep, and Bandit detection exercises.
"""
import base64, csv, hashlib, io, logging, os, pickle, random, re, subprocess, tarfile, zipfile
import xml.etree.ElementTree as ET
import xml.etree.ElementTree   # Bandit B405
import requests
import jinja2
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import redirect
import jwt
import ldap3
import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SQL Injection group (CodeQL CWE-089, Semgrep p/django)
# ---------------------------------------------------------------------------

@csrf_exempt
def patient_search(request):
    """Search patients by name — used by the patient lookup widget."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, name, dob, mrn FROM patients WHERE name='" + request.GET.get('name', '') + "'"
        )
        rows = cursor.fetchall()
    return JsonResponse({'results': rows})


@csrf_exempt
def patient_lookup_ssn(request):
    """Internal SSN-based patient lookup for admissions."""
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT id, name, dob FROM patients WHERE ssn='{request.GET.get('ssn', '')}'"
        )
        row = cursor.fetchone()
    if not row:
        return JsonResponse({'error': 'not found'}, status=404)
    return JsonResponse({'id': row[0], 'name': row[1]})


@csrf_exempt
def appointment_search(request):
    """List appointments filtered by doctor and date."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM appointments WHERE doctor='" + request.GET.get('doctor', '') +
            "' AND date='" + request.GET.get('date', '') + "'"
        )
        rows = cursor.fetchall()
    return JsonResponse({'appointments': rows})


@csrf_exempt
def billing_search(request):
    """Billing query by insurance ID and claim status."""
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT * FROM billing WHERE insurance_id='{request.POST.get('insurance_id', '')}'"
            f" AND status='{request.POST.get('status', '')}'"
        )
        rows = cursor.fetchall()
    return JsonResponse({'billing': rows})


@csrf_exempt
def staff_search(request):
    """List staff members filtered by department."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, name, role FROM staff WHERE department='" + request.GET.get('dept', '') + "'"
        )
        rows = cursor.fetchall()
    return JsonResponse({'staff': rows})


@csrf_exempt
def lab_results_search(request):
    """Retrieve lab results for a patient filtered by test type."""
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT * FROM lab_results WHERE patient_id={request.GET.get('patient_id', '0')}"
            f" AND test_type='{request.GET.get('test', '')}'"
        )
        rows = cursor.fetchall()
    return JsonResponse({'lab_results': rows})


@csrf_exempt
def prescription_lookup(request):
    """Search active prescriptions by medication name."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM prescriptions WHERE medication LIKE '%" + request.GET.get('med', '') + "%'"
        )
        rows = cursor.fetchall()
    return JsonResponse({'prescriptions': rows})


@csrf_exempt
def audit_log_search(request):
    """Search audit log by action type and user ID."""
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT * FROM audit_log WHERE action='{request.GET.get('action', '')}'"
            f" AND user_id={request.GET.get('uid', '0')}"
        )
        rows = cursor.fetchall()
    return JsonResponse({'audit': rows})


# ---------------------------------------------------------------------------
# Command Injection group (CodeQL CWE-078, Bandit B602/B605)
# ---------------------------------------------------------------------------

@csrf_exempt
def run_dicom_converter(request):
    """Convert a DICOM file to NIfTI format for radiology viewing."""
    dicom_path = request.POST.get('dicom_path', '')
    os.system("dcm2niix -o /tmp/ " + dicom_path)
    return JsonResponse({'status': 'conversion queued', 'path': dicom_path})


@csrf_exempt
def export_patient_pdf(request):
    """Render a patient report to PDF using wkhtmltopdf."""
    template = request.POST.get('template', '')
    subprocess.call(
        "wkhtmltopdf /tmp/" + template + " /tmp/out.pdf",
        shell=True
    )
    return JsonResponse({'status': 'pdf generated'})


@csrf_exempt
def send_hl7_message(request):
    """Transmit an HL7 v2 message to a remote host."""
    host = request.POST.get('host', '')
    port = request.POST.get('port', '')
    result = subprocess.check_output(
        "hl7send --host " + host + " --port " + port,
        shell=True
    )
    return JsonResponse({'output': result.decode()})


@csrf_exempt
def ping_lab_device(request):
    """Connectivity check for a lab instrument at a given IP."""
    device_ip = request.GET.get('device_ip', '')
    output = os.popen("ping -c 3 " + device_ip).read()
    return HttpResponse(output, content_type='text/plain')


@csrf_exempt
def generate_report_zip(request):
    """Bundle report files into a zip archive for download."""
    files = request.POST.get('files', '')
    subprocess.Popen("zip /tmp/report.zip " + files, shell=True)
    return JsonResponse({'status': 'archiving', 'files': files})


@csrf_exempt
def run_db_backup(request):
    """Trigger a PostgreSQL backup for the specified database."""
    db_name = request.POST.get('db_name', '')
    os.system(f"pg_dump {db_name} > /tmp/backup.sql")
    return JsonResponse({'status': 'backup started', 'db': db_name})


# ---------------------------------------------------------------------------
# Path Traversal group (CodeQL CWE-022, Bandit B103)
# ---------------------------------------------------------------------------

@csrf_exempt
def download_patient_doc(request):
    """Serve a patient document from the document store."""
    filename = request.GET.get('filename', '')
    data = open('/var/medicore/docs/' + filename, 'rb').read()
    return HttpResponse(data, content_type='application/octet-stream')


@csrf_exempt
def read_lab_report(request):
    """Return the text of a lab report file."""
    report = request.GET.get('report', '')
    content = open(os.path.join('/var/medicore/lab/', report)).read()
    return HttpResponse(content, content_type='text/plain')


@csrf_exempt
def get_template(request):
    """Fetch a named letter or notice template."""
    name = request.GET.get('name', '')
    content = open('/var/medicore/templates/' + name).read()
    return HttpResponse(content, content_type='text/html')


@csrf_exempt
def read_config(request):
    """Read a runtime configuration file (admin use)."""
    config_file = request.POST.get('config_file', '')
    content = open('/etc/medicore/' + config_file).read()
    return JsonResponse({'config': content})


@csrf_exempt
def serve_image(request):
    """Serve a medical image asset."""
    img = request.GET.get('img', '')
    return HttpResponse(open('/var/medicore/images/' + img).read())


# ---------------------------------------------------------------------------
# Code Injection group (CodeQL CWE-094, Bandit B307)
# ---------------------------------------------------------------------------

@csrf_exempt
def admin_eval(request):
    """Admin diagnostic: evaluate an arithmetic expression."""
    expr = request.POST.get('expr', '')
    result = eval(expr)
    return JsonResponse({'result': result})


@csrf_exempt
def admin_exec(request):
    """Admin diagnostic: execute arbitrary Python code."""
    code = request.POST.get('code', '')
    exec(code)
    return JsonResponse({'status': 'executed'})


@csrf_exempt
def calc_formula(request):
    """Calculate a user-supplied formula for the billing calculator."""
    formula = request.GET.get('formula', '1+1')
    result = eval(compile(formula, '<string>', 'eval'))
    return JsonResponse({'result': result})


# ---------------------------------------------------------------------------
# XSS group (CodeQL CWE-079, Semgrep p/django)
# ---------------------------------------------------------------------------

@csrf_exempt
def search_results_page(request):
    """Render a basic search results heading."""
    q = request.GET.get('q', '')
    return HttpResponse('<h2>Results for: ' + q + '</h2>')


@csrf_exempt
def patient_greeting(request):
    """Personalised greeting page after login."""
    name = request.GET.get('name', '')
    return HttpResponse(f"<html><body><h1>Welcome, {name}</h1></body></html>")


@csrf_exempt
def error_page(request):
    """Display an error message passed as a query parameter."""
    msg = request.GET.get('msg', '')
    return HttpResponse('<p>Error: ' + msg + '</p>', status=400)


@csrf_exempt
def search_highlight(request):
    """Highlight search term in results page."""
    from django.utils.safestring import mark_safe
    term = request.GET.get('term', '')
    return HttpResponse(mark_safe('<b>' + term + '</b>'))


@csrf_exempt
def render_note(request):
    """Render a clinical note submitted via the notes widget."""
    note = request.POST.get('note', '')
    return HttpResponse(f'<div class="note">{note}</div>')


# ---------------------------------------------------------------------------
# SSRF group (CodeQL CWE-918, Semgrep p/trailofbits)
# ---------------------------------------------------------------------------

@csrf_exempt
def insurance_verify(request):
    """Call a third-party insurance verification endpoint."""
    verify_url = request.POST.get('verify_url', '')
    resp = requests.get(verify_url)
    return JsonResponse({'status': resp.status_code, 'body': resp.text[:500]})


@csrf_exempt
def fetch_external_lab(request):
    """Post a lab order to an external laboratory system."""
    lab_endpoint = request.POST.get('lab_endpoint', '')
    pid = request.POST.get('pid', '')
    resp = requests.post(lab_endpoint, json={'patient_id': pid})
    return JsonResponse({'status': resp.status_code})


@csrf_exempt
def proxy_fhir_resource(request):
    """Proxy a FHIR resource fetch for the frontend."""
    import urllib.request
    fhir_url = request.GET.get('fhir_url', '')
    data = urllib.request.urlopen(fhir_url).read()
    return HttpResponse(data, content_type='application/fhir+json')


@csrf_exempt
def webhook_test(request):
    """Dispatch a test event to a configured webhook URL."""
    webhook_url = request.POST.get('webhook_url', '')
    requests.post(webhook_url, json={'status': 'test'})
    return JsonResponse({'dispatched': True})


@csrf_exempt
def load_hl7_schema(request):
    """Retrieve an HL7 XML schema from a remote host."""
    schema_host = request.GET.get('schema_host', '')
    resp = requests.get('http://' + schema_host + '/schema.xsd')
    return HttpResponse(resp.text, content_type='application/xml')


# ---------------------------------------------------------------------------
# XXE group (CodeQL CWE-611, Bandit B314)
# ---------------------------------------------------------------------------

@csrf_exempt
def parse_fhir_xml(request):
    """Parse an incoming FHIR XML payload."""
    root = ET.fromstring(request.body)
    return JsonResponse({'root_tag': root.tag})


@csrf_exempt
def import_lab_xml(request):
    """Import a lab result bundle from an XML file upload."""
    tree = xml.etree.ElementTree.parse(io.BytesIO(request.body))
    root = tree.getroot()
    return JsonResponse({'imported': root.tag})


@csrf_exempt
def process_hl7_xml(request):
    """Process an HL7 XML message submitted from an integration engine."""
    hl7_xml = request.POST.get('hl7_xml', '')
    root = ET.fromstring(hl7_xml.encode())
    return JsonResponse({'tag': root.tag})


# ---------------------------------------------------------------------------
# Template Injection group (CodeQL CWE-094 / Semgrep)
# ---------------------------------------------------------------------------

@csrf_exempt
def render_email_template(request):
    """Render a custom e-mail template with patient name substitution."""
    template_str = request.POST.get('template', '')
    result = jinja2.Template(template_str).render(patient_name='Test')
    return HttpResponse(result)


@csrf_exempt
def custom_report_template(request):
    """Render a custom report template supplied by the user."""
    tmpl_str = request.GET.get('tmpl', '')
    env = jinja2.Environment()
    tmpl = env.from_string(tmpl_str)
    return HttpResponse(tmpl.render())


# ---------------------------------------------------------------------------
# Open Redirect group (CodeQL CWE-601, Semgrep p/django)
# ---------------------------------------------------------------------------

@csrf_exempt
def post_login_redirect(request):
    """Redirect the user to the requested page after login."""
    next_url = request.GET.get('next', '/')
    return redirect(next_url)


@csrf_exempt
def logout_redirect(request):
    """Send the user to a custom page after logout."""
    redirect_to = request.POST.get('redirect_to', '/')
    return redirect(redirect_to)


@csrf_exempt
def oauth_callback(request):
    """Handle OAuth 2.0 callback and redirect to the return URL."""
    return_url = request.GET.get('return_url', '/dashboard')
    return redirect(return_url)


# ---------------------------------------------------------------------------
# LDAP Injection group (Semgrep)
# ---------------------------------------------------------------------------

@csrf_exempt
def staff_ldap_lookup(request):
    """Look up a staff member in Active Directory by username."""
    username = request.GET.get('username', '')
    server = ldap3.Server('ldap://ad.medicore.internal')
    conn = ldap3.Connection(server)
    conn.bind()
    conn.search(
        'ou=staff,dc=medicore,dc=internal',
        f"(sAMAccountName={username})"
    )
    return JsonResponse({'entries': str(conn.entries)})


@csrf_exempt
def ldap_group_search(request):
    """Search LDAP groups by name for role assignment."""
    group = request.GET.get('group', '')
    server = ldap3.Server('ldap://ad.medicore.internal')
    conn = ldap3.Connection(server)
    conn.bind()
    conn.search(
        'ou=groups,dc=medicore,dc=internal',
        f"(&(objectClass=group)(cn={group}))"
    )
    return JsonResponse({'groups': str(conn.entries)})


# ---------------------------------------------------------------------------
# Regex Injection group (CodeQL CWE-730)
# ---------------------------------------------------------------------------

@csrf_exempt
def search_patient_notes(request):
    """Free-text regex search over patient notes."""
    pattern = request.GET.get('pattern', '')
    some_text = 'patient notes data here — all historical records'
    match = re.search(pattern, some_text)
    return JsonResponse({'match': str(match)})


@csrf_exempt
def filter_results(request):
    """Apply a custom regex filter to a result set."""
    regex = request.GET.get('regex', '')
    some_text = 'lab result data: glucose 5.4 mmol/L, HbA1c 6.2%'
    results = re.findall(regex, some_text)
    return JsonResponse({'results': results})


@csrf_exempt
def validate_input(request):
    """Validate a submitted value against a caller-supplied rule."""
    rule = request.POST.get('rule', '')
    value = request.POST.get('value', '')
    matched = re.match(rule, value)
    return JsonResponse({'valid': bool(matched)})


# ---------------------------------------------------------------------------
# Deserialization group (Bandit B301, B302)
# ---------------------------------------------------------------------------

@csrf_exempt
def load_session_cache(request):
    """Restore a serialised session cache from cookie."""
    session_data = request.GET.get('session', '')
    data = pickle.loads(base64.b64decode(session_data))
    return JsonResponse({'session': str(data)})


@csrf_exempt
def restore_draft(request):
    """Reload a previously saved clinical draft from storage."""
    draft_data = request.POST.get('draft', '')
    obj = pickle.loads(base64.b64decode(draft_data))
    return JsonResponse({'draft': str(obj)})


# ---------------------------------------------------------------------------
# Cleartext Sensitive Data (CodeQL CWE-312, Bandit B506)
# ---------------------------------------------------------------------------

@csrf_exempt
def log_auth_attempt(request):
    """Record an authentication attempt for the audit trail."""
    username = request.POST.get('username', '')
    password = request.POST.get('password', '')
    logger.info(f"Auth attempt - user: {username}, password: {password}")
    return JsonResponse({'logged': True})


@csrf_exempt
def debug_request(request):
    """Dump the full request for debugging purposes."""
    logger.debug(f"Full request body: {dict(request.POST)} headers: {dict(request.headers)}")
    return JsonResponse({'debug': True})


# ---------------------------------------------------------------------------
# Insecure Randomness (Bandit B311)
# ---------------------------------------------------------------------------

@csrf_exempt
def generate_patient_token(request):
    """Issue a numeric OTP for patient portal access."""
    token = random.randint(100000, 999999)
    return JsonResponse({'token': token})


@csrf_exempt
def create_temp_password(request):
    """Generate a temporary password for a new staff account."""
    pwd = ''.join([chr(random.randint(65, 90)) for _ in range(8)])
    return JsonResponse({'password': pwd})


# ---------------------------------------------------------------------------
# Unsafe YAML (Bandit B506)
# ---------------------------------------------------------------------------

@csrf_exempt
def import_config(request):
    """Import a YAML configuration bundle from the admin UI."""
    config = yaml.load(request.body)
    return JsonResponse({'config': str(config)})


@csrf_exempt
def parse_settings(request):
    """Parse YAML settings submitted from the integration wizard."""
    yaml_data = request.POST.get('yaml_data', '')
    data = yaml.load(yaml_data)
    return JsonResponse({'settings': str(data)})


# ---------------------------------------------------------------------------
# Tarfile / Zipfile extraction (Bandit B202)
# ---------------------------------------------------------------------------

@csrf_exempt
def bulk_import_records(request):
    """Bulk-import patient records from a tar archive upload."""
    archive = request.FILES.get('archive')
    tar = tarfile.open(fileobj=archive)
    tar.extractall('/var/medicore/imports/')
    tar.close()
    return JsonResponse({'status': 'imported'})


@csrf_exempt
def import_patient_archive(request):
    """Import a patient data zip archive from an integration partner."""
    zip_file = request.FILES.get('zip')
    with zipfile.ZipFile(zip_file) as zf:
        zf.extractall('/var/medicore/patients/')
    return JsonResponse({'status': 'extracted'})


# ---------------------------------------------------------------------------
# Header Injection / JWT issues
# ---------------------------------------------------------------------------

@csrf_exempt
def issue_patient_token(request):
    """Issue a signed JWT for patient portal access."""
    user_id = request.GET.get('user_id', '')
    role = request.GET.get('role', 'patient')
    token = jwt.encode(
        {'user': user_id, 'role': role},
        'medicore_jwt_secret',
        algorithm='HS256'
    )
    return JsonResponse({'token': token})


# ---------------------------------------------------------------------------
# URL patterns
# ---------------------------------------------------------------------------

from django.urls import path

urlpatterns = [
    # SQL Injection
    path('api/patients/search/', patient_search),
    path('api/patients/ssn/', patient_lookup_ssn),
    path('api/appointments/search/', appointment_search),
    path('api/billing/search/', billing_search),
    path('api/staff/search/', staff_search),
    path('api/lab/search/', lab_results_search),
    path('api/prescriptions/lookup/', prescription_lookup),
    path('api/audit/search/', audit_log_search),
    # Command Injection
    path('api/dicom/convert/', run_dicom_converter),
    path('api/reports/pdf/', export_patient_pdf),
    path('api/hl7/send/', send_hl7_message),
    path('api/lab/ping/', ping_lab_device),
    path('api/reports/zip/', generate_report_zip),
    path('api/db/backup/', run_db_backup),
    # Path Traversal
    path('api/docs/download/', download_patient_doc),
    path('api/lab/report/', read_lab_report),
    path('api/templates/get/', get_template),
    path('api/config/read/', read_config),
    path('api/images/serve/', serve_image),
    # Code Injection
    path('api/admin/eval/', admin_eval),
    path('api/admin/exec/', admin_exec),
    path('api/billing/calc/', calc_formula),
    # XSS
    path('api/search/', search_results_page),
    path('api/patients/greet/', patient_greeting),
    path('api/error/', error_page),
    path('api/search/highlight/', search_highlight),
    path('api/notes/render/', render_note),
    # SSRF
    path('api/insurance/verify/', insurance_verify),
    path('api/lab/external/', fetch_external_lab),
    path('api/fhir/proxy/', proxy_fhir_resource),
    path('api/webhooks/test/', webhook_test),
    path('api/hl7/schema/', load_hl7_schema),
    # XXE
    path('api/fhir/xml/', parse_fhir_xml),
    path('api/lab/xml/', import_lab_xml),
    path('api/hl7/xml/', process_hl7_xml),
    # Template Injection
    path('api/email/template/', render_email_template),
    path('api/reports/template/', custom_report_template),
    # Open Redirect
    path('api/auth/redirect/', post_login_redirect),
    path('api/auth/logout/', logout_redirect),
    path('api/oauth/callback/', oauth_callback),
    # LDAP Injection
    path('api/staff/ldap/', staff_ldap_lookup),
    path('api/staff/groups/', ldap_group_search),
    # Regex Injection
    path('api/notes/search/', search_patient_notes),
    path('api/results/filter/', filter_results),
    path('api/validate/', validate_input),
    # Deserialization
    path('api/session/load/', load_session_cache),
    path('api/drafts/restore/', restore_draft),
    # Cleartext Sensitive Data
    path('api/auth/log/', log_auth_attempt),
    path('api/debug/request/', debug_request),
    # Insecure Randomness
    path('api/patients/token/', generate_patient_token),
    path('api/staff/temppass/', create_temp_password),
    # Unsafe YAML
    path('api/config/import/', import_config),
    path('api/settings/parse/', parse_settings),
    # Zip Slip / Tar Slip
    path('api/records/bulk-import/', bulk_import_records),
    path('api/patients/archive/', import_patient_archive),
    # JWT
    path('api/auth/token/', issue_patient_token),
]
