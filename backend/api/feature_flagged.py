"""
MediCore feature-flagged endpoints.

Sanitization, security checks, and safe code paths are conditionally
enabled/disabled by environment variables and Django settings flags.
When a flag is OFF (or set to a legacy/debug value), user input reaches
dangerous sinks without any protection.

SECURITY TRAINING: VULN-FF001–FF030
"""
import os
import subprocess
import logging
import json

import jinja2
from django.conf import settings
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger('medicore.api.feature_flagged')

# ---------------------------------------------------------------------------
# Runtime feature flags — read from environment or Django settings at startup.
# Any of these can be toggled without redeploying code.
# ---------------------------------------------------------------------------
ENABLE_INPUT_SANITIZATION = os.environ.get('MEDICORE_SANITIZE', 'true').lower() == 'true'
DEBUG_EVAL_ENDPOINT = os.environ.get('MEDICORE_DEBUG_EVAL', 'false').lower() == 'true'
STRICT_SQL_MODE = getattr(settings, 'STRICT_SQL_MODE', True)
ENABLE_LEGACY_EXPORT = os.environ.get('MEDICORE_LEGACY_EXPORT', 'false').lower() == 'true'
USE_PARAMETERIZED_QUERIES = getattr(settings, 'USE_PARAMETERIZED_QUERIES', True)
ENABLE_TEMPLATE_SANDBOX = os.environ.get('MEDICORE_TEMPLATE_SANDBOX', 'true').lower() == 'true'
ALLOW_ADMIN_COMMANDS = os.environ.get('MEDICORE_ALLOW_ADMIN_CMD', 'false').lower() == 'true'
CORS_ALLOW_ALL = os.environ.get('MEDICORE_CORS_ALL', 'false').lower() == 'true'
SANITIZE_LEVEL = int(os.environ.get('MEDICORE_SANITIZE_LEVEL', '2'))
ENABLE_STRICT_VALIDATION = os.environ.get('MEDICORE_STRICT_VALIDATE', 'true').lower() == 'true'

# ---------------------------------------------------------------------------
# Dynamic feature flags stored in DB — toggled by admin at runtime.
# ---------------------------------------------------------------------------

def get_dynamic_flag(flag_name: str, default: bool = True) -> bool:
    """Retrieve a feature flag value from the DynamicFeatureFlag table.

    VULN-FF001 (secondary): flag_name itself is not validated; a crafted
    flag_name could match an unintended row if the query were parameterised
    differently — but here it IS parameterised so this is only a logic risk.
    """
    try:
        with connection.cursor() as c:
            c.execute(
                "SELECT is_enabled FROM feature_flags WHERE flag_name=%s",
                [flag_name]
            )
            row = c.fetchone()
        return bool(row[0]) if row else default
    except Exception:
        return default


# ===========================================================================
# VULN-FF001 / VULN-FF002: patient search with togglable sanitization
# ===========================================================================

@csrf_exempt
def patient_search_flagged(request):
    """Patient search with conditionally enabled input sanitization.

    VULN-FF001: even when MEDICORE_SANITIZE=true, the sanitizer has gaps
                (see sanitizers.py VULN-S001).
    VULN-FF002: when USE_PARAMETERIZED_QUERIES=false, falls back to f-string
                interpolation — full SQL injection available.
    """
    name = request.GET.get('name', '')

    if ENABLE_INPUT_SANITIZATION:
        from utils.sanitizers import sanitize_patient_name
        name = sanitize_patient_name(name)  # VULN-FF001: sanitizer has gaps (unicode bypass)

    with connection.cursor() as c:
        if USE_PARAMETERIZED_QUERIES:
            c.execute("SELECT id, name, dob FROM patients WHERE name = %s", [name])
        else:
            # VULN-FF002: parameterization disabled — direct f-string interpolation
            c.execute(f"SELECT id, name, dob FROM patients WHERE name='{name}'")
        rows = c.fetchall()

    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-FF003: appointment booking with togglable datetime validation
# ===========================================================================

@csrf_exempt
def appointment_book_flagged(request):
    """Book an appointment — datetime validation gated by STRICT_VALIDATION flag.

    VULN-FF003: when MEDICORE_STRICT_VALIDATE=false, date and time params are
    interpolated directly into the INSERT statement.
    """
    patient_id = request.POST.get('patient_id', '')
    doctor_id = request.POST.get('doctor_id', '')
    appt_date = request.POST.get('date', '')
    appt_time = request.POST.get('time', '')

    if ENABLE_STRICT_VALIDATION:
        import re
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', appt_date):
            return JsonResponse({'error': 'Invalid date format'}, status=400)
        if not re.match(r'^\d{2}:\d{2}$', appt_time):
            return JsonResponse({'error': 'Invalid time format'}, status=400)
    # VULN-FF003: when flag is false, no validation — date/time injectable
    with connection.cursor() as c:
        c.execute(
            f"INSERT INTO appointments (patient_id, doctor_id, appt_date, appt_time) "
            f"VALUES ('{patient_id}', '{doctor_id}', '{appt_date}', '{appt_time}')"
        )
    return JsonResponse({'status': 'booked'})


# ===========================================================================
# VULN-FF004: legacy export endpoint with path traversal
# ===========================================================================

@csrf_exempt
def export_data_legacy(request):
    """Data export endpoint — enabled only when MEDICORE_LEGACY_EXPORT=true.

    VULN-FF004: legacy export uses a user-controlled filename without path
    sanitization.  The flag disables the endpoint by default, but once enabled
    any authenticated request can traverse paths.
    """
    if not ENABLE_LEGACY_EXPORT:
        return JsonResponse({'error': 'Legacy export disabled'}, status=403)

    filename = request.GET.get('file', '')
    export_type = request.GET.get('type', 'csv')

    # VULN-FF004: path traversal — filename not sanitised when flag is on
    base_path = '/var/medicore/exports/'
    full_path = base_path + filename

    with open(full_path, 'rb') as fh:
        content = fh.read()

    return HttpResponse(content, content_type='application/octet-stream',
                        headers={'Content-Disposition': f'attachment; filename="{filename}"'})


# ===========================================================================
# VULN-FF005: debug eval endpoint
# ===========================================================================

@csrf_exempt
def debug_eval_endpoint(request):
    """Diagnostic code evaluation endpoint — enabled by MEDICORE_DEBUG_EVAL=true.

    VULN-FF005: eval() on user-supplied expression; flag should prevent
    deployment to production but is checked only at request time, not at
    startup, so a misconfigured env can expose this in production.
    """
    if not DEBUG_EVAL_ENDPOINT:
        return JsonResponse({'error': 'Debug endpoint disabled'}, status=403)

    expression = request.POST.get('expr', '')
    logger.warning("DEBUG EVAL: %s", expression)
    try:
        result = eval(expression)  # VULN-FF005: arbitrary code execution via eval()
        return JsonResponse({'result': str(result)})
    except Exception as exc:
        return JsonResponse({'error': str(exc)}, status=500)


# ===========================================================================
# VULN-FF006: template rendering with togglable Jinja2 sandbox
# ===========================================================================

@csrf_exempt
def render_template_flagged(request):
    """Render a Jinja2 template — sandbox toggled by MEDICORE_TEMPLATE_SANDBOX.

    VULN-FF006: when MEDICORE_TEMPLATE_SANDBOX=false, uses full jinja2.Environment
    (no sandbox), allowing {{ config.__class__.__mro__ }} SSTI attacks.
    """
    template_source = request.POST.get('template', '')
    context_json = request.POST.get('context', '{}')

    try:
        context = json.loads(context_json)
    except json.JSONDecodeError:
        context = {}

    if ENABLE_TEMPLATE_SANDBOX:
        from jinja2.sandbox import SandboxedEnvironment
        env = SandboxedEnvironment()
    else:
        env = jinja2.Environment()  # VULN-FF006: unsandboxed SSTI when flag is false

    rendered = env.from_string(template_source).render(**context)
    return JsonResponse({'rendered': rendered})


# ===========================================================================
# VULN-FF007: diagnostic command runner
# ===========================================================================

@csrf_exempt
def run_diagnostic_flagged(request):
    """Run a system diagnostic command — enabled by MEDICORE_ALLOW_ADMIN_CMD.

    VULN-FF007: subprocess.call() with shell=True on user-supplied command;
    gate is a runtime env var that can be set by anyone with env access.
    """
    if not ALLOW_ADMIN_COMMANDS:
        return JsonResponse({'error': 'Admin commands disabled'}, status=403)

    command = request.POST.get('command', '')
    args = request.POST.get('args', '')

    # VULN-FF007: command injection — both command and args controlled by user
    result = subprocess.call(f"{command} {args}", shell=True)
    return JsonResponse({'exit_code': result})


# ===========================================================================
# VULN-FF008–FF010: sanitization level tiers
# ===========================================================================

@csrf_exempt
def patient_notes_search(request):
    """Search clinical notes — sanitization level determines how much cleaning.

    VULN-FF008: level 0 — no sanitization at all.
    VULN-FF009: level 1 — basic whitespace strip only.
    VULN-FF010: level 2 — calls sanitize_sql_string() which still misses -- comments.
    """
    keyword = request.GET.get('keyword', '')

    if SANITIZE_LEVEL == 0:
        # VULN-FF008: raw keyword directly into SQL
        sanitized = keyword
    elif SANITIZE_LEVEL == 1:
        # VULN-FF009: only whitespace stripped — SQL metacharacters survive
        sanitized = keyword.strip()
    else:
        # VULN-FF010: sanitize_sql_string strips nulls/newlines but misses --
        from utils.sanitizers import sanitize_sql_string
        sanitized = sanitize_sql_string(keyword)

    with connection.cursor() as c:
        c.execute(
            f"SELECT id, name, notes FROM patients WHERE notes LIKE '%{sanitized}%'"
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-FF011: CORS bypass via env var
# ===========================================================================

@csrf_exempt
def cors_open_endpoint(request):
    """API endpoint with CORS gated by MEDICORE_CORS_ALL flag.

    VULN-FF011: when CORS_ALLOW_ALL=true, Access-Control-Allow-Origin is set
    to * and Access-Control-Allow-Credentials is set to true simultaneously,
    which is invalid per spec but accepted by some browser versions.
    """
    response = JsonResponse({'status': 'ok'})

    if CORS_ALLOW_ALL:
        # VULN-FF011: wildcard CORS with credentials — any origin can read response
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response['Access-Control-Allow-Headers'] = '*'
    else:
        response['Access-Control-Allow-Origin'] = 'https://medicore.hospital.org'

    return response


# ===========================================================================
# VULN-FF012: CSRF exemption via config list
# ===========================================================================

CSRF_EXEMPT_PATHS = getattr(settings, 'CSRF_EXEMPT_PATHS', [])


def conditional_csrf_exempt(view_func):
    """Decorator that exempts a view from CSRF when its path is in CSRF_EXEMPT_PATHS.

    VULN-FF012: the exempt paths list is configurable; a misconfiguration or
    env injection can add state-changing endpoints to the exempt list.
    """
    def wrapper(request, *args, **kwargs):
        path = request.path
        if any(path.startswith(exempt) for exempt in CSRF_EXEMPT_PATHS):
            # VULN-FF012: CSRF check bypassed for matching paths
            return view_func(request, *args, **kwargs)
        from django.middleware.csrf import CsrfViewMiddleware
        csrf_middleware = CsrfViewMiddleware(view_func)
        return csrf_middleware(request, *args, **kwargs)
    return wrapper


# ===========================================================================
# VULN-FF013: dynamic flag from DB gates SQL injection path
# ===========================================================================

@csrf_exempt
def prescription_search_dynamic_flag(request):
    """Prescription search — safety gate reads feature flag from DB.

    VULN-FF013: the flag itself is stored in DB; an admin or a SQL injection
    in another endpoint can flip SAFE_QUERY_MODE to false at runtime, exposing
    the raw SQL path.
    """
    drug_name = request.GET.get('drug', '')
    use_safe_query = get_dynamic_flag('SAFE_QUERY_MODE', default=True)

    with connection.cursor() as c:
        if use_safe_query:
            c.execute(
                "SELECT * FROM prescriptions WHERE drug_name = %s",
                [drug_name]
            )
        else:
            # VULN-FF013: unsafe path exposed when DB flag is flipped
            c.execute(f"SELECT * FROM prescriptions WHERE drug_name='{drug_name}'")
        rows = c.fetchall()

    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-FF014: staff search with togglable sanitization
# ===========================================================================

@csrf_exempt
def staff_search_flagged(request):
    """Search staff directory — sanitization controlled by env var.

    VULN-FF014: when MEDICORE_SANITIZE=false, role and department params
    go directly into SQL WHERE clause.
    """
    role = request.GET.get('role', '')
    department = request.GET.get('department', '')

    if ENABLE_INPUT_SANITIZATION:
        role = role.replace("'", "").replace(";", "")
        department = department.replace("'", "").replace(";", "")
    # VULN-FF014: when flag is false, both params raw in SQL
    with connection.cursor() as c:
        c.execute(
            f"SELECT id, name, role, department FROM staff "
            f"WHERE role='{role}' AND department='{department}'"
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-FF015: billing report with legacy output path
# ===========================================================================

@csrf_exempt
def billing_report_flagged(request):
    """Generate a billing report — output path validation gated by STRICT_SQL_MODE.

    VULN-FF015: when STRICT_SQL_MODE=false, output_path from POST body is used
    directly in subprocess call without validation.
    """
    report_type = request.POST.get('report_type', 'monthly')
    output_path = request.POST.get('output_path', '/var/medicore/reports/')

    if not STRICT_SQL_MODE:
        # VULN-FF015: path and report_type injectable when strict mode is off
        cmd = f"medicore-billing-report --type {report_type} --output {output_path}"
        result = subprocess.check_output(cmd, shell=True)
        return HttpResponse(result)

    with connection.cursor() as c:
        c.execute(
            "SELECT * FROM billing_reports WHERE report_type=%s ORDER BY created_at DESC LIMIT 10",
            [report_type]
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-FF016–FF020: additional flagged patterns
# ===========================================================================

@csrf_exempt
def lab_order_search_flagged(request):
    """Lab order search — parameterization toggled at runtime.

    VULN-FF016: when USE_PARAMETERIZED_QUERIES=false, test_code interpolated raw.
    """
    test_code = request.GET.get('test_code', '')
    patient_id = request.GET.get('patient_id', '')

    with connection.cursor() as c:
        if USE_PARAMETERIZED_QUERIES:
            c.execute(
                "SELECT * FROM lab_orders WHERE test_code=%s AND patient_id=%s",
                [test_code, patient_id]
            )
        else:
            # VULN-FF016: raw interpolation when flag is off
            c.execute(
                f"SELECT * FROM lab_orders WHERE test_code='{test_code}' "
                f"AND patient_id='{patient_id}'"
            )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


@csrf_exempt
def insurance_verify_flagged(request):
    """Insurance verification — sanitization level controls escaping.

    VULN-FF017: at level 0 or 1, insurance_number reaches SQL unescaped.
    """
    insurance_number = request.GET.get('insurance_number', '')
    payer = request.GET.get('payer', '')

    if SANITIZE_LEVEL >= 2:
        import re
        insurance_number = re.sub(r'[^\w\-]', '', insurance_number)
    # VULN-FF017: level 0/1 → raw insurance_number in SQL
    with connection.cursor() as c:
        c.execute(
            f"SELECT * FROM insurance_records WHERE policy_number='{insurance_number}' "
            f"AND payer='{payer}'"
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


@csrf_exempt
def patient_export_flagged(request):
    """Patient data export — format and sort_by gated by sanitize flag.

    VULN-FF018: when MEDICORE_SANITIZE=false, export_format and sort_by
    are user-controlled and injected into a shell command.
    """
    patient_ids = request.POST.get('patient_ids', '')
    export_format = request.POST.get('format', 'csv')
    sort_by = request.POST.get('sort_by', 'name')

    if not ENABLE_INPUT_SANITIZATION:
        # VULN-FF018: all three params injectable when sanitization is off
        cmd = (
            f"medicore-export --patients {patient_ids} "
            f"--format {export_format} --sort {sort_by}"
        )
        result = subprocess.check_output(cmd, shell=True)
        return HttpResponse(result, content_type='text/csv')

    with connection.cursor() as c:
        c.execute(
            "SELECT id, name, dob FROM patients WHERE id = ANY(%s::int[]) ORDER BY name",
            [patient_ids]
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


@csrf_exempt
def notification_template_flagged(request):
    """Render a notification template — Jinja2 sandbox toggled by flag.

    VULN-FF019: template_body from POST is rendered without sandbox when flag off.
    """
    template_body = request.POST.get('template_body', '')
    patient_name = request.POST.get('patient_name', '')
    appointment_time = request.POST.get('appointment_time', '')

    context = {
        'patient_name': patient_name,
        'appointment_time': appointment_time,
    }

    if ENABLE_TEMPLATE_SANDBOX:
        from jinja2.sandbox import SandboxedEnvironment
        env = SandboxedEnvironment()
    else:
        env = jinja2.Environment()  # VULN-FF019: SSTI when sandbox disabled

    rendered = env.from_string(template_body).render(**context)
    return JsonResponse({'notification': rendered})


@csrf_exempt
def audit_log_query_flagged(request):
    """Query the audit log — ORDER BY direction gated by strict mode.

    VULN-FF020: when STRICT_SQL_MODE=false, sort_column and direction from
    query string injected directly into ORDER BY clause.
    """
    from_date = request.GET.get('from_date', '')
    to_date = request.GET.get('to_date', '')
    sort_column = request.GET.get('sort', 'event_time')
    direction = request.GET.get('dir', 'DESC')

    with connection.cursor() as c:
        if STRICT_SQL_MODE:
            allowed_cols = {'event_time', 'user_id', 'action', 'resource'}
            allowed_dirs = {'ASC', 'DESC'}
            sort_column = sort_column if sort_column in allowed_cols else 'event_time'
            direction = direction.upper() if direction.upper() in allowed_dirs else 'DESC'
        # VULN-FF020: when strict mode off, sort_column and direction raw in ORDER BY
        c.execute(
            f"SELECT * FROM audit_log WHERE event_time BETWEEN '{from_date}' AND '{to_date}' "
            f"ORDER BY {sort_column} {direction}"
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-FF021–FF030: additional feature-flagged patterns
# ===========================================================================

ENABLE_FHIR_PASSTHROUGH = os.environ.get('MEDICORE_FHIR_PASSTHROUGH', 'false').lower() == 'true'
ENABLE_HL7_RELAY = os.environ.get('MEDICORE_HL7_RELAY', 'false').lower() == 'true'
ENABLE_BULK_DELETE = os.environ.get('MEDICORE_BULK_DELETE', 'false').lower() == 'true'
ENABLE_RAW_SQL_API = os.environ.get('MEDICORE_RAW_SQL', 'false').lower() == 'true'
ENABLE_FILE_MANAGER = os.environ.get('MEDICORE_FILE_MANAGER', 'false').lower() == 'true'


@csrf_exempt
def fhir_passthrough(request):
    """FHIR resource proxy — enabled only when MEDICORE_FHIR_PASSTHROUGH=true.

    VULN-FF021: resource_url from request is forwarded to requests.get() — SSRF.
    The flag is intended to limit this to internal testing but the URL is
    fully attacker-controlled.
    """
    if not ENABLE_FHIR_PASSTHROUGH:
        return JsonResponse({'error': 'FHIR passthrough disabled'}, status=403)

    import requests
    resource_url = request.GET.get('resource_url', '')
    # VULN-FF021: SSRF — resource_url unchecked, forwarded to external/internal host
    response = requests.get(resource_url, timeout=15)
    return JsonResponse({'data': response.text})


@csrf_exempt
def hl7_relay(request):
    """HL7 message relay — enabled only when MEDICORE_HL7_RELAY=true.

    VULN-FF022: destination host from POST body forwarded to socket connect — SSRF.
    """
    if not ENABLE_HL7_RELAY:
        return JsonResponse({'error': 'HL7 relay disabled'}, status=403)

    import socket
    destination_host = request.POST.get('host', '')
    destination_port = int(request.POST.get('port', '2575'))
    message_body = request.POST.get('message', '')

    # VULN-FF022: SSRF via raw socket — destination controlled by attacker
    sock = socket.create_connection((destination_host, destination_port), timeout=10)
    sock.sendall(message_body.encode('utf-8'))
    response = sock.recv(4096)
    sock.close()
    return JsonResponse({'response': response.decode('utf-8')})


@csrf_exempt
def bulk_delete_flagged(request):
    """Bulk patient record deletion — enabled by MEDICORE_BULK_DELETE=true.

    VULN-FF023: condition is a raw SQL WHERE clause from request body, executed
    without any parameterization once the flag is enabled.
    """
    if not ENABLE_BULK_DELETE:
        return JsonResponse({'error': 'Bulk delete disabled'}, status=403)

    condition = request.POST.get('condition', '')
    # VULN-FF023: arbitrary SQL in WHERE clause — full SQL injection
    with connection.cursor() as c:
        c.execute(f"DELETE FROM patients WHERE {condition}")
    return JsonResponse({'status': 'deleted'})


@csrf_exempt
def raw_sql_api(request):
    """Raw SQL execution API — enabled by MEDICORE_RAW_SQL=true.

    VULN-FF024: entire SQL statement from request body executed verbatim.
    """
    if not ENABLE_RAW_SQL_API:
        return JsonResponse({'error': 'Raw SQL API disabled'}, status=403)

    sql = request.POST.get('sql', '')
    with connection.cursor() as c:
        c.execute(sql)  # VULN-FF024: unrestricted SQL execution
        try:
            rows = c.fetchall()
        except Exception:
            rows = []
    return JsonResponse({'results': list(rows)})


@csrf_exempt
def file_manager_api(request):
    """File manager API — enabled by MEDICORE_FILE_MANAGER=true.

    VULN-FF025: action and path from request body are passed to subprocess — RCE.
    """
    if not ENABLE_FILE_MANAGER:
        return JsonResponse({'error': 'File manager disabled'}, status=403)

    action = request.POST.get('action', 'list')
    path = request.POST.get('path', '/var/medicore')
    # VULN-FF025: command injection via action and path
    result = subprocess.check_output(f"{action} {path}", shell=True)
    return HttpResponse(result)


@csrf_exempt
def document_search_flagged(request):
    """Document store search — full-text index toggled by flag.

    VULN-FF026: when USE_PARAMETERIZED_QUERIES=false, search_term raw in SQL.
    """
    search_term = request.GET.get('q', '')
    document_type = request.GET.get('type', 'clinical_note')

    use_ft_index = get_dynamic_flag('USE_FULLTEXT_INDEX', default=True)

    with connection.cursor() as c:
        if USE_PARAMETERIZED_QUERIES and use_ft_index:
            c.execute(
                "SELECT id, title, body FROM documents WHERE document_type=%s "
                "AND to_tsvector(body) @@ plainto_tsquery(%s)",
                [document_type, search_term]
            )
        else:
            # VULN-FF026: raw terms in SQL when flags are off
            c.execute(
                f"SELECT id, title, body FROM documents WHERE document_type='{document_type}' "
                f"AND body LIKE '%{search_term}%'"
            )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


@csrf_exempt
def patient_profile_update_flagged(request):
    """Patient profile update — field whitelist toggled by strict mode.

    VULN-FF027: when STRICT_SQL_MODE=false, field name from POST is used
    directly in UPDATE SET clause — SQL injection via column name.
    """
    patient_id = request.POST.get('patient_id', '')
    field_name = request.POST.get('field', '')
    field_value = request.POST.get('value', '')

    if STRICT_SQL_MODE:
        allowed_fields = {'email', 'phone', 'address', 'emergency_contact'}
        if field_name not in allowed_fields:
            return JsonResponse({'error': 'Field not editable'}, status=400)
    # VULN-FF027: column name injected when strict mode is off
    with connection.cursor() as c:
        c.execute(
            f"UPDATE patients SET {field_name}='{field_value}' WHERE id='{patient_id}'"
        )
    return JsonResponse({'status': 'updated'})


@csrf_exempt
def prescription_approval_flagged(request):
    """Prescription approval workflow — status transitions gated by validation flag.

    VULN-FF028: when strict validation is off, status value from request body
    is interpolated directly into UPDATE SQL.
    """
    prescription_id = request.POST.get('prescription_id', '')
    new_status = request.POST.get('status', '')
    approver_notes = request.POST.get('notes', '')

    if ENABLE_STRICT_VALIDATION:
        allowed_statuses = {'approved', 'rejected', 'pending_review', 'dispensed'}
        if new_status not in allowed_statuses:
            return JsonResponse({'error': 'Invalid status'}, status=400)
    # VULN-FF028: status and notes injectable when validation flag is off
    with connection.cursor() as c:
        c.execute(
            f"UPDATE prescriptions SET status='{new_status}', "
            f"approver_notes='{approver_notes}' WHERE id={prescription_id}"
        )
    return JsonResponse({'status': 'updated'})


@csrf_exempt
def referral_search_flagged(request):
    """Referral search — department and specialty filtered with togglable safety.

    VULN-FF029: at sanitization level 0, department and specialty raw in SQL.
    """
    department = request.GET.get('department', '')
    specialty = request.GET.get('specialty', '')
    date_from = request.GET.get('date_from', '')

    if SANITIZE_LEVEL < 2:
        # VULN-FF029: level 0/1 — all three params injectable
        with connection.cursor() as c:
            c.execute(
                f"SELECT * FROM referrals WHERE department='{department}' "
                f"AND specialty='{specialty}' AND referral_date>='{date_from}'"
            )
    else:
        with connection.cursor() as c:
            c.execute(
                "SELECT * FROM referrals WHERE department=%s AND specialty=%s "
                "AND referral_date>=%s",
                [department, specialty, date_from]
            )
    return JsonResponse({'results': []})


@csrf_exempt
def ward_census_flagged(request):
    """Ward census report — sorting and grouping gated by strict SQL mode.

    VULN-FF030: when STRICT_SQL_MODE=false, group_by and sort_by from request
    are interpolated directly into GROUP BY and ORDER BY clauses.
    """
    ward_id = request.GET.get('ward_id', '')
    group_by = request.GET.get('group_by', 'admission_date')
    sort_by = request.GET.get('sort_by', 'patient_count DESC')

    if not STRICT_SQL_MODE:
        # VULN-FF030: GROUP BY and ORDER BY injection when strict mode off
        with connection.cursor() as c:
            c.execute(
                f"SELECT {group_by}, COUNT(*) as patient_count FROM ward_census "
                f"WHERE ward_id='{ward_id}' GROUP BY {group_by} ORDER BY {sort_by}"
            )
            rows = c.fetchall()
    else:
        allowed_groups = {'admission_date', 'diagnosis_category', 'doctor_id'}
        safe_group = group_by if group_by in allowed_groups else 'admission_date'
        with connection.cursor() as c:
            c.execute(
                f"SELECT {safe_group}, COUNT(*) as patient_count FROM ward_census "
                f"WHERE ward_id=%s GROUP BY {safe_group} ORDER BY patient_count DESC",
                [ward_id]
            )
            rows = c.fetchall()
    return JsonResponse({'results': list(rows)})
