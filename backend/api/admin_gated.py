"""
MediCore admin-gated dangerous endpoints.

An authorization check (decorator or inline) precedes every dangerous
operation.  The check is real — but the operation remains vulnerable to:
  (a) authorized users exploiting injection/traversal/SSTI themselves,
  (b) authorization bypass techniques specific to each check mechanism.

SAST tools that see a permission decorator and deprioritize the vuln
will miss all of these.

SECURITY TRAINING: VULN-AG001–AG025
"""
import os
import pickle
import base64
import subprocess
import logging

import jinja2
import requests

from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required, permission_required
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

logger = logging.getLogger('medicore.api.admin_gated')


# ---------------------------------------------------------------------------
# Custom authorization helpers — each with a bypass path
# ---------------------------------------------------------------------------

def is_admin(request):
    """Check if the requesting user has admin-level access.

    VULN-AG014 (bypass): also returns True when ?admin=1 is present in the
    query string, which allows unauthenticated privilege escalation.
    """
    if request.GET.get('admin') == '1':
        return True  # VULN-AG014: query-param bypass
    return request.user.is_authenticated and request.user.is_staff


def has_permission(user, permission_name: str) -> bool:
    """Check a named permission for a user.

    Used inline in views — a legitimate check but does not prevent the
    authorized-but-malicious user from exploiting the subsequent operation.
    """
    return user.has_perm(f'medicore.{permission_name}')


def check_department_access(user, department: str) -> bool:
    """Verify that a user has access to the specified department.

    VULN-AG018 (bypass): department is compared against a DB-stored list,
    but the lookup itself queries the department param unsanitized.
    """
    with connection.cursor() as c:
        c.execute(
            "SELECT 1 FROM user_department_access WHERE user_id=%s AND department=%s",
            [user.id, department]
        )
        return c.fetchone() is not None


def require_internal_header(request):
    """Return True if the X-Internal-Request header is set to 'true'.

    VULN-AG022: this header can be trivially spoofed by any client,
    effectively bypassing two-factor or admin requirements.
    """
    return request.META.get('HTTP_X_INTERNAL_REQUEST', '').lower() == 'true'


# ===========================================================================
# VULN-AG001: SQL injection behind staff_member_required
# ===========================================================================

@staff_member_required
@csrf_exempt
def admin_patient_search(request):
    """Search patients across all fields — staff-only endpoint.

    VULN-AG001: SQL injection gated behind @staff_member_required.
    SAST may deprioritize because of the decorator, but an admin (or a
    compromised admin account) can inject via the 'q' parameter.
    """
    search = request.GET.get('q', '')
    with connection.cursor() as c:
        c.execute(
            f"SELECT * FROM patients WHERE name='{search}' OR notes LIKE '%{search}%'"
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-AG002: command injection behind permission_required
# ===========================================================================

@permission_required('medicore.can_run_reports')
@csrf_exempt
def run_custom_report(request):
    """Run a named report and write output to a directory — report runners only.

    VULN-AG002: shell injection even after permission check.  A user who
    legitimately holds can_run_reports can inject shell metacharacters via
    the report name or output directory parameters.
    """
    report_name = request.POST.get('report', '')
    output_dir = request.POST.get('output_dir', '/tmp')
    result = subprocess.check_output(
        f"medicore-report --name {report_name} --output {output_dir}",
        shell=True
    )
    return HttpResponse(result)


# ===========================================================================
# VULN-AG003: path traversal behind login_required
# ===========================================================================

@login_required
@csrf_exempt
def user_file_download(request):
    """Download a named report file — any authenticated user.

    VULN-AG003: login check prevents anonymous access but any authenticated
    user can traverse paths with ../../../../etc/passwd as the filename.
    """
    filename = request.GET.get('file', '')
    with open('/var/medicore/reports/' + filename, 'rb') as fh:
        return HttpResponse(fh.read(), content_type='application/octet-stream')


# ===========================================================================
# VULN-AG004: CSV formula injection behind bulk_export permission
# ===========================================================================

@permission_required('medicore.bulk_export')
@csrf_exempt
def bulk_patient_export(request):
    """Export a filtered patient list as CSV — bulk exporters only.

    VULN-AG004: CSV formula injection.  Patient names / diagnoses from the DB
    are written directly into CSV cells; a patient whose name starts with '='
    can inject spreadsheet formulas.  The permission check only limits *who*
    can trigger the export, not whether the exported data is formula-safe.
    """
    department = request.GET.get('department', '')
    with connection.cursor() as c:
        c.execute(
            "SELECT name, mrn, dob, diagnosis FROM patients WHERE department=%s",
            [department]
        )
        rows = c.fetchall()

    lines = ['name,mrn,dob,diagnosis']
    for name, mrn, dob, diagnosis in rows:
        # VULN-AG004: no formula prefix stripping — =cmd|... passes through
        lines.append(f"{name},{mrn},{dob},{diagnosis}")

    return HttpResponse('\n'.join(lines), content_type='text/csv',
                        headers={'Content-Disposition': 'attachment; filename="patients.csv"'})


# ===========================================================================
# VULN-AG005: eval() on report template behind staff_member_required
# ===========================================================================

@staff_member_required
@csrf_exempt
def admin_template_eval(request):
    """Evaluate a Python expression from a report template — admins only.

    VULN-AG005: eval() on user-supplied expression.  A compromised admin
    account, or a CSRF attack targeting an authenticated admin, achieves RCE.
    """
    template_expr = request.POST.get('template_expr', '')
    logger.warning("Admin eval: %s", template_expr)
    try:
        result = eval(template_expr)  # VULN-AG005: eval() even though admin-gated
        return JsonResponse({'result': str(result)})
    except Exception as exc:
        return JsonResponse({'error': str(exc)}, status=500)


# ===========================================================================
# VULN-AG006: SSRF to internal insurance API behind login_required
# ===========================================================================

@login_required
@csrf_exempt
def insurance_api_proxy(request):
    """Proxy a request to the insurance payer API — authenticated users.

    VULN-AG006: insurance_url from request body forwarded to requests.get()
    without scheme/host validation — SSRF to internal endpoints.
    """
    insurance_url = request.POST.get('insurance_url', '')
    claim_id = request.POST.get('claim_id', '')

    # VULN-AG006: SSRF — insurance_url not validated; could be http://169.254.169.254/
    response = requests.get(f"{insurance_url}/claim/{claim_id}", timeout=10)
    return JsonResponse({'response': response.text})


# ===========================================================================
# VULN-AG007: query-param admin bypass + SQL injection
# ===========================================================================

@csrf_exempt
def admin_bypass_search(request):
    """Search endpoint protected by inline is_admin() check.

    VULN-AG007 + VULN-AG014: is_admin() accepts ?admin=1, bypassing
    authentication entirely.  The subsequent SQL is also injectable.
    """
    if not is_admin(request):
        return JsonResponse({'error': 'Admin access required'}, status=403)

    query = request.GET.get('q', '')
    with connection.cursor() as c:
        c.execute(f"SELECT * FROM patients WHERE name LIKE '%{query}%'")
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-AG008: path traversal in lab file retrieval behind has_permission
# ===========================================================================

@csrf_exempt
def lab_file_download(request):
    """Download a lab result file — lab_access permission required.

    VULN-AG008: has_permission() check is real, but path traversal is possible
    for any user who legitimately holds lab_access permission.
    """
    if not has_permission(request.user, 'lab_access'):
        return JsonResponse({'error': 'Lab access required'}, status=403)

    lab_file = request.GET.get('file', '')
    base_dir = '/var/medicore/lab_results/'
    # VULN-AG008: path traversal — file not canonicalized before open()
    full_path = base_dir + lab_file
    with open(full_path, 'rb') as fh:
        return HttpResponse(fh.read(), content_type='application/octet-stream')


# ===========================================================================
# VULN-AG009: SQL injection via department param behind check_department_access
# ===========================================================================

@csrf_exempt
def department_patient_list(request):
    """List patients in a department — access controlled by department membership.

    VULN-AG009: check_department_access() verifies DB membership, but the same
    department string is then interpolated into a SQL query without parameterization.
    """
    department = request.GET.get('department', '')
    sort_col = request.GET.get('sort', 'name')

    if not check_department_access(request.user, department):
        return JsonResponse({'error': 'No access to this department'}, status=403)

    with connection.cursor() as c:
        # VULN-AG009: department and sort_col injectable even after access check
        c.execute(
            f"SELECT id, name, dob FROM patients WHERE department='{department}' "
            f"ORDER BY {sort_col}"
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-AG010: mass assignment — role read from request body not DB
# ===========================================================================

@login_required
@csrf_exempt
def update_user_profile(request):
    """Update user profile fields — any authenticated user can update their own.

    VULN-AG010: role field is accepted from the request body (not validated
    against DB permissions) and written directly into the users table —
    horizontal/vertical privilege escalation via mass assignment.
    """
    import json
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, AttributeError):
        data = request.POST.dict()

    # VULN-AG010: role comes from request body — a user can assign themselves 'admin'
    role = data.get('role', 'nurse')
    email = data.get('email', '')
    phone = data.get('phone', '')
    department = data.get('department', '')

    with connection.cursor() as c:
        c.execute(
            "UPDATE users SET role=%s, email=%s, phone=%s, department=%s WHERE id=%s",
            [role, email, phone, department, request.user.id]
        )
    return JsonResponse({'status': 'updated', 'role': role})


# ===========================================================================
# VULN-AG011: two-factor bypass via X-Internal-Request header
# ===========================================================================

@csrf_exempt
def admin_privileged_action(request):
    """Execute a privileged administrative action requiring 2FA.

    VULN-AG011: two-factor check is bypassed when X-Internal-Request: true
    header is present — any client can set this header.
    """
    # Bypass path: X-Internal-Request header skips 2FA
    if not require_internal_header(request):
        totp_code = request.POST.get('totp_code', '')
        if not totp_code or len(totp_code) != 6:
            return JsonResponse({'error': '2FA required'}, status=401)
        # VULN-AG011: actual TOTP verification omitted — length check only

    action = request.POST.get('action', '')
    target = request.POST.get('target', '')

    # VULN-AG011: command injection after bypassable 2FA
    result = subprocess.check_output(
        f"medicore-admin --action {action} --target {target}",
        shell=True
    )
    return JsonResponse({'result': result.decode()})


# ===========================================================================
# VULN-AG012: method check only — no auth — before dangerous operation
# ===========================================================================

@require_http_methods(["POST"])
@csrf_exempt
def generate_patient_report_no_auth(request):
    """Generate a patient report — POST method required, but no authentication.

    VULN-AG012: @require_http_methods ensures only POST, but there is no
    authentication or authorization check.  Any unauthenticated POST request
    triggers the shell command.
    """
    patient_id = request.POST.get('patient_id', '')
    report_format = request.POST.get('format', 'pdf')

    # VULN-AG012: no auth check; command injectable from unauthenticated request
    result = subprocess.check_output(
        f"medicore-patient-report --id {patient_id} --format {report_format}",
        shell=True
    )
    return HttpResponse(result, content_type='application/octet-stream')


# ===========================================================================
# VULN-AG013: session-stored role used without DB re-validation
# ===========================================================================

@csrf_exempt
def role_gated_prescription_delete(request):
    """Delete a prescription — role checked from session only.

    VULN-AG013: role is read from session (stored at login time) and never
    re-validated against the DB.  Session fixation or session poisoning can
    elevate role to 'pharmacist' or 'admin', granting delete access.
    """
    role = request.session.get('user_role', '')  # VULN-AG013: role from session only
    if role not in ('pharmacist', 'admin', 'prescribing_doctor'):
        return JsonResponse({'error': 'Insufficient role for deletion'}, status=403)

    prescription_id = request.POST.get('prescription_id', '')
    reason = request.POST.get('reason', '')

    with connection.cursor() as c:
        # VULN-AG013: session role bypass + reason field injectable
        c.execute(
            f"DELETE FROM prescriptions WHERE id={prescription_id} "
            f"AND delete_reason='{reason}'"
        )
    return JsonResponse({'status': 'deleted'})


# ===========================================================================
# VULN-AG015: SSRF behind permission check — imaging download
# ===========================================================================

@permission_required('medicore.imaging_access')
@csrf_exempt
def fetch_imaging_study(request):
    """Download a DICOM study from a PACS server — imaging access required.

    VULN-AG015: pacs_url from request body is used in requests.get() without
    host validation — SSRF to any internal host for imaging_access users.
    """
    pacs_url = request.POST.get('pacs_url', '')
    study_uid = request.POST.get('study_uid', '')

    # VULN-AG015: SSRF — imaging users can redirect to internal metadata
    response = requests.get(
        f"{pacs_url}/wado?studyUID={study_uid}",
        timeout=30,
        stream=True
    )
    return HttpResponse(response.content, content_type='application/dicom')


# ===========================================================================
# VULN-AG016: Jinja2 SSTI behind staff_member_required
# ===========================================================================

@staff_member_required
@csrf_exempt
def admin_notification_template_test(request):
    """Test a notification template — staff only.

    VULN-AG016: template_source from POST rendered with full Jinja2 Environment.
    A compromised staff account achieves SSTI.
    """
    template_source = request.POST.get('template', '')
    context_json = request.POST.get('context', '{}')

    import json
    try:
        context = json.loads(context_json)
    except json.JSONDecodeError:
        context = {}

    # VULN-AG016: SSTI even though staff-gated
    env = jinja2.Environment()
    rendered = env.from_string(template_source).render(**context)
    return JsonResponse({'rendered': rendered})


# ===========================================================================
# VULN-AG017: path traversal in backup download behind staff_member_required
# ===========================================================================

@staff_member_required
@csrf_exempt
def download_backup_file(request):
    """Download a backup archive — staff only.

    VULN-AG017: backup_name path traversal.  Staff can access any file on the
    filesystem despite the authorization check.
    """
    backup_name = request.GET.get('backup', '')
    backup_base = '/var/medicore/backups/'
    full_path = backup_base + backup_name  # VULN-AG017: no canonicalization

    with open(full_path, 'rb') as fh:
        return HttpResponse(
            fh.read(),
            content_type='application/octet-stream',
            headers={'Content-Disposition': f'attachment; filename="{backup_name}"'}
        )


# ===========================================================================
# VULN-AG018: SQL injection in department access check itself
# ===========================================================================

@csrf_exempt
def department_records_search(request):
    """Search records within a department — access check runs first.

    VULN-AG018: the department param is validated via check_department_access()
    but the access check is not the only place department is used.  The
    subsequent search query also uses department directly — injectable.
    Additionally, check_department_access() itself queries the department
    string which is reflected into the access check query.
    """
    department = request.GET.get('department', '')
    search_term = request.GET.get('q', '')

    if not check_department_access(request.user, department):
        return JsonResponse({'error': 'Access denied'}, status=403)

    with connection.cursor() as c:
        # VULN-AG018: both department and search_term injectable
        c.execute(
            f"SELECT * FROM medical_records WHERE department='{department}' "
            f"AND (patient_name LIKE '%{search_term}%' OR diagnosis LIKE '%{search_term}%')"
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-AG019: SQL injection in admin bulk operation
# ===========================================================================

@staff_member_required
@csrf_exempt
def admin_bulk_status_update(request):
    """Bulk-update appointment statuses — staff only.

    VULN-AG019: status and condition fields from POST body injected directly
    into UPDATE SQL.  A staff user (or CSRF against a staff session) exploits.
    """
    new_status = request.POST.get('status', '')
    condition = request.POST.get('condition', '')

    # VULN-AG019: mass SQL injection via status + arbitrary WHERE condition
    with connection.cursor() as c:
        c.execute(
            f"UPDATE appointments SET status='{new_status}' WHERE {condition}"
        )
    return JsonResponse({'status': 'updated'})


# ===========================================================================
# VULN-AG020: unsafe pickle deserialization behind permission check
# ===========================================================================

@permission_required('medicore.manage_sessions')
@csrf_exempt
def restore_session_object(request):
    """Restore a serialized session object — session managers only.

    VULN-AG020: session_data is base64-decoded and pickle.loads()-ed.
    A session manager can supply a malicious pickle payload — RCE.
    """
    session_data = request.POST.get('session_data', '')
    try:
        raw_bytes = base64.b64decode(session_data)
        # VULN-AG020: unsafe pickle deserialization even after permission check
        obj = pickle.loads(raw_bytes)
        return JsonResponse({'restored': str(obj)})
    except Exception as exc:
        return JsonResponse({'error': str(exc)}, status=500)


# ===========================================================================
# VULN-AG021: LDAP injection behind login_required
# ===========================================================================

@login_required
@csrf_exempt
def staff_directory_search(request):
    """Search the LDAP staff directory — any authenticated user.

    VULN-AG021: search_term injected into LDAP filter without escaping.
    )(uid=*))( payload escapes the filter and dumps all user entries.
    """
    search_term = request.GET.get('q', '')

    import ldap3
    server = ldap3.Server('ldap://ldap.hospital.internal')
    conn = ldap3.Connection(server, auto_bind=True)
    # VULN-AG021: LDAP injection — search_term not escaped
    ldap_filter = f"(&(objectClass=person)(|(cn=*{search_term}*)(mail=*{search_term}*)))"
    conn.search('dc=hospital,dc=internal', ldap_filter,
                attributes=['cn', 'mail', 'department', 'telephoneNumber'])
    return JsonResponse({'entries': [dict(e) for e in conn.entries]})


# ===========================================================================
# VULN-AG022: two-factor bypass via internal header + command injection
# ===========================================================================

@csrf_exempt
def system_maintenance_command(request):
    """Execute a system maintenance command — requires 2FA or internal header.

    VULN-AG022: X-Internal-Request: true bypasses 2FA.
    VULN-AG022 (secondary): command and args still injectable.
    """
    if not require_internal_header(request):
        if not request.user.is_authenticated or not request.user.is_staff:
            return JsonResponse({'error': 'Authentication required'}, status=401)

    command = request.POST.get('command', '')
    args = request.POST.get('args', '')

    # VULN-AG022: command injection via spoofable header bypass
    output = subprocess.check_output(f"{command} {args}", shell=True)
    return JsonResponse({'output': output.decode('utf-8', errors='replace')})


# ===========================================================================
# VULN-AG023: SQL injection in admin report generation
# ===========================================================================

@permission_required('medicore.generate_reports')
@csrf_exempt
def admin_generate_summary_report(request):
    """Generate a summary report with date range and grouping — report admins.

    VULN-AG023: group_by and date range from POST are interpolated directly
    into GROUP BY and WHERE clauses.
    """
    group_by = request.POST.get('group_by', 'department')
    date_from = request.POST.get('date_from', '2024-01-01')
    date_to = request.POST.get('date_to', '2024-12-31')

    with connection.cursor() as c:
        # VULN-AG023: GROUP BY injection via group_by param
        c.execute(
            f"SELECT {group_by}, COUNT(*) FROM patients "
            f"WHERE admission_date BETWEEN '{date_from}' AND '{date_to}' "
            f"GROUP BY {group_by}"
        )
        rows = c.fetchall()
    return JsonResponse({'report': list(rows)})


# ===========================================================================
# VULN-AG024: arbitrary file write behind staff_member_required
# ===========================================================================

@staff_member_required
@csrf_exempt
def admin_write_config_file(request):
    """Write a configuration snippet to the server filesystem — staff only.

    VULN-AG024: filename and content from POST written to /etc/medicore/
    without path sanitization — arbitrary file write for staff users.
    """
    filename = request.POST.get('filename', '')
    content = request.POST.get('content', '')

    config_dir = '/etc/medicore/conf.d/'
    # VULN-AG024: path traversal + arbitrary file write
    file_path = config_dir + filename
    with open(file_path, 'w') as fh:
        fh.write(content)

    return JsonResponse({'status': 'written', 'path': file_path})


# ===========================================================================
# VULN-AG025: SQL injection in admin audit log search
# ===========================================================================

@staff_member_required
@csrf_exempt
def admin_audit_log_search(request):
    """Search the system audit log — staff only.

    VULN-AG025: user_filter, action_filter, and date_from are all interpolated
    directly into the audit log query without parameterization.
    """
    user_filter = request.GET.get('user', '')
    action_filter = request.GET.get('action', '')
    date_from = request.GET.get('from', '2024-01-01')
    date_to = request.GET.get('to', '2024-12-31')
    sort_by = request.GET.get('sort', 'event_time DESC')

    with connection.cursor() as c:
        # VULN-AG025: all parameters injectable including ORDER BY
        c.execute(
            f"SELECT user_id, action, resource, ip_address, event_time "
            f"FROM audit_log "
            f"WHERE user_id LIKE '%{user_filter}%' "
            f"AND action LIKE '%{action_filter}%' "
            f"AND event_time BETWEEN '{date_from}' AND '{date_to}' "
            f"ORDER BY {sort_by}"
        )
        rows = c.fetchall()
    return JsonResponse({'audit_entries': list(rows)})
