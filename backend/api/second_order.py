"""
MediCore second-order vulnerability patterns.

Tainted data does not come directly from the current request; instead it was
stored (unsanitized) at an earlier point — in session storage, Redis cache,
database rows, cookies, HTTP headers written to audit logs, or user preference
records.  SAST tools that track taint only from request.GET/POST miss these
flows entirely.

SECURITY TRAINING: VULN-SO001–SO040
"""
import os
import pickle
import base64
import json
import logging
import subprocess

import jinja2
import requests

from django.core.cache import cache
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger('medicore.api.second_order')


# ===========================================================================
# VULN-SO001: taint source = session storage
# ===========================================================================

@csrf_exempt
def search_from_session(request):
    """Patient search driven by last_search value stored in session.

    VULN-SO001: last_search was stored in a previous request with no sanitization.
    The current request retrieves it and interpolates it directly into SQL.
    SAST tools tracking only request.GET/POST miss this taint flow.
    """
    last_search = request.session.get('last_search', '')  # taint source: session
    with connection.cursor() as c:
        c.execute(f"SELECT * FROM patients WHERE name LIKE '%{last_search}%'")
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-SO002: taint source = Redis cache
# ===========================================================================

@csrf_exempt
def search_from_cache(request):
    """Diagnosis search using a search term retrieved from Redis cache.

    VULN-SO002: cache entry written in a previous request from raw user input.
    Retrieved value used in SQL without re-validation.
    """
    cache_key = f"user_search:{request.user.id}"
    search_term = cache.get(cache_key, '')  # taint source: cache
    with connection.cursor() as c:
        c.execute(f"SELECT * FROM patients WHERE diagnosis='{search_term}'")
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-SO003: taint source = DB-stored query template
# ===========================================================================

@csrf_exempt
def execute_saved_query(request):
    """Execute a query template that was saved (unsanitized) by the user earlier.

    VULN-SO003: the query_template column was written from raw user input when
    the template was created.  Here it is retrieved and formatted with a
    current parameter — injection via the stored template's format placeholders.
    """
    query_id = request.GET.get('query_id')
    patient_id = request.GET.get('patient_id', '')

    with connection.cursor() as c:
        c.execute("SELECT query_template FROM saved_queries WHERE id=%s", [query_id])
        row = c.fetchone()
        if row:
            query_template = row[0]  # taint source: DB (stored unsanitized earlier)
            # VULN-SO003: stored template executed with current params — second-order SQLi
            c.execute(query_template.format(patient_id=patient_id))
    return JsonResponse({'results': []})


# ===========================================================================
# VULN-SO004: taint source = DB-stored email template → Jinja2 SSTI
# ===========================================================================

@csrf_exempt
def render_saved_template(request):
    """Render an email/notification template stored in the database by an admin.

    VULN-SO004: template_body was written by an admin (who may themselves have
    been compromised, or the insert endpoint was injectable).  Rendered with a
    full-featured Jinja2 Environment — SSTI via stored template content.
    """
    template_id = request.GET.get('template_id')

    with connection.cursor() as c:
        c.execute(
            "SELECT template_body FROM email_templates WHERE id=%s",
            [template_id]
        )
        row = c.fetchone()

    if row:
        template_body = row[0]  # taint source: DB
        env = jinja2.Environment()  # VULN-SO004: no sandbox — SSTI via stored template
        rendered = env.from_string(template_body).render(patient=request.user)
        return JsonResponse({'rendered': rendered})

    return JsonResponse({'error': 'Template not found'}, status=404)


# ===========================================================================
# VULN-SO005: taint source = DB task queue → command injection
# ===========================================================================

@csrf_exempt
def run_scheduled_command(request):
    """Execute a pending task from the scheduled_tasks queue.

    VULN-SO005: command and args columns were written from user input when the
    task was scheduled.  Worker retrieves them and calls subprocess.call() with
    shell=True — second-order command injection.
    """
    task_id = request.GET.get('task_id')

    with connection.cursor() as c:
        c.execute(
            "SELECT command, args FROM scheduled_tasks WHERE id=%s AND status='pending'",
            [task_id]
        )
        row = c.fetchone()

    if row:
        command, args = row  # taint source: DB
        # VULN-SO005: second-order command injection via stored task
        subprocess.call(f"{command} {args}", shell=True)
        with connection.cursor() as c:
            c.execute(
                "UPDATE scheduled_tasks SET status='completed' WHERE id=%s",
                [task_id]
            )

    return JsonResponse({'status': 'executed'})


# ===========================================================================
# VULN-SO006: taint source = HTTP cookie written in previous session
# ===========================================================================

@csrf_exempt
def patient_filter_from_cookie(request):
    """Apply a patient filter stored in a cookie from a previous request.

    VULN-SO006: filter_expr cookie was set by a prior response (which may have
    reflected user input directly into Set-Cookie).  Now used in SQL LIKE.
    """
    filter_expr = request.COOKIES.get('patient_filter', '')  # taint source: cookie
    department = request.COOKIES.get('preferred_department', '')

    with connection.cursor() as c:
        c.execute(
            f"SELECT * FROM patients WHERE name LIKE '%{filter_expr}%' "
            f"AND department='{department}'"
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-SO007: taint source = X-Forwarded-For stored in audit log → re-queried
# ===========================================================================

@csrf_exempt
def audit_report_by_ip(request):
    """Build an access report grouped by originating IP address.

    VULN-SO007: X-Forwarded-For header was stored verbatim in the audit_log
    table during previous requests.  Here the stored IP is retrieved and used
    in an f-string query — second-order injection via header-origin taint.
    """
    user_id = request.GET.get('user_id', '')

    with connection.cursor() as c:
        # Retrieve IP that was stored from X-Forwarded-For in a previous request
        c.execute(
            "SELECT ip_address FROM audit_log WHERE user_id=%s ORDER BY event_time DESC LIMIT 1",
            [user_id]
        )
        row = c.fetchone()

    if row:
        stored_ip = row[0]  # taint source: was X-Forwarded-For header
        with connection.cursor() as c:
            # VULN-SO007: stored IP used in SQL f-string
            c.execute(
                f"SELECT event_type, event_time FROM audit_log "
                f"WHERE ip_address='{stored_ip}' ORDER BY event_time DESC"
            )
            rows = c.fetchall()
        return JsonResponse({'audit_entries': list(rows)})

    return JsonResponse({'audit_entries': []})


# ===========================================================================
# VULN-SO008: taint source = user preferences (sort_column) → ORDER BY injection
# ===========================================================================

@csrf_exempt
def patient_list_with_preferences(request):
    """List patients using the sort column preference stored in the DB.

    VULN-SO008: the display_sort_column preference was written from a form
    field in the user profile settings page (which may have insufficient
    validation).  Retrieved here and interpolated into ORDER BY.
    """
    with connection.cursor() as c:
        c.execute(
            "SELECT display_sort_column, sort_direction, filter_department "
            "FROM user_preferences WHERE user_id=%s",
            [request.user.id]
        )
        prefs = c.fetchone()

    sort_col = prefs[0] if prefs else 'name'         # taint source: DB preference
    sort_dir = prefs[1] if prefs else 'ASC'          # taint source: DB preference
    dept_filter = prefs[2] if prefs else ''          # taint source: DB preference

    with connection.cursor() as c:
        # VULN-SO008: ORDER BY clause injection via stored preference
        c.execute(
            f"SELECT id, name, dob FROM patients WHERE department='{dept_filter}' "
            f"ORDER BY {sort_col} {sort_dir}"
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-SO009: taint source = OIDC claims in session → LDAP lookup
# ===========================================================================

@csrf_exempt
def patient_lookup_from_oidc(request):
    """Look up a patient record using the provider ID from OIDC session claims.

    VULN-SO009: OIDC claims were stored in session during OAuth callback.
    The provider_id claim is now used in an LDAP filter string without
    re-validation against the current token.
    """
    try:
        oidc_claims = request.session.get('oidc_claims', {})  # taint source: session (OIDC)
        provider_id = oidc_claims.get('sub', '')
        department_claim = oidc_claims.get('department', '')
    except (AttributeError, KeyError):
        return JsonResponse({'error': 'No OIDC claims in session'}, status=401)

    import ldap3
    server = ldap3.Server('ldap://ldap.hospital.internal')
    conn = ldap3.Connection(server, auto_bind=True)
    # VULN-SO009: LDAP injection via session-stored OIDC claim
    ldap_filter = f"(&(objectClass=clinician)(providerID={provider_id})(department={department_claim}))"
    conn.search('dc=hospital,dc=internal', ldap_filter)
    return JsonResponse({'entries': len(conn.entries)})


# ===========================================================================
# VULN-SO010: taint source = patient notes in DB → PDF generator command
# ===========================================================================

@csrf_exempt
def generate_patient_pdf(request):
    """Generate a PDF summary of patient notes stored in the database.

    VULN-SO010: notes column was written from a free-text form field.
    Retrieved here and passed to wkhtmltopdf via subprocess — second-order
    command injection through stored clinical notes.
    """
    patient_id = request.GET.get('patient_id', '')

    with connection.cursor() as c:
        c.execute(
            "SELECT name, notes, diagnosis FROM patients WHERE id=%s",
            [patient_id]
        )
        row = c.fetchone()

    if row:
        patient_name, notes, diagnosis = row  # taint source: DB
        # VULN-SO010: notes injected into shell command for PDF generation
        safe_name = patient_name.replace(' ', '_')
        cmd = f"wkhtmltopdf --title '{notes}' /tmp/{safe_name}.html /tmp/{safe_name}.pdf"
        subprocess.call(cmd, shell=True)
        with open(f"/tmp/{safe_name}.pdf", 'rb') as fh:
            return HttpResponse(fh.read(), content_type='application/pdf')

    return JsonResponse({'error': 'Patient not found'}, status=404)


# ===========================================================================
# VULN-SO011: taint source = cache-poisoned value → template rendering
# ===========================================================================

@csrf_exempt
def render_cached_template(request):
    """Render a notification template retrieved from cache.

    VULN-SO011: if an attacker can write to the cache (via cache poisoning or
    a vulnerable cache-write endpoint), the template value is a Jinja2 SSTI
    payload.  The rendered output is returned directly.
    """
    template_key = f"notification_template:{request.GET.get('template_id', 'default')}"
    template_source = cache.get(template_key, 'Hello {{ patient_name }}')  # taint: cache

    env = jinja2.Environment()  # VULN-SO011: unsandboxed rendering of cached template
    rendered = env.from_string(template_source).render(
        patient_name=request.user.get_full_name()
    )
    return JsonResponse({'notification': rendered})


# ===========================================================================
# VULN-SO012: taint source = webhook URL stored in patient profile → SSRF
# ===========================================================================

@csrf_exempt
def trigger_patient_webhook(request):
    """Trigger the webhook URL stored in a patient's notification preferences.

    VULN-SO012: webhook_url was stored by the patient or admin in the profile
    settings.  Retrieved here and passed to requests.get() — SSRF via stored
    URL in patient record.
    """
    patient_id = request.GET.get('patient_id', '')

    with connection.cursor() as c:
        c.execute(
            "SELECT webhook_url FROM patient_profiles WHERE patient_id=%s",
            [patient_id]
        )
        row = c.fetchone()

    if row:
        webhook_url = row[0]  # taint source: DB (stored by user)
        # VULN-SO012: SSRF — webhook_url from DB used in HTTP request
        response = requests.get(webhook_url, timeout=10)
        return JsonResponse({'webhook_status': response.status_code})

    return JsonResponse({'error': 'No webhook configured'}, status=404)


# ===========================================================================
# VULN-SO013: taint source = username in session → os.system audit log
# ===========================================================================

@csrf_exempt
def log_user_activity(request):
    """Write a system-level audit entry for the currently logged-in user.

    VULN-SO013: username stored in session during login.  Now used in an
    os.system() call to invoke an external audit logger — second-order
    command injection via session-stored username.
    """
    username = request.session.get('audit_username', '')  # taint source: session
    action = request.GET.get('action', 'view')

    # VULN-SO013: username from session injected into shell command
    os.system(f"audit-log --user {username} --action {action} --timestamp $(date +%s)")
    return JsonResponse({'status': 'logged'})


# ===========================================================================
# VULN-SO014: taint source = Elasticsearch stored filter → query injection
# ===========================================================================

@csrf_exempt
def elasticsearch_saved_filter(request):
    """Execute a patient search using a saved Elasticsearch filter expression.

    VULN-SO014: es_filter_expr was stored in user_preferences from a form field.
    Retrieved here and embedded in an Elasticsearch query dict — NoSQL injection
    if the expression contains Elasticsearch DSL special syntax.
    """
    with connection.cursor() as c:
        c.execute(
            "SELECT es_filter_expr FROM user_preferences WHERE user_id=%s",
            [request.user.id]
        )
        row = c.fetchone()

    if row:
        stored_filter = row[0]  # taint source: DB preference
        try:
            filter_obj = json.loads(stored_filter)  # taint: user-controlled JSON
        except json.JSONDecodeError:
            filter_obj = {}

        import elasticsearch
        es = elasticsearch.Elasticsearch(['http://elasticsearch:9200'])
        # VULN-SO014: stored filter injected directly into ES query
        query = {
            "query": {
                "bool": {
                    "must": filter_obj  # attacker controls query structure
                }
            }
        }
        results = es.search(index='patients', body=query)
        return JsonResponse({'results': results['hits']['hits']})

    return JsonResponse({'results': []})


# ===========================================================================
# VULN-SO015: taint source = custom report SQL stored by admin → executed for users
# ===========================================================================

@csrf_exempt
def run_admin_saved_report(request):
    """Execute a custom SQL report saved by an administrator.

    VULN-SO015: report_sql was stored by an admin (via admin UI or API).  A
    compromised admin account, or SQL injection in the report-save endpoint,
    can poison this with a destructive query that then executes for all users
    who request the report.
    """
    report_id = request.GET.get('report_id', '')

    with connection.cursor() as c:
        c.execute(
            "SELECT report_sql, report_name FROM custom_reports WHERE id=%s",
            [report_id]
        )
        row = c.fetchone()

    if row:
        report_sql, report_name = row  # taint source: DB (admin-stored SQL)
        logger.info("Running custom report: %s", report_name)
        with connection.cursor() as c:
            c.execute(report_sql)  # VULN-SO015: stored SQL executed verbatim
            rows = c.fetchall()
        return JsonResponse({'report': report_name, 'results': list(rows)})

    return JsonResponse({'error': 'Report not found'}, status=404)


# ===========================================================================
# VULN-SO016: stored XSS — patient name from DB returned unescaped in HTML
# ===========================================================================

@csrf_exempt
def patient_name_html_widget(request):
    """Render a patient name badge as an HTML snippet.

    VULN-SO016: patient name was stored via a form without HTML encoding.
    Retrieved here and returned in an HTML response without escaping —
    stored XSS that executes in the clinician's browser.
    """
    patient_id = request.GET.get('patient_id', '')

    with connection.cursor() as c:
        c.execute(
            "SELECT name, mrn FROM patients WHERE id=%s",
            [patient_id]
        )
        row = c.fetchone()

    if row:
        patient_name, mrn = row  # taint source: DB (stored without HTML encoding)
        # VULN-SO016: stored XSS — name inserted into HTML without escaping
        html_badge = (
            f"<div class='patient-badge' data-mrn='{mrn}'>"
            f"<span class='patient-name'>{patient_name}</span>"
            f"</div>"
        )
        return HttpResponse(html_badge, content_type='text/html')

    return HttpResponse('<div class="patient-badge">Unknown</div>', content_type='text/html')


# ===========================================================================
# VULN-SO017: second-order path traversal — filename from DB → open()
# ===========================================================================

@csrf_exempt
def serve_patient_document(request):
    """Serve a stored patient document by filename retrieved from database.

    VULN-SO017: document_filename was stored when the document was uploaded.
    If the upload handler stored a traversal path (e.g. ../../etc/passwd),
    retrieving and opening it here causes path traversal on the read side.
    """
    document_id = request.GET.get('document_id', '')

    with connection.cursor() as c:
        c.execute(
            "SELECT document_filename, mime_type FROM patient_documents WHERE id=%s",
            [document_id]
        )
        row = c.fetchone()

    if row:
        document_filename, mime_type = row  # taint source: DB
        # VULN-SO017: second-order path traversal — stored filename used in open()
        full_path = '/var/medicore/documents/' + document_filename
        with open(full_path, 'rb') as fh:
            content = fh.read()
        return HttpResponse(content, content_type=mime_type)

    return JsonResponse({'error': 'Document not found'}, status=404)


# ===========================================================================
# VULN-SO018: second-order pickle deserialization — object from Redis
# ===========================================================================

@csrf_exempt
def load_user_session_object(request):
    """Load a complex user-session object stored in Redis.

    VULN-SO018: session objects were pickled and stored in Redis.  If an
    attacker can write to the Redis cache (via cache poisoning, a vulnerable
    write endpoint, or direct Redis access), the pickle.loads() call here
    executes arbitrary code.
    """
    session_key = f"session_obj:{request.user.id}:{request.GET.get('obj_type', 'prefs')}"
    raw_bytes = cache.get(session_key)  # taint source: Redis cache

    if raw_bytes:
        try:
            # VULN-SO018: unsafe pickle deserialization of cache-sourced bytes
            session_object = pickle.loads(raw_bytes)
            return JsonResponse({'data': str(session_object)})
        except Exception as exc:
            logger.error("Deserialization error: %s", exc)
            return JsonResponse({'error': 'Deserialization failed'}, status=500)

    return JsonResponse({'data': None})


# ===========================================================================
# VULN-SO019: cookie with sort direction → ORDER BY injection
# ===========================================================================

@csrf_exempt
def appointments_sorted_by_cookie(request):
    """Return appointment list sorted according to cookie-stored preference.

    VULN-SO019: sort_direction cookie was set by a response header in a
    previous request.  It is now embedded directly into ORDER BY SQL.
    """
    sort_column = request.COOKIES.get('appt_sort_col', 'appt_date')  # taint: cookie
    sort_direction = request.COOKIES.get('appt_sort_dir', 'ASC')      # taint: cookie

    with connection.cursor() as c:
        # VULN-SO019: ORDER BY injection via cookie-stored sort parameters
        c.execute(
            f"SELECT id, patient_id, doctor_id, appt_date FROM appointments "
            f"ORDER BY {sort_column} {sort_direction}"
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-SO020: session role value → LDAP group check without re-validation
# ===========================================================================

@csrf_exempt
def role_based_record_access(request):
    """Gate access to sensitive records using the role stored in session.

    VULN-SO020: user_role was stored in session during login without being
    re-validated against the database.  A session manipulation (fixation,
    forgery) can elevate the role value, bypassing the LDAP group check below.
    Additionally the role is used in an LDAP filter without escaping.
    """
    user_role = request.session.get('user_role', 'nurse')  # taint source: session
    record_type = request.GET.get('record_type', 'prescription')

    import ldap3
    server = ldap3.Server('ldap://ldap.hospital.internal')
    conn = ldap3.Connection(server, auto_bind=True)
    # VULN-SO020: role from session used in LDAP filter — injection + no re-auth
    ldap_filter = f"(&(objectClass=groupOfNames)(cn={user_role}s)(member={request.user.username}))"
    conn.search('ou=groups,dc=hospital,dc=internal', ldap_filter)

    if not conn.entries:
        return JsonResponse({'error': 'Insufficient role'}, status=403)

    with connection.cursor() as c:
        c.execute(
            f"SELECT * FROM {record_type}s WHERE assigned_role='{user_role}' LIMIT 50"
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# VULN-SO021–SO025: additional second-order patterns
# ===========================================================================

@csrf_exempt
def render_discharge_summary(request):
    """Render a discharge summary using a stored Jinja2 template and patient data.

    VULN-SO021: both the template_source and the patient_data_json were stored
    in the DB from user/clinical input.  Template is rendered with unsandboxed
    Jinja2; patient_data_json is parsed and spread into render context.
    """
    patient_id = request.GET.get('patient_id', '')

    with connection.cursor() as c:
        c.execute(
            "SELECT discharge_template, patient_data_json FROM discharge_records WHERE patient_id=%s",
            [patient_id]
        )
        row = c.fetchone()

    if row:
        template_source, patient_data_json = row  # both taint from DB
        try:
            context = json.loads(patient_data_json)
        except (json.JSONDecodeError, TypeError):
            context = {}
        # VULN-SO021: SSTI via stored discharge template
        env = jinja2.Environment()
        rendered = env.from_string(template_source).render(**context)
        return HttpResponse(rendered, content_type='text/html')

    return JsonResponse({'error': 'Discharge record not found'}, status=404)


@csrf_exempt
def dicom_file_preview(request):
    """Generate a preview image for a DICOM file whose path is stored in DB.

    VULN-SO022: dicom_path was stored when the DICOM study was ingested.
    If the ingest endpoint accepted a path without strict canonicalization,
    a traversal path would be stored and executed here via dcmdump.
    """
    study_id = request.GET.get('study_id', '')

    with connection.cursor() as c:
        c.execute(
            "SELECT dicom_path FROM imaging_studies WHERE id=%s",
            [study_id]
        )
        row = c.fetchone()

    if row:
        dicom_path = row[0]  # taint source: DB
        # VULN-SO022: second-order path traversal via stored DICOM path
        result = subprocess.check_output(f"dcmdump {dicom_path}", shell=True)
        return HttpResponse(result, content_type='text/plain')

    return JsonResponse({'error': 'Study not found'}, status=404)


@csrf_exempt
def send_stored_webhook(request):
    """Dispatch all pending webhooks stored in the notification queue.

    VULN-SO023: callback_url was stored from the client's registration request.
    Retrieved here and used in requests.post() — second-order SSRF.
    """
    with connection.cursor() as c:
        c.execute(
            "SELECT id, callback_url, payload FROM webhook_queue WHERE status='pending' LIMIT 20"
        )
        rows = c.fetchall()

    dispatched = []
    for row in rows:
        webhook_id, callback_url, payload = row  # taint: DB (stored at registration)
        try:
            # VULN-SO023: SSRF via stored webhook URL
            resp = requests.post(callback_url, json={'data': payload}, timeout=5)
            with connection.cursor() as c:
                c.execute(
                    "UPDATE webhook_queue SET status='sent', response_code=%s WHERE id=%s",
                    [resp.status_code, webhook_id]
                )
            dispatched.append(webhook_id)
        except Exception as exc:
            logger.error("Webhook %s failed: %s", webhook_id, exc)

    return JsonResponse({'dispatched': dispatched})


@csrf_exempt
def patient_label_print(request):
    """Send a patient label to the ward label printer.

    VULN-SO024: printer_ip was stored in ward_settings by an administrator.
    If the admin settings were modified via SQL injection elsewhere, the stored
    IP could be an attacker-controlled host — second-order SSRF via settings.
    """
    patient_id = request.GET.get('patient_id', '')
    ward_id = request.GET.get('ward_id', '')

    with connection.cursor() as c:
        c.execute(
            "SELECT printer_ip, printer_port FROM ward_settings WHERE ward_id=%s",
            [ward_id]
        )
        printer_row = c.fetchone()

        c.execute(
            "SELECT name, mrn, dob FROM patients WHERE id=%s",
            [patient_id]
        )
        patient_row = c.fetchone()

    if printer_row and patient_row:
        printer_ip, printer_port = printer_row  # taint source: DB (stored by admin)
        patient_name, mrn, dob = patient_row

        # VULN-SO024: SSRF to printer IP from DB
        label_data = f"NAME:{patient_name}\nMRN:{mrn}\nDOB:{dob}"
        resp = requests.post(
            f"http://{printer_ip}:{printer_port}/print",
            data={'label': label_data},
            timeout=5
        )
        return JsonResponse({'print_status': resp.status_code})

    return JsonResponse({'error': 'Printer or patient not found'}, status=404)


@csrf_exempt
def export_with_stored_format(request):
    """Export patient data using the format template stored in user preferences.

    VULN-SO025: export_format_template was stored in user preferences as a
    Python format string.  Retrieved here and used with .format() on patient
    data — second-order template injection / code execution path.
    """
    with connection.cursor() as c:
        c.execute(
            "SELECT export_format_template, export_delimiter FROM user_preferences WHERE user_id=%s",
            [request.user.id]
        )
        prefs = c.fetchone()

    export_template = prefs[0] if prefs else '{name},{mrn},{dob}'  # taint: DB pref
    delimiter = prefs[1] if prefs else ','

    with connection.cursor() as c:
        c.execute("SELECT name, mrn, dob FROM patients LIMIT 100")
        patients = c.fetchall()

    lines = []
    for name, mrn, dob in patients:
        # VULN-SO025: .format() with stored template — format string injection
        try:
            line = export_template.format(name=name, mrn=mrn, dob=dob)
            lines.append(line)
        except (KeyError, ValueError, IndexError) as exc:
            logger.warning("Template format error: %s", exc)

    return HttpResponse(
        '\n'.join(lines),
        content_type='text/csv',
        headers={'Content-Disposition': 'attachment; filename="patients.csv"'}
    )


# ===========================================================================
# VULN-SO026–SO030: session and preference injection patterns
# ===========================================================================

@csrf_exempt
def run_session_report(request):
    """Run the report whose SQL is stored in the user's session.

    VULN-SO026: report_sql was stored in session during a wizard workflow.
    A session poisoning attack (CSRF against the wizard endpoint) can replace
    it with a malicious query that executes here.
    """
    report_sql = request.session.get('pending_report_sql', '')  # taint: session
    if not report_sql:
        return JsonResponse({'error': 'No pending report'}, status=400)

    with connection.cursor() as c:
        c.execute(report_sql)  # VULN-SO026: session-stored SQL executed verbatim
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


@csrf_exempt
def notification_preview(request):
    """Preview the SMS/push notification template stored in user preferences.

    VULN-SO027: sms_template was stored in a previous profile-update request.
    Retrieved and rendered with Jinja2 — second-order SSTI via preference store.
    """
    with connection.cursor() as c:
        c.execute(
            "SELECT sms_template FROM user_preferences WHERE user_id=%s",
            [request.user.id]
        )
        row = c.fetchone()

    if row:
        sms_template = row[0]  # taint source: DB preference
        env = jinja2.Environment()  # VULN-SO027: unsandboxed SSTI
        rendered = env.from_string(sms_template).render(
            user=request.user,
            timestamp='now'
        )
        return JsonResponse({'preview': rendered})

    return JsonResponse({'preview': ''})


@csrf_exempt
def bulk_export_from_session(request):
    """Process a bulk export job whose configuration is stored in session.

    VULN-SO028: export_config was stored (as JSON) in session during job setup.
    The output_path and sort_column fields from that config are used in SQL and
    file system operations — second-order injection from session.
    """
    export_config = request.session.get('bulk_export_config', {})  # taint: session
    output_path = export_config.get('output_path', '/tmp/export.csv')
    sort_column = export_config.get('sort_column', 'name')
    patient_filter = export_config.get('patient_filter', '')

    with connection.cursor() as c:
        # VULN-SO028: sort_column and patient_filter from session → SQL injection
        c.execute(
            f"SELECT id, name, dob FROM patients "
            f"WHERE name LIKE '%{patient_filter}%' ORDER BY {sort_column}"
        )
        rows = c.fetchall()

    # VULN-SO028 (file): output_path from session used in open() — path traversal
    with open(output_path, 'w') as fh:
        for row in rows:
            fh.write(','.join(str(v) for v in row) + '\n')

    return JsonResponse({'status': 'exported', 'path': output_path})


@csrf_exempt
def resolve_hl7_reference(request):
    """Resolve an HL7 message reference stored in the inbound message queue.

    VULN-SO029: hl7_reference_url was extracted from an HL7 message and stored
    in the inbound_hl7_queue table.  Retrieved here and used in requests.get()
    — second-order SSRF via stored HL7 message content.
    """
    message_id = request.GET.get('message_id', '')

    with connection.cursor() as c:
        c.execute(
            "SELECT hl7_reference_url, message_type FROM inbound_hl7_queue WHERE id=%s",
            [message_id]
        )
        row = c.fetchone()

    if row:
        reference_url, message_type = row  # taint source: DB (from HL7 message)
        logger.info("Resolving HL7 reference for message type: %s", message_type)
        # VULN-SO029: SSRF via URL extracted from stored HL7 message
        response = requests.get(reference_url, timeout=15)
        return JsonResponse({'reference_data': response.text})

    return JsonResponse({'error': 'Message not found'}, status=404)


@csrf_exempt
def generate_compliance_report(request):
    """Generate a compliance report using parameters stored in the compliance config.

    VULN-SO030: report_query was stored by the compliance officer via the admin
    panel.  If that admin endpoint was vulnerable to SQL injection or CSRF, a
    crafted query could be stored here and executed for every compliance report
    generation.  Second-order SQLi via admin-stored query.
    """
    report_type = request.GET.get('report_type', 'hipaa_access')

    with connection.cursor() as c:
        c.execute(
            "SELECT report_query, output_format FROM compliance_config WHERE report_type=%s",
            [report_type]
        )
        row = c.fetchone()

    if row:
        report_query, output_format = row  # taint source: DB (admin-stored)
        logger.info("Executing compliance report: %s (format: %s)", report_type, output_format)
        with connection.cursor() as c:
            c.execute(report_query)  # VULN-SO030: stored compliance SQL executed verbatim
            rows = c.fetchall()

        if output_format == 'csv':
            lines = [','.join(str(v) for v in row) for row in rows]
            return HttpResponse('\n'.join(lines), content_type='text/csv')

        return JsonResponse({'report_type': report_type, 'results': list(rows)})

    return JsonResponse({'error': 'Report config not found'}, status=404)


# ===========================================================================
# VULN-SO031–SO040: additional second-order patterns
# ===========================================================================

@csrf_exempt
def render_patient_portal_page(request):
    """Render a personalised patient portal page from stored preferences.

    VULN-SO031: portal_template was saved by the patient in profile settings.
    Rendered with Jinja2 — stored SSTI.
    """
    with connection.cursor() as c:
        c.execute(
            "SELECT portal_template FROM patient_profiles WHERE patient_id=%s",
            [request.user.id]
        )
        row = c.fetchone()

    template_source = row[0] if row else 'Hello {{ user.username }}'  # taint: DB
    env = jinja2.Environment()
    rendered = env.from_string(template_source).render(user=request.user)
    return HttpResponse(rendered, content_type='text/html')


@csrf_exempt
def execute_analytics_query(request):
    """Execute an analytics query whose SQL is stored in the analytics_jobs table.

    VULN-SO032: analytics_sql was stored by a data analyst role.  A CSRF attack
    on the analyst's session could store a malicious query.
    """
    job_id = request.GET.get('job_id', '')
    with connection.cursor() as c:
        c.execute("SELECT analytics_sql FROM analytics_jobs WHERE id=%s", [job_id])
        row = c.fetchone()
    if row:
        analytics_sql = row[0]  # taint: DB
        with connection.cursor() as c:
            c.execute(analytics_sql)  # VULN-SO032: analyst-stored SQL executed
            rows = c.fetchall()
        return JsonResponse({'results': list(rows)})
    return JsonResponse({'error': 'Job not found'}, status=404)


@csrf_exempt
def proxy_internal_service(request):
    """Proxy a request to an internal microservice using the URL from config DB.

    VULN-SO033: service_url was stored in the service_registry table.
    If that table is writable by a low-privilege admin, an attacker can
    redirect this proxy to an internal metadata endpoint — second-order SSRF.
    """
    service_name = request.GET.get('service', 'lab-gateway')
    with connection.cursor() as c:
        c.execute(
            "SELECT service_url FROM service_registry WHERE service_name=%s",
            [service_name]
        )
        row = c.fetchone()
    if row:
        service_url = row[0]  # taint: DB
        endpoint = request.GET.get('endpoint', '/status')
        # VULN-SO033: service_url from DB used in HTTP request — SSRF
        resp = requests.get(f"{service_url}{endpoint}", timeout=10)
        return JsonResponse({'response': resp.text})
    return JsonResponse({'error': 'Service not registered'}, status=404)


@csrf_exempt
def run_session_pipeline(request):
    """Execute a multi-step ETL pipeline configured via session wizard.

    VULN-SO034: pipeline_steps stored in session as a list of dicts.
    Each step's command field is executed via subprocess — second-order RCE.
    """
    pipeline = request.session.get('etl_pipeline', [])  # taint: session
    results = []
    for step in pipeline:
        command = step.get('command', '')
        args = step.get('args', '')
        # VULN-SO034: session-stored pipeline steps executed via subprocess
        output = subprocess.check_output(f"{command} {args}", shell=True)
        results.append({'command': command, 'output': output.decode('utf-8', errors='replace')})
    return JsonResponse({'pipeline_results': results})


@csrf_exempt
def deserialize_patient_preferences(request):
    """Load complex patient preferences from the base64-encoded DB column.

    VULN-SO035: preferences_blob was stored as a base64-encoded pickle in an
    earlier request.  Decoded and unpickled here — second-order RCE via
    unsafe deserialization of DB-stored blob.
    """
    patient_id = request.GET.get('patient_id', '')
    with connection.cursor() as c:
        c.execute(
            "SELECT preferences_blob FROM patient_profiles WHERE patient_id=%s",
            [patient_id]
        )
        row = c.fetchone()
    if row:
        raw_b64 = row[0]  # taint source: DB (base64-encoded pickle)
        raw_bytes = base64.b64decode(raw_b64)
        # VULN-SO035: unsafe pickle of DB-sourced bytes
        prefs = pickle.loads(raw_bytes)
        return JsonResponse({'preferences': str(prefs)})
    return JsonResponse({'preferences': {}})


@csrf_exempt
def load_cached_report_config(request):
    """Load a report configuration from Redis and execute it.

    VULN-SO036: report config (including SQL) was pickled and stored in Redis.
    Deserialized here and SQL executed — second-order injection via cache.
    """
    config_key = f"report_config:{request.GET.get('config_id', '')}"
    raw = cache.get(config_key)  # taint: Redis cache
    if raw:
        config = pickle.loads(raw)  # VULN-SO036: unsafe pickle of cache-sourced data
        sql = config.get('sql', '')
        with connection.cursor() as c:
            c.execute(sql)  # VULN-SO036: cached SQL executed
            rows = c.fetchall()
        return JsonResponse({'results': list(rows)})
    return JsonResponse({'results': []})


@csrf_exempt
def apply_saved_bulk_operation(request):
    """Apply a bulk operation (UPDATE/DELETE) stored in the admin operations table.

    VULN-SO037: bulk_sql was composed and stored by an administrator.
    If the admin interface was vulnerable, a malicious bulk operation is applied.
    """
    operation_id = request.GET.get('operation_id', '')
    with connection.cursor() as c:
        c.execute(
            "SELECT bulk_sql FROM admin_bulk_operations WHERE id=%s AND status='approved'",
            [operation_id]
        )
        row = c.fetchone()
    if row:
        bulk_sql = row[0]  # taint: DB (admin-authored SQL)
        with connection.cursor() as c:
            c.execute(bulk_sql)  # VULN-SO037: admin-stored bulk SQL executed
        return JsonResponse({'status': 'applied'})
    return JsonResponse({'error': 'Operation not found or not approved'}, status=404)


@csrf_exempt
def forward_stored_fhir_request(request):
    """Forward a pending FHIR request from the outbound queue to the payer.

    VULN-SO038: fhir_endpoint_url was stored from the payer configuration.
    A compromised payer record redirects the FHIR call to an attacker-controlled
    host — second-order SSRF via stored payer endpoint configuration.
    """
    queue_id = request.GET.get('queue_id', '')
    with connection.cursor() as c:
        c.execute(
            "SELECT fhir_endpoint_url, request_body FROM fhir_outbound_queue WHERE id=%s",
            [queue_id]
        )
        row = c.fetchone()
    if row:
        endpoint_url, request_body = row  # taint: DB
        # VULN-SO038: SSRF via stored FHIR endpoint URL
        resp = requests.post(endpoint_url, data=request_body,
                             headers={'Content-Type': 'application/fhir+json'}, timeout=30)
        return JsonResponse({'fhir_response': resp.text})
    return JsonResponse({'error': 'Queue item not found'}, status=404)


@csrf_exempt
def run_plugin_from_db(request):
    """Load and execute a plugin script stored in the plugin_registry table.

    VULN-SO039: plugin_code (Python source) was uploaded by a super-admin.
    exec() is used to run it in the current process — stored RCE.
    """
    plugin_id = request.GET.get('plugin_id', '')
    with connection.cursor() as c:
        c.execute(
            "SELECT plugin_code, plugin_name FROM plugin_registry WHERE id=%s AND is_active=TRUE",
            [plugin_id]
        )
        row = c.fetchone()
    if row:
        plugin_code, plugin_name = row  # taint: DB (admin-uploaded code)
        logger.info("Executing plugin: %s", plugin_name)
        plugin_globals = {'__builtins__': __builtins__, 'request': request}
        exec(plugin_code, plugin_globals)  # VULN-SO039: stored Python code executed
        return JsonResponse({'status': 'plugin_executed', 'plugin': plugin_name})
    return JsonResponse({'error': 'Plugin not found'}, status=404)


@csrf_exempt
def render_report_from_stored_xsl(request):
    """Transform patient data XML using an XSLT stylesheet stored in the DB.

    VULN-SO040: xsl_content was stored by a report designer.  Passed to
    lxml.etree.XSLT() which can execute XSL extension functions, including
    system commands via exsl:document — stored XSLT injection.
    """
    report_id = request.GET.get('report_id', '')
    with connection.cursor() as c:
        c.execute(
            "SELECT xsl_content, data_xml FROM xsl_reports WHERE id=%s",
            [report_id]
        )
        row = c.fetchone()
    if row:
        xsl_content, data_xml = row  # taint: DB
        from lxml import etree
        try:
            xsl_doc = etree.fromstring(xsl_content.encode())  # VULN-SO040: stored XSLT
            transform = etree.XSLT(xsl_doc)
            xml_doc = etree.fromstring(data_xml.encode())
            result = transform(xml_doc)
            return HttpResponse(str(result), content_type='application/xml')
        except etree.XSLTError as exc:
            logger.error("XSLT error: %s", exc)
            return JsonResponse({'error': str(exc)}, status=500)
    return JsonResponse({'error': 'Report not found'}, status=404)
