"""
MediCore multi-step transformation chains.

Each chain passes user input through 3–5 transformation functions before
reaching a dangerous sink.  The taint survives every step because each
transformation preserves the injected content (or only partially neutralises it).

SAST tools must track taint through all intermediate function calls to detect
these — a shallow analysis misses the sink.

SECURITY TRAINING: VULN-TC001–TC030
"""
import base64
import html
import json
import os
import re
import subprocess
import urllib.parse

import jinja2
import requests

from django.db import connection
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt

# ===========================================================================
# Shared low-level transformation steps (reused across chains)
# ===========================================================================

def _b64_or_url_decode(raw: str) -> str:
    """Try base64 decode; fall back to URL decode.  VULN helper — taint passes through."""
    try:
        decoded = base64.b64decode(raw + '==').decode('utf-8')
        return decoded
    except Exception:
        return urllib.parse.unquote(raw)


def _normalize_whitespace(text: str) -> str:
    """Collapse repeated whitespace to single spaces."""
    return ' '.join(text.split())


def _title_case_format(text: str) -> str:
    """Convert to title case for display — taint in casing is preserved."""
    return text.strip().title()


def _html_unescape(text: str) -> str:
    """Unescape HTML entities — can reintroduce injection chars."""
    return html.unescape(text)


def _strip_outer_tags(text: str) -> str:
    """Remove the outermost HTML tag pair — naive, bypassable."""
    return re.sub(r'^<[^>]+>(.*)</[^>]+>$', r'\1', text, flags=re.DOTALL)


def _url_decode(text: str) -> str:
    """Single-pass URL decode — double-encoded payloads survive."""
    return urllib.parse.unquote(text)


def _apply_prefix_wildcard(text: str) -> str:
    """Append wildcard for LIKE searches."""
    return text + '%'


def _truncate(text: str, max_len: int = 200) -> str:
    """Truncate to max_len characters — injection payload may fit within limit."""
    return text[:max_len]


def _xor_decrypt(ciphertext: str, key: int = 0x5A) -> str:
    """XOR decrypt with a fixed key — taint fully restored after decryption."""
    try:
        raw_bytes = base64.b64decode(ciphertext + '==')
        return ''.join(chr(b ^ key) for b in raw_bytes)
    except Exception:
        return ciphertext


def _validate_format_loose(value: str, pattern: str = r'.+') -> str:
    """Loose format validation — only checks the pattern, returns original value."""
    if not re.match(pattern, value):
        raise ValueError(f"Value {value!r} does not match expected pattern")
    return value  # VULN: original (tainted) value returned, not a sanitised version


def _resolve_path(relative_path: str, base_dir: str = '/var/medicore/') -> str:
    """Join relative path to base directory — no canonicalization."""
    return os.path.join(base_dir, relative_path)


def _to_sql_date(date_str: str) -> str:
    """Convert a date string for embedding in SQL — no escaping applied."""
    return date_str.strip()


def _build_csv_row(fields: list) -> str:
    """Build a CSV row — no formula prefix stripping."""
    return ','.join(str(f) for f in fields)


# ===========================================================================
# Chain 1: decode → normalize → format → SQL (VULN-TC001)
# ===========================================================================

def step1_decode_input(raw: str) -> str:
    """Step 1: Base64 or URL decode."""
    return _b64_or_url_decode(raw)


def step2_normalize_whitespace(text: str) -> str:
    """Step 2: Normalize whitespace."""
    return _normalize_whitespace(text)


def step3_format_for_query(text: str) -> str:
    """Step 3: Title-case the value for display/query consistency."""
    return _title_case_format(text)


@csrf_exempt
def search_patients_chained(request):
    """VULN-TC001: 3-step chain: decode → normalize → format → SQL.

    The injection payload survives all three transformations and lands in
    a raw cursor.execute() f-string.
    """
    raw_input = request.GET.get('q', '')
    decoded = step1_decode_input(raw_input)       # step 1
    normalized = step2_normalize_whitespace(decoded)   # step 2
    formatted = step3_format_for_query(normalized)     # step 3
    with connection.cursor() as c:
        c.execute(f"SELECT * FROM patients WHERE name='{formatted}'")  # sink
        return JsonResponse({'results': list(c.fetchall())})


# ===========================================================================
# Chain 2: parse JSON → extract term → apply wildcard → SQL LIKE (VULN-TC002)
# ===========================================================================

def parse_json_field(raw_json: str, field: str) -> str:
    """Step 1: Parse JSON and extract a named field."""
    try:
        obj = json.loads(raw_json)
        return str(obj.get(field, ''))
    except (json.JSONDecodeError, AttributeError):
        return raw_json


def extract_search_term(value: str) -> str:
    """Step 2: Strip surrounding quotes from search term."""
    return value.strip('"\'')


def apply_prefix_wildcard(term: str) -> str:
    """Step 3: Add SQL LIKE wildcard prefix."""
    return '%' + term


@csrf_exempt
def diagnosis_search_chained(request):
    """VULN-TC002: parse_json_field → extract_search_term → apply_prefix_wildcard → SQL LIKE."""
    raw_json = request.GET.get('filter', '{"term": "diabetes"}')
    term = parse_json_field(raw_json, 'term')        # step 1
    clean = extract_search_term(term)                # step 2
    wildcard = apply_prefix_wildcard(clean)          # step 3
    with connection.cursor() as c:
        c.execute(f"SELECT * FROM patients WHERE diagnosis LIKE '{wildcard}%'")  # sink
        return JsonResponse({'results': list(c.fetchall())})


# ===========================================================================
# Chain 3: URL decode → HTML unescape → strip tags → shell command (VULN-TC003)
# ===========================================================================

def step_url_decode(text: str) -> str:
    """Step 1: URL decode."""
    return _url_decode(text)


def step_html_unescape(text: str) -> str:
    """Step 2: HTML unescape — reintroduces < > ' " etc."""
    return _html_unescape(text)


def step_strip_outer_tag(text: str) -> str:
    """Step 3: Strip outermost HTML tag."""
    return _strip_outer_tag(text)


def _strip_outer_tag(text: str) -> str:
    return re.sub(r'^<[^>]+>(.*)</[^>]+>$', r'\1', text, flags=re.DOTALL).strip()


@csrf_exempt
def export_diagnosis_report_chained(request):
    """VULN-TC003: url_decode → html_unescape → strip_tags → os.system."""
    raw = request.POST.get('diagnosis_filter', '')
    decoded = step_url_decode(raw)          # step 1
    unescaped = step_html_unescape(decoded) # step 2
    stripped = step_strip_outer_tag(unescaped)  # step 3
    # VULN-TC003: shell command injection after 3-step transform
    os.system(f"medicore-export --filter '{stripped}' --output /tmp/report.csv")
    return JsonResponse({'status': 'exported'})


# ===========================================================================
# Chain 4: XOR decrypt → validate format → resolve path → open() (VULN-TC004)
# ===========================================================================

def step_decrypt_param(ciphertext: str) -> str:
    """Step 1: XOR decrypt with fixed key."""
    return _xor_decrypt(ciphertext)


def step_validate_format(value: str, pattern: str = r'^[\w\-\.]+$') -> str:
    """Step 2: Validate format pattern — only checks shape, returns original."""
    return _validate_format_loose(value, pattern)


def step_resolve_path(relative: str) -> str:
    """Step 3: Resolve to absolute path under base directory."""
    return _resolve_path(relative, '/var/medicore/documents/')


@csrf_exempt
def serve_encrypted_document(request):
    """VULN-TC004: decrypt → validate_format → resolve_path → open().

    The format check passes simple filenames AND traversal paths like
    '../../etc/passwd' (which matches [\w\-\./]+).
    """
    ciphertext = request.GET.get('doc', '')
    decrypted = step_decrypt_param(ciphertext)      # step 1
    validated = step_validate_format(decrypted, r'^[\w\-\./]+$')  # step 2 — '/' allowed!
    full_path = step_resolve_path(validated)        # step 3
    with open(full_path, 'rb') as fh:              # sink — path traversal
        return HttpResponse(fh.read(), content_type='application/octet-stream')


# ===========================================================================
# Chain 5: deserialize preference → apply user template → render with Jinja2 (VULN-TC005)
# ===========================================================================

def deserialize_preference(raw_b64: str) -> dict:
    """Step 1: Decode base64 JSON user preference blob."""
    try:
        decoded = base64.b64decode(raw_b64 + '==').decode('utf-8')
        return json.loads(decoded)
    except Exception:
        return {}


def apply_user_template(prefs: dict) -> str:
    """Step 2: Extract the template string from the preferences dict."""
    return prefs.get('notification_template', 'Hello {{ username }}')


def render_with_jinja2(template_source: str, context: dict) -> str:
    """Step 3: Render template with Jinja2 — no sandbox."""
    env = jinja2.Environment()  # VULN: unsandboxed
    return env.from_string(template_source).render(**context)


@csrf_exempt
def render_user_notification_chained(request):
    """VULN-TC005: deserialize_preference → apply_user_template → render_with_jinja2 (SSTI)."""
    pref_blob = request.GET.get('prefs', 'e30=')     # default: {}
    prefs = deserialize_preference(pref_blob)        # step 1
    template_source = apply_user_template(prefs)     # step 2
    rendered = render_with_jinja2(template_source, {'username': request.user.username if request.user.is_authenticated else 'Guest'})  # step 3 = sink
    return JsonResponse({'notification': rendered})


# ===========================================================================
# Chain 6: decode HL7 segment → extract field → normalize for DB → cursor.execute (VULN-TC006)
# ===========================================================================

def decode_hl7_segment(raw_segment: str) -> list:
    """Step 1: Parse a pipe-delimited HL7 segment into fields."""
    return raw_segment.split('|')


def extract_hl7_field_value(fields: list, index: int = 3) -> str:
    """Step 2: Extract a specific field value from the HL7 segment."""
    try:
        return fields[index].strip()
    except IndexError:
        return ''


def normalize_for_db(value: str) -> str:
    """Step 3: Normalize value for database storage — uppercase, strip spaces."""
    return value.strip().upper()


@csrf_exempt
def ingest_hl7_patient_data(request):
    """VULN-TC006: decode_hl7_segment → extract_field → normalize → cursor.execute."""
    raw_segment = request.POST.get('segment', '')
    fields = decode_hl7_segment(raw_segment)        # step 1
    field_value = extract_hl7_field_value(fields, index=3)  # step 2
    normalized = normalize_for_db(field_value)      # step 3
    with connection.cursor() as c:
        # VULN-TC006: normalized HL7 field value interpolated into SQL
        c.execute(f"INSERT INTO hl7_inbound (patient_id, value) VALUES (1, '{normalized}')")
    return JsonResponse({'status': 'ingested'})


# ===========================================================================
# Chain 7: parse FHIR reference → resolve type → build URL → requests.get (VULN-TC007)
# ===========================================================================

def parse_fhir_reference(ref: str) -> dict:
    """Step 1: Parse a FHIR resource reference into type and ID."""
    parts = ref.split('/')
    return {'resource_type': parts[0] if parts else '', 'resource_id': parts[1] if len(parts) > 1 else ''}


def resolve_reference_type(parsed: dict) -> str:
    """Step 2: Map FHIR resource type to a URL path component."""
    type_map = {
        'Patient': 'patients',
        'Observation': 'observations',
        'Encounter': 'encounters',
    }
    return type_map.get(parsed.get('resource_type', ''), parsed.get('resource_type', ''))


def build_resource_url(base_url: str, path_component: str, resource_id: str) -> str:
    """Step 3: Build the full FHIR resource URL."""
    return f"{base_url}/{path_component}/{resource_id}"


@csrf_exempt
def fhir_resource_proxy_chained(request):
    """VULN-TC007: parse_fhir_reference → resolve_type → build_url → requests.get (SSRF)."""
    fhir_ref = request.GET.get('ref', '')
    fhir_base = request.GET.get('base', 'https://fhir.hospital.internal')
    parsed = parse_fhir_reference(fhir_ref)              # step 1
    path_component = resolve_reference_type(parsed)      # step 2
    resource_url = build_resource_url(fhir_base, path_component, parsed.get('resource_id', ''))  # step 3
    # VULN-TC007: SSRF — base URL and resource_id attacker-controlled
    response = requests.get(resource_url, timeout=10)
    return JsonResponse({'data': response.json()})


# ===========================================================================
# Chain 8: strip HTML → decode entities → truncate → build_csv_row (VULN-TC008)
# ===========================================================================

def strip_html_markup(text: str) -> str:
    """Step 1: Strip HTML tags using regex."""
    return re.sub(r'<[^>]+>', '', text)


def decode_html_entities(text: str) -> str:
    """Step 2: Decode HTML entities — reintroduces special characters."""
    return html.unescape(text)


def truncate_for_csv(text: str, max_len: int = 100) -> str:
    """Step 3: Truncate to max CSV cell length."""
    return text[:max_len]


@csrf_exempt
def export_patient_notes_csv_chained(request):
    """VULN-TC008: strip_html → decode_entities → truncate → CSV (formula injection).

    After HTML stripping and entity decoding, a =cmd| payload that was encoded
    as &#61;cmd| passes through to the CSV cell.
    """
    patient_id = request.GET.get('patient_id', '')
    with connection.cursor() as c:
        c.execute("SELECT name, notes FROM patients WHERE id=%s", [patient_id])
        row = c.fetchone()

    if row:
        name, notes = row
        clean_name = strip_html_markup(str(name))      # step 1
        decoded_name = decode_html_entities(clean_name)  # step 2
        truncated_name = truncate_for_csv(decoded_name)  # step 3
        # VULN-TC008: CSV formula injection — =cmd|... restored after entity decode
        csv_row = _build_csv_row([truncated_name, patient_id])
        return HttpResponse(csv_row, content_type='text/csv')

    return JsonResponse({'error': 'Patient not found'}, status=404)


# ===========================================================================
# Chain 9: parse date → format for locale → to_sql_date → ORDER BY (VULN-TC009)
# ===========================================================================

def parse_appointment_date(date_str: str) -> str:
    """Step 1: Parse a user-supplied date and re-format as YYYY-MM-DD."""
    from datetime import datetime
    for fmt in ('%d/%m/%Y', '%m/%d/%Y', '%Y-%m-%d'):
        try:
            return datetime.strptime(date_str, fmt).strftime('%Y-%m-%d')
        except ValueError:
            continue
    return date_str  # VULN: if no format matches, raw string returned


def format_for_locale(date_iso: str, locale: str = 'en-US') -> str:
    """Step 2: Format date for locale display — passes through ISO string."""
    locale_formats = {'en-US': '%m/%d/%Y', 'en-GB': '%d/%m/%Y', 'de': '%d.%m.%Y'}
    fmt = locale_formats.get(locale, '%Y-%m-%d')
    try:
        from datetime import datetime
        dt = datetime.strptime(date_iso, '%Y-%m-%d')
        return dt.strftime(fmt)
    except ValueError:
        return date_iso  # VULN: unparsed raw string falls through


def to_sql_date_format(date_str: str) -> str:
    """Step 3: Convert locale-formatted date back for SQL — no escaping."""
    return _to_sql_date(date_str)


@csrf_exempt
def appointments_by_date_chained(request):
    """VULN-TC009: parse_date → format_locale → to_sql_date → ORDER BY injection.

    If parse_appointment_date() fails to parse (e.g. attacker sends "name; DROP TABLE"),
    the raw string propagates through all three steps into ORDER BY.
    """
    date_str = request.GET.get('date', '')
    order_by_field = request.GET.get('order', 'appt_date')

    parsed = parse_appointment_date(date_str)          # step 1
    locale_date = format_for_locale(parsed)            # step 2
    sql_date = to_sql_date_format(locale_date)         # step 3

    with connection.cursor() as c:
        # VULN-TC009: ORDER BY injection via order_by_field; date injection possible too
        c.execute(
            f"SELECT * FROM appointments WHERE appt_date='{sql_date}' ORDER BY {order_by_field}"
        )
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# Chain 10: normalize insurance ID → lookup provider mapping → build query (VULN-TC010)
# ===========================================================================

def normalize_insurance_id(insurance_id: str) -> str:
    """Step 1: Strip non-alphanumeric characters from insurance ID."""
    return re.sub(r'[^A-Z0-9]', '', insurance_id.upper())


def lookup_provider_mapping(insurance_id: str) -> str:
    """Step 2: Look up a provider code for the insurance ID from DB."""
    with connection.cursor() as c:
        c.execute(
            "SELECT provider_code FROM insurance_mappings WHERE insurance_id=%s",
            [insurance_id]
        )
        row = c.fetchone()
    return row[0] if row else insurance_id  # VULN: falls back to raw insurance_id


def build_provider_query(provider_code: str) -> str:
    """Step 3: Build a SQL query string for the provider — no parameterization."""
    return f"SELECT * FROM billing WHERE provider_code='{provider_code}'"


@csrf_exempt
def billing_lookup_chained(request):
    """VULN-TC010: normalize_insurance_id → lookup_provider_mapping → build_query → execute."""
    insurance_id = request.GET.get('insurance_id', '')
    normalized = normalize_insurance_id(insurance_id)      # step 1
    provider_code = lookup_provider_mapping(normalized)    # step 2
    query = build_provider_query(provider_code)            # step 3
    with connection.cursor() as c:
        c.execute(query)  # VULN-TC010: SQL injection via provider_code from mapping table
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# ===========================================================================
# Chain 11: parse upload metadata → generate storage path → validate ext → write (VULN-TC011)
# ===========================================================================

def parse_upload_metadata(metadata_json: str) -> dict:
    """Step 1: Parse upload metadata from JSON."""
    try:
        return json.loads(metadata_json)
    except json.JSONDecodeError:
        return {}


def generate_storage_path(metadata: dict) -> str:
    """Step 2: Generate a storage path from metadata fields."""
    patient_id = metadata.get('patient_id', 'unknown')
    filename = metadata.get('filename', 'upload.bin')
    return f"/var/medicore/uploads/{patient_id}/{filename}"


def validate_extension(path: str) -> str:
    """Step 3: Check that the file extension is allowed — path returned as-is."""
    allowed = {'.pdf', '.jpg', '.png', '.dicom', '.dcm'}
    _, ext = os.path.splitext(path)
    if ext.lower() not in allowed:
        raise ValueError(f"Extension not allowed: {ext!r}")
    return path  # VULN: full (potentially traversal) path returned


@csrf_exempt
def upload_patient_document_chained(request):
    """VULN-TC011: parse_metadata → generate_path → validate_ext → open() write.

    metadata.filename = '../../etc/cron.d/malicious.pdf' passes the extension
    check and writes to /etc/cron.d/.
    """
    metadata_json = request.POST.get('metadata', '{}')
    file_content = request.body

    metadata = parse_upload_metadata(metadata_json)    # step 1
    storage_path = generate_storage_path(metadata)    # step 2
    validated_path = validate_extension(storage_path) # step 3

    with open(validated_path, 'wb') as fh:            # sink — path traversal
        fh.write(file_content)

    return JsonResponse({'stored_at': validated_path})


# ===========================================================================
# Chains 12–20: additional 3–5 step chains
# ===========================================================================

# Chain 12: decode → normalize → lookup DB → LDAP query (VULN-TC012)

def decode_staff_id(raw: str) -> str:
    """Step 1: URL decode staff identifier."""
    return urllib.parse.unquote(raw)


def normalize_staff_id(staff_id: str) -> str:
    """Step 2: Strip whitespace and lowercase."""
    return staff_id.strip().lower()


def resolve_staff_username(staff_id: str) -> str:
    """Step 3: Look up LDAP username from DB for the staff ID."""
    with connection.cursor() as c:
        c.execute("SELECT ldap_username FROM staff WHERE staff_id=%s", [staff_id])
        row = c.fetchone()
    return row[0] if row else staff_id  # VULN: fallback to raw staff_id


@csrf_exempt
def staff_ldap_lookup_chained(request):
    """VULN-TC012: decode → normalize → resolve_username → LDAP filter injection."""
    raw_id = request.GET.get('staff_id', '')
    decoded = decode_staff_id(raw_id)           # step 1
    normalized = normalize_staff_id(decoded)    # step 2
    ldap_user = resolve_staff_username(normalized)  # step 3

    import ldap3
    server = ldap3.Server('ldap://ldap.hospital.internal')
    conn = ldap3.Connection(server, auto_bind=True)
    # VULN-TC012: LDAP injection via resolved username
    ldap_filter = f"(&(objectClass=person)(uid={ldap_user}))"
    conn.search('dc=hospital,dc=internal', ldap_filter)
    return JsonResponse({'found': len(conn.entries) > 0})


# Chain 13: parse cookie → expand template variables → SQL query (VULN-TC013)

def parse_cookie_filter(cookie_value: str) -> dict:
    """Step 1: Parse a cookie value as JSON filter config."""
    try:
        return json.loads(urllib.parse.unquote(cookie_value))
    except (json.JSONDecodeError, Exception):
        return {'field': 'name', 'value': cookie_value}


def expand_filter_template(config: dict) -> str:
    """Step 2: Build a filter expression string from config."""
    field = config.get('field', 'name')
    value = config.get('value', '')
    return f"{field} LIKE '%{value}%'"


@csrf_exempt
def cookie_driven_search(request):
    """VULN-TC013: parse_cookie → expand_template → SQL WHERE injection."""
    cookie_val = request.COOKIES.get('patient_filter_config', '{}')
    filter_config = parse_cookie_filter(cookie_val)      # step 1
    where_clause = expand_filter_template(filter_config) # step 2
    with connection.cursor() as c:
        # VULN-TC013: WHERE clause from cookie-derived config
        c.execute(f"SELECT id, name FROM patients WHERE {where_clause}")
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# Chain 14: decode base64 header → parse CSV → build INSERT (VULN-TC014)

def decode_b64_header(header_val: str) -> str:
    """Step 1: Base64 decode a custom HTTP header value."""
    try:
        return base64.b64decode(header_val + '==').decode('utf-8')
    except Exception:
        return header_val


def parse_csv_record(csv_line: str) -> list:
    """Step 2: Split CSV line into fields."""
    return [field.strip() for field in csv_line.split(',')]


def build_patient_insert(fields: list) -> str:
    """Step 3: Build an INSERT statement from fields."""
    if len(fields) >= 3:
        name, dob, mrn = fields[0], fields[1], fields[2]
        return f"INSERT INTO patients (name, dob, mrn) VALUES ('{name}', '{dob}', '{mrn}')"
    return "SELECT 1"


@csrf_exempt
def import_patient_from_header(request):
    """VULN-TC014: decode_b64_header → parse_csv → build_insert → execute."""
    encoded_header = request.META.get('HTTP_X_PATIENT_DATA', '')
    decoded = decode_b64_header(encoded_header)      # step 1
    fields = parse_csv_record(decoded)               # step 2
    insert_sql = build_patient_insert(fields)        # step 3
    with connection.cursor() as c:
        c.execute(insert_sql)  # VULN-TC014: SQL injection via base64-encoded header
    return JsonResponse({'status': 'imported'})


# Chain 15: apply prefix → format query template → SQL (VULN-TC015)

def apply_search_prefix(value: str, prefix: str = 'MRN-') -> str:
    """Step 1: Add a standard prefix to the lookup value."""
    return prefix + value


def format_query_template(prefixed: str) -> str:
    """Step 2: Format into query expression."""
    return f"mrn = '{prefixed}' OR mrn LIKE '{prefixed}%'"


@csrf_exempt
def mrn_search_chained(request):
    """VULN-TC015: apply_prefix → format_query_template → SQL WHERE injection."""
    raw_mrn = request.GET.get('mrn', '')
    prefixed = apply_search_prefix(raw_mrn)       # step 1
    where_expr = format_query_template(prefixed)  # step 2
    with connection.cursor() as c:
        c.execute(f"SELECT * FROM patients WHERE {where_expr}")
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# Chain 16: split → join → shell quote (VULN-TC016)

def split_diagnosis_list(csv_diagnoses: str) -> list:
    """Step 1: Split comma-separated diagnosis codes."""
    return [d.strip() for d in csv_diagnoses.split(',') if d.strip()]


def join_for_sql_in(codes: list) -> str:
    """Step 2: Join codes for a SQL IN clause — no parameterization."""
    quoted = ', '.join(f"'{c}'" for c in codes)
    return f"({quoted})"


@csrf_exempt
def multi_diagnosis_search_chained(request):
    """VULN-TC016: split_diagnosis_list → join_for_sql_in → SQL IN injection."""
    raw_codes = request.GET.get('diagnoses', '')
    codes = split_diagnosis_list(raw_codes)         # step 1
    in_clause = join_for_sql_in(codes)              # step 2
    with connection.cursor() as c:
        c.execute(f"SELECT * FROM patients WHERE diagnosis IN {in_clause}")
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# Chain 17: decode → expand macros → render template (VULN-TC017)

def decode_notification_payload(raw: str) -> str:
    """Step 1: URL decode notification payload."""
    return urllib.parse.unquote(raw)


def expand_notification_macros(template_str: str, patient_name: str) -> str:
    """Step 2: Replace simple {{PATIENT}} macro — leaves Jinja2 {{ }} intact."""
    return template_str.replace('{{PATIENT}}', patient_name)


@csrf_exempt
def send_custom_notification_chained(request):
    """VULN-TC017: decode → expand_macros → jinja2.render (SSTI)."""
    raw_template = request.POST.get('template', '')
    patient_name = request.POST.get('patient_name', '')

    decoded = decode_notification_payload(raw_template)        # step 1
    expanded = expand_notification_macros(decoded, patient_name)  # step 2

    env = jinja2.Environment()
    rendered = env.from_string(expanded).render(patient_name=patient_name)  # step 3 — SSTI
    return JsonResponse({'message': rendered})


# Chain 18: validate schema → extract payload → execute report (VULN-TC018)

def validate_report_request_schema(data: dict) -> dict:
    """Step 1: Validate required keys are present — does NOT sanitize values."""
    required = {'report_name', 'output_format', 'date_range'}
    if not required.issubset(data.keys()):
        raise ValueError("Missing required report fields")
    return data  # VULN: values unchanged


def extract_report_payload(validated: dict) -> tuple:
    """Step 2: Extract individual fields from validated request."""
    return validated['report_name'], validated['output_format'], validated['date_range']


@csrf_exempt
def run_report_chained(request):
    """VULN-TC018: validate_schema → extract_payload → subprocess command injection."""
    import json as _json
    try:
        data = _json.loads(request.body)
    except Exception:
        data = {}

    validated = validate_report_request_schema(data)              # step 1
    report_name, output_format, date_range = extract_report_payload(validated)  # step 2

    # VULN-TC018: command injection — all three fields injected into shell command
    cmd = (
        f"medicore-report --name {report_name} "
        f"--format {output_format} --range '{date_range}'"
    )
    result = subprocess.check_output(cmd, shell=True)
    return HttpResponse(result)


# Chain 19: parse session pref → apply sort → SQL query (VULN-TC019)

def parse_session_preference(session: dict, key: str, default: str) -> str:
    """Step 1: Retrieve a preference value from session dict."""
    return str(session.get(key, default))


def apply_sort_preference(sort_col: str, sort_dir: str) -> str:
    """Step 2: Combine sort column and direction into ORDER BY expression."""
    return f"{sort_col} {sort_dir}"


@csrf_exempt
def patient_list_session_pref_chained(request):
    """VULN-TC019: parse_session_pref → apply_sort → SQL ORDER BY injection."""
    sort_col = parse_session_preference(request.session, 'sort_col', 'name')  # step 1
    sort_dir = parse_session_preference(request.session, 'sort_dir', 'ASC')   # step 1
    order_expr = apply_sort_preference(sort_col, sort_dir)                     # step 2
    with connection.cursor() as c:
        c.execute(f"SELECT id, name, dob FROM patients ORDER BY {order_expr}")   # step 3 — sink
        rows = c.fetchall()
    return JsonResponse({'results': list(rows)})


# Chain 20: decode → normalise → lookup cached → SSRF (VULN-TC020)

def decode_endpoint_ref(raw: str) -> str:
    """Step 1: Decode a potentially encoded endpoint reference."""
    return _b64_or_url_decode(raw)


def normalize_endpoint_scheme(endpoint: str) -> str:
    """Step 2: Ensure https:// scheme — but doesn't block internal addresses."""
    if not endpoint.startswith('http'):
        endpoint = 'https://' + endpoint
    return endpoint


def resolve_endpoint_from_cache(endpoint: str) -> str:
    """Step 3: Check cache for a remapped endpoint — fallback to original."""
    from django.core.cache import cache
    remapped = cache.get(f"endpoint_remap:{endpoint}")
    return remapped if remapped else endpoint


@csrf_exempt
def fetch_external_reference_chained(request):
    """VULN-TC020: decode → normalize_scheme → resolve_cache → requests.get (SSRF)."""
    raw_endpoint = request.GET.get('endpoint', '')
    decoded = decode_endpoint_ref(raw_endpoint)           # step 1
    normalized = normalize_endpoint_scheme(decoded)       # step 2
    resolved = resolve_endpoint_from_cache(normalized)    # step 3
    # VULN-TC020: SSRF — endpoint attacker-controlled after 3-step chain
    response = requests.get(resolved, timeout=10)
    return JsonResponse({'data': response.text[:2000]})


# ===========================================================================
# Chains 21–30: further chains covering remaining patterns
# ===========================================================================

# Chain 21: parse XML field → extract text → build query (VULN-TC021)

def parse_xml_patient_id(xml_body: str) -> str:
    """Step 1: Extract patient_id from XML using naive string parsing."""
    match = re.search(r'<patient_id>([^<]+)</patient_id>', xml_body)
    return match.group(1) if match else ''


def validate_numeric_id(value: str) -> str:
    """Step 2: Validate that the value is numeric — returns original string."""
    if not value.isdigit():
        raise ValueError("patient_id must be numeric")
    return value  # VULN: original string (not int()) returned


@csrf_exempt
def xml_patient_lookup_chained(request):
    """VULN-TC021: parse_xml → validate_numeric → SQL injection (string not cast)."""
    xml_body = request.body.decode('utf-8', errors='replace')
    patient_id_str = parse_xml_patient_id(xml_body)    # step 1
    validated = validate_numeric_id(patient_id_str)    # step 2
    with connection.cursor() as c:
        c.execute(f"SELECT * FROM patients WHERE id={validated}")  # step 3 — injectable if isdigit() bypassed via unicode
        row = c.fetchone()
    return JsonResponse({'patient': row})


# Chain 22: strip quotes → encode for URL → use as path param (VULN-TC022)

def strip_quote_chars(value: str) -> str:
    """Step 1: Remove single and double quotes."""
    return value.replace("'", '').replace('"', '')


def encode_for_url_path(value: str) -> str:
    """Step 2: URL encode — then decoded by server, restoring traversal chars."""
    return urllib.parse.quote(value, safe='')


@csrf_exempt
def patient_file_indirect_chained(request):
    """VULN-TC022: strip_quotes → encode_url → path traversal.

    After stripping quotes, a payload like ../../../etc/passwd survives
    URL encoding and is decoded again by open().
    """
    raw_filename = request.GET.get('filename', '')
    stripped = strip_quote_chars(raw_filename)      # step 1
    encoded = encode_for_url_path(stripped)         # step 2
    decoded_path = urllib.parse.unquote(encoded)    # step 3 (server decode)
    full_path = '/var/medicore/files/' + decoded_path
    with open(full_path, 'rb') as fh:              # sink
        return HttpResponse(fh.read(), content_type='application/octet-stream')


# Chain 23: parse headers → build auth string → LDAP bind (VULN-TC023)

def parse_auth_header(auth_header: str) -> tuple:
    """Step 1: Parse a Basic auth header into username/password."""
    try:
        scheme, credentials = auth_header.split(' ', 1)
        decoded = base64.b64decode(credentials + '==').decode('utf-8')
        username, password = decoded.split(':', 1)
        return username, password
    except Exception:
        return '', ''


def build_ldap_dn(username: str, base_dn: str = 'dc=hospital,dc=internal') -> str:
    """Step 2: Construct an LDAP distinguished name from username."""
    return f"uid={username},ou=users,{base_dn}"


@csrf_exempt
def ldap_bind_chained(request):
    """VULN-TC023: parse_auth_header → build_ldap_dn → LDAP bind (LDAP injection)."""
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    username, password = parse_auth_header(auth_header)  # step 1
    ldap_dn = build_ldap_dn(username)                     # step 2

    import ldap3
    server = ldap3.Server('ldap://ldap.hospital.internal')
    # VULN-TC023: LDAP injection via username in constructed DN
    conn = ldap3.Connection(server, user=ldap_dn, password=password)
    conn.bind()
    return JsonResponse({'authenticated': conn.bound})


# Chain 24: session → deserialize → execute (VULN-TC024)

def load_session_bytes(session, key: str) -> bytes:
    """Step 1: Load raw bytes from session."""
    raw = session.get(key, b'')
    if isinstance(raw, str):
        return base64.b64decode(raw + '==')
    return raw


def deserialize_bytes(raw_bytes: bytes) -> object:
    """Step 2: Deserialize bytes — uses pickle."""
    import pickle as _pickle
    return _pickle.loads(raw_bytes)  # VULN: unsafe deserialization


@csrf_exempt
def execute_session_pipeline_chained(request):
    """VULN-TC024: load_session_bytes → deserialize (pickle.loads) → exec."""
    raw = load_session_bytes(request.session, 'pipeline_object')  # step 1
    if raw:
        pipeline = deserialize_bytes(raw)  # step 2 — RCE via pickle
        # step 3: execute the pipeline
        if hasattr(pipeline, 'run'):
            result = pipeline.run()
            return JsonResponse({'result': str(result)})
    return JsonResponse({'result': None})


# Chain 25: URL param → strip whitespace → insert into email header (VULN-TC025)

def extract_recipient(param: str) -> str:
    """Step 1: Extract recipient from URL parameter."""
    return param.strip()


def build_email_from_field(recipient: str) -> str:
    """Step 2: Construct the From header for the email."""
    return f"MediCore Notifications <{recipient}>"


@csrf_exempt
def send_notification_chained(request):
    """VULN-TC025: extract_recipient → build_from_field → SMTP header injection."""
    import smtplib
    raw_recipient = request.GET.get('to', '')
    recipient = extract_recipient(raw_recipient)      # step 1
    from_field = build_email_from_field(recipient)    # step 2 — injects headers via recipient

    smtp_conn = smtplib.SMTP('smtp.hospital.internal', 25)
    # VULN-TC025: header injection via crafted recipient
    message = (
        f"From: {from_field}\r\n"
        f"To: {recipient}\r\n"
        f"Subject: Appointment Reminder\r\n"
        f"\r\nYour appointment is scheduled."
    )
    smtp_conn.sendmail('noreply@hospital.org', recipient, message)
    smtp_conn.quit()
    return JsonResponse({'status': 'sent'})


# Chain 26: DB value → format string → os.popen (VULN-TC026)

def fetch_lab_command_template(lab_id: str) -> str:
    """Step 1: Retrieve command template from DB for a lab instrument."""
    with connection.cursor() as c:
        c.execute("SELECT command_template FROM lab_instruments WHERE id=%s", [lab_id])
        row = c.fetchone()
    return row[0] if row else 'echo {order_id}'


def apply_command_params(template: str, params: dict) -> str:
    """Step 2: Apply parameters to the command template."""
    return template.format(**params)  # VULN: format string from DB + user-controlled params


@csrf_exempt
def run_lab_command_chained(request):
    """VULN-TC026: fetch_db_template → apply_format_params → os.popen (RCE).

    The command template is stored in DB; params come from the request.
    A {__class__} format payload extracts data; a template like
    'curl {host}' lets the attacker control the host.
    """
    lab_id = request.GET.get('lab_id', '')
    order_id = request.GET.get('order_id', '')
    additional = request.GET.get('extra', '')

    template = fetch_lab_command_template(lab_id)          # step 1
    cmd = apply_command_params(template, {'order_id': order_id, 'extra': additional})  # step 2

    result = os.popen(cmd).read()  # step 3 — RCE
    return JsonResponse({'output': result})


# Chain 27: query param → HTML escape → insert as Jinja2 source (VULN-TC027)

def escape_for_display(value: str) -> str:
    """Step 1: HTML-escape for display — but result used as Jinja2 source."""
    return html.escape(value)


def wrap_in_template_block(escaped: str) -> str:
    """Step 2: Wrap value in a template display block — may include {{ }} syntax."""
    return f"<p>Patient: {escaped}</p>"


@csrf_exempt
def patient_badge_template_chained(request):
    """VULN-TC027: escape_html → wrap_template_block → Jinja2.from_string (SSTI).

    html.escape() converts ' to &#x27; but {{ and }} are not HTML special chars
    and pass through unchanged — SSTI payload {{ 7*7 }} is preserved.
    """
    patient_name = request.GET.get('name', '')
    escaped = escape_for_display(patient_name)     # step 1
    template_src = wrap_in_template_block(escaped) # step 2

    env = jinja2.Environment()
    rendered = env.from_string(template_src).render()  # step 3 — SSTI
    return HttpResponse(rendered, content_type='text/html')


# Chain 28: deserialize config → extract URL → proxy request (VULN-TC028)

def deserialize_config_from_request(request_body: bytes) -> dict:
    """Step 1: Parse JSON config from request body."""
    try:
        return json.loads(request_body.decode('utf-8'))
    except Exception:
        return {}


def extract_proxy_target(config: dict) -> str:
    """Step 2: Extract the proxy target URL from config."""
    return config.get('proxy_target', '')


def validate_https_scheme(url: str) -> str:
    """Step 3: Validate HTTPS — but internal http:// addresses bypass HTTPS check."""
    if url.startswith('https://'):
        return url
    if url.startswith('http://10.') or url.startswith('http://192.168.') or url.startswith('http://172.'):
        return url  # VULN: internal RFC1918 addresses allowed over HTTP
    raise ValueError("Only HTTPS URLs are allowed")


@csrf_exempt
def config_driven_proxy_chained(request):
    """VULN-TC028: deserialize_config → extract_url → validate_https → requests.get (SSRF)."""
    config = deserialize_config_from_request(request.body)    # step 1
    proxy_target = extract_proxy_target(config)               # step 2
    validated_url = validate_https_scheme(proxy_target)       # step 3 — allows internal IPs

    response = requests.get(validated_url, timeout=10)        # sink — SSRF
    return JsonResponse({'response': response.text[:2000]})


# Chain 29: template from cache → merge context → render (VULN-TC029)

def fetch_template_from_cache(template_id: str) -> str:
    """Step 1: Retrieve template source from Redis cache."""
    from django.core.cache import cache as _cache
    return _cache.get(f"tmpl:{template_id}", '{{ greeting }}')


def merge_template_context(context_json: str, defaults: dict) -> dict:
    """Step 2: Parse context JSON and merge with defaults."""
    try:
        user_context = json.loads(context_json)
    except json.JSONDecodeError:
        user_context = {}
    merged = {**defaults, **user_context}
    return merged


@csrf_exempt
def render_cached_notification_chained(request):
    """VULN-TC029: fetch_cache → merge_context → Jinja2 render (SSTI via cached template)."""
    template_id = request.GET.get('template_id', 'default')
    context_json = request.GET.get('context', '{}')

    template_src = fetch_template_from_cache(template_id)  # step 1
    context = merge_template_context(context_json, {'greeting': 'Hello'})  # step 2

    env = jinja2.Environment()
    rendered = env.from_string(template_src).render(**context)  # step 3 — SSTI
    return JsonResponse({'rendered': rendered})


# Chain 30: parse multipart → extract field → build INSERT (VULN-TC030)

def extract_multipart_field(request_body: bytes, boundary: str, field_name: str) -> str:
    """Step 1: Naive multipart field extraction — no Content-Disposition validation."""
    try:
        body_str = request_body.decode('utf-8', errors='replace')
        pattern = rf'name="{field_name}"\r\n\r\n(.*?)\r\n--'
        match = re.search(pattern, body_str, re.DOTALL)
        return match.group(1) if match else ''
    except Exception:
        return ''


def sanitize_multipart_value_weak(value: str) -> str:
    """Step 2: Weak sanitization — strips only backslash."""
    return value.replace('\\', '')


def build_clinical_note_insert(patient_id: str, note_content: str) -> str:
    """Step 3: Build INSERT SQL — note_content not escaped."""
    return (
        f"INSERT INTO clinical_notes (patient_id, note_content, created_at) "
        f"VALUES ('{patient_id}', '{note_content}', NOW())"
    )


@csrf_exempt
def upload_clinical_note_chained(request):
    """VULN-TC030: extract_multipart → weak_sanitize → build_insert → execute (SQLi)."""
    content_type = request.META.get('CONTENT_TYPE', '')
    boundary = content_type.split('boundary=')[-1] if 'boundary=' in content_type else ''

    patient_id = extract_multipart_field(request.body, boundary, 'patient_id')  # step 1a
    note_content = extract_multipart_field(request.body, boundary, 'note')      # step 1b
    sanitized_note = sanitize_multipart_value_weak(note_content)                # step 2
    insert_sql = build_clinical_note_insert(patient_id, sanitized_note)        # step 3

    with connection.cursor() as c:
        c.execute(insert_sql)  # sink — SQL injection
    return JsonResponse({'status': 'note_uploaded'})
