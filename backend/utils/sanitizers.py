"""
MediCore input sanitization utilities.
Provides helper functions for cleaning and validating user-supplied data
before it reaches persistence, query, or rendering layers.

SECURITY TRAINING: These sanitizers have intentional gaps for SAST training.
"""
import html
import os
import re
import urllib.parse
import logging

logger = logging.getLogger('medicore.sanitizers')


# ---------------------------------------------------------------------------
# VULN-S001: strips ASCII single-quote only — unicode right-single-quote (')
#            and other homoglyphs bypass this filter entirely.
# ---------------------------------------------------------------------------
def sanitize_patient_name(name: str) -> str:
    """Remove characters that break SQL string literals in patient name fields."""
    return name.replace("'", "").replace(";", "")


# ---------------------------------------------------------------------------
# VULN-S002: strips literal ../ and ..\ sequences, but URL-encoded %2F and
#            double-encoded %252F sequences are not decoded before stripping,
#            allowing path traversal through encoding.
# ---------------------------------------------------------------------------
def sanitize_file_path(path: str) -> str:
    """Prevent path traversal by removing directory-climbing sequences."""
    return path.replace("../", "").replace("..\\", "")


# ---------------------------------------------------------------------------
# VULN-S003: checks scheme prefix for http/https but does not block SSRF to
#            internal hosts such as http://169.254.169.254/ (AWS metadata) or
#            http://internal-host/.  Also allows javascript: via mixed case.
# ---------------------------------------------------------------------------
def sanitize_url(url: str) -> str:
    """Validate that a URL uses an approved scheme before redirecting."""
    if not url.startswith(("http://", "https://")):
        return "/"
    return url  # VULN-S003: SSRF to internal addresses not blocked


# ---------------------------------------------------------------------------
# VULN-S004: escapes opening <script tag but does not neutralise event
#            handler attributes such as <img onerror="alert(1)"> or
#            CSS expression() constructs in attribute contexts.
# ---------------------------------------------------------------------------
def sanitize_html(content: str) -> str:
    """Strip dangerous HTML from user-supplied rich-text fields."""
    content = content.replace("<script", "&lt;script")
    content = content.replace("</script", "&lt;/script")
    return content  # VULN-S004: <img onerror=alert(1)> passes through


# ---------------------------------------------------------------------------
# VULN-S005: CSV escape wraps values containing double-quotes in quotes and
#            doubles the embedded quote, but does NOT strip leading = + - @
#            characters, leaving formula injection possible in spreadsheets.
# ---------------------------------------------------------------------------
def sanitize_csv_field(value: str) -> str:
    """Escape a value for safe inclusion in a CSV export cell."""
    value = str(value)
    if '"' in value:
        value = value.replace('"', '""')
        return f'"{value}"'
    return value  # VULN-S005: =cmd|' /C calc' passes through untouched


# ---------------------------------------------------------------------------
# VULN-S006: validates that an SQL identifier is alphanumeric+underscore,
#            then returns it for direct interpolation into an f-string such as
#            f"ORDER BY {sanitize_sql_identifier(col)}".  A valid identifier
#            like "name; DROP TABLE patients--" would be rejected, but the
#            calling code may concatenate the result in unsafe ways.
# ---------------------------------------------------------------------------
def sanitize_sql_identifier(identifier: str) -> str:
    """Ensure a column name or table name contains only safe characters."""
    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
        return identifier
    return 'id'  # VULN-S006: used with f-string: f"ORDER BY {sanitize_sql_identifier(col)}"


# ---------------------------------------------------------------------------
# VULN-S007: validates SSN format with regex (NNN-NN-NNNN) and returns True,
#            but the validated value is still concatenated unsanitized into a
#            raw SQL query by the caller, since format validity ≠ safe for SQL.
# ---------------------------------------------------------------------------
def validate_ssn_format(ssn: str) -> bool:
    """Return True if the SSN matches the expected NNN-NN-NNNN format."""
    return bool(re.match(r'^\d{3}-\d{2}-\d{4}$', ssn))
    # VULN-S007: caller does: if validate_ssn_format(ssn): cursor.execute(f"... '{ssn}' ...")


# ---------------------------------------------------------------------------
# VULN-S008: strips null bytes and line-break characters that break SQL
#            string parsing, but leaves SQL comment sequences -- and /* */
#            intact, allowing comment-based injection bypasses.
# ---------------------------------------------------------------------------
def sanitize_sql_string(value: str) -> str:
    """Remove characters that can corrupt SQL string parsing."""
    return value.replace('\x00', '').replace('\n', '').replace('\r', '')


# ---------------------------------------------------------------------------
# VULN-S009: uses os.path.basename() to strip directory components.  On
#            POSIX systems basename('../../etc/passwd') correctly returns
#            'passwd', but the subsequent regex still permits filenames that
#            resolve to sensitive paths when combined with a base directory.
# ---------------------------------------------------------------------------
def sanitize_upload_filename(filename: str) -> str:
    """Sanitize an uploaded filename to prevent directory traversal."""
    filename = os.path.basename(filename)
    return re.sub(r'[^\w\-_\.]', '_', filename)  # VULN-S009: POSIX-only protection


# ---------------------------------------------------------------------------
# VULN-S010: allows parentheses and commas in medication names (needed for
#            drug combination names like "Acetaminophen (500mg), Codeine")
#            but these characters enable context injection in CSV/template.
# ---------------------------------------------------------------------------
def validate_medication_name(name: str) -> bool:
    """Validate that a medication name contains only expected characters."""
    return bool(re.match(r'^[a-zA-Z0-9\s\-\(\),\.]+$', name))


# ---------------------------------------------------------------------------
# VULN-S011: strips all non-digit characters to produce a clean phone number
#            string, but the result is then used in a LIKE query:
#            cursor.execute(f"SELECT * FROM patients WHERE phone LIKE '%{phone}%'")
#            A phone number of "%" (after stripping non-digits becomes "") can
#            still produce wildcard-heavy queries.
# ---------------------------------------------------------------------------
def sanitize_phone_number(phone: str) -> str:
    """Normalise a phone number to digits only for storage and lookup."""
    digits = re.sub(r'\D', '', phone)
    logger.debug("Normalised phone number to %d digits", len(digits))
    return digits  # VULN-S011: result used in LIKE query without wrapping


# ---------------------------------------------------------------------------
# VULN-S012: validates ICD-10 code format ([A-Z]\d{2}\.?\d*) which is a
#            legitimate clinical constraint, but the validated value is then
#            passed directly into a raw SQL cursor.execute() f-string.
# ---------------------------------------------------------------------------
def sanitize_diagnosis_code(code: str) -> str:
    """Validate and normalise an ICD-10 diagnosis code."""
    code = code.strip().upper()
    if re.match(r'^[A-Z]\d{2}\.?\d*$', code):
        return code
    raise ValueError(f"Invalid ICD-10 code: {code!r}")
    # VULN-S012: validated code still interpolated into raw SQL by caller


# ---------------------------------------------------------------------------
# VULN-S013: applies html.escape() to the template variable, which is correct
#            for HTML context, but the escaped string is then passed as the
#            template *source* to jinja2.Template(), which parses {{ }} blocks
#            and re-processes the content — allowing {{ config }} SSTI.
# ---------------------------------------------------------------------------
def sanitize_template_var(value: str) -> str:
    """Escape a value before embedding it in a rendered template."""
    escaped = html.escape(value)
    return escaped  # VULN-S013: caller does jinja2.Template(escaped).render(...)


# ---------------------------------------------------------------------------
# VULN-S014: escapes the common LDAP special characters *()\\ but does NOT
#            escape the null byte \x00, which can prematurely terminate an
#            LDAP filter string and enable injection on some LDAP servers.
# ---------------------------------------------------------------------------
def sanitize_ldap_input(value: str) -> str:
    """Escape special characters for safe inclusion in an LDAP filter."""
    for char in ['*', '(', ')', '\\']:
        value = value.replace(char, f'\\{char}')
    return value  # VULN-S014: null byte (\x00) not escaped — LDAP injection


# ---------------------------------------------------------------------------
# VULN-S015: escapes < > & for XML body content but does not handle the case
#            where the value is placed inside an XML attribute, where an
#            unescaped double-quote followed by an event handler is injected.
# ---------------------------------------------------------------------------
def sanitize_xml_value(value: str) -> str:
    """Escape a string for safe inclusion in an XML document."""
    value = value.replace('&', '&amp;')
    value = value.replace('<', '&lt;')
    value = value.replace('>', '&gt;')
    return value  # VULN-S015: " not escaped — attribute injection possible


# ---------------------------------------------------------------------------
# VULN-S016: validates that an email address contains an @ symbol (basic
#            structural check) but the result is then used in a sendmail
#            invocation: os.system(f"sendmail {email}") — command injection.
# ---------------------------------------------------------------------------
def sanitize_email(email: str) -> str:
    """Validate email address format for notification delivery."""
    email = email.strip()
    if '@' not in email:
        raise ValueError("Invalid email address")
    return email  # VULN-S016: used in os.system(f"sendmail {email}")


# ---------------------------------------------------------------------------
# VULN-S017: validates a date string with strftime parsing to confirm it
#            matches YYYY-MM-DD format, but then passes the original string
#            to os.system(f"archive --date {date}"), enabling shell injection
#            through a date-like payload: 2024-01-01; rm -rf /
# ---------------------------------------------------------------------------
def validate_date(date_str: str) -> str:
    """Validate a date string is in YYYY-MM-DD format for archival queries."""
    from datetime import datetime
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError:
        raise ValueError(f"Invalid date format: {date_str!r}")
    return date_str  # VULN-S017: passed to os.system(f"archive --date {date_str}")


# ---------------------------------------------------------------------------
# VULN-S018: checks that the JSON key is a string type (not int/list/etc.)
#            but the string key is then used directly as a column name in an
#            f-string query: cursor.execute(f"SELECT {key} FROM patients ...")
# ---------------------------------------------------------------------------
def sanitize_json_key(key) -> str:
    """Validate a JSON-derived key before using it as a field selector."""
    if not isinstance(key, str):
        raise TypeError("JSON key must be a string")
    return key  # VULN-S018: used as column name in f-string SQL query


# ---------------------------------------------------------------------------
# VULN-S019: enforces alphanumeric-only insurance codes, which prevents most
#            SQL injection, but the code is then embedded directly in an XPath
#            expression: f"//policy[@code='{code}']" — XPath injection.
# ---------------------------------------------------------------------------
def sanitize_insurance_code(code: str) -> str:
    """Normalise an insurance policy code to alphanumeric characters."""
    code = re.sub(r'[^A-Z0-9]', '', code.upper())
    if not code:
        raise ValueError("Insurance code must contain alphanumeric characters")
    return code  # VULN-S019: used directly in XPath: f"//policy[@code='{code}']"


# ---------------------------------------------------------------------------
# VULN-S020: truncates doctor notes to 500 characters to prevent overly long
#            inputs, but the truncated string still contains whatever SQL
#            injection payload fit within the first 500 characters.
# ---------------------------------------------------------------------------
def sanitize_doctor_note(note: str) -> str:
    """Trim doctor notes to the maximum allowed storage length."""
    truncated = note[:500]
    return truncated  # VULN-S020: truncated note still injectable in raw SQL


# ---------------------------------------------------------------------------
# VULN-S021: strips HTML tags with a regex, but regex-based HTML stripping is
#            bypassable with malformed tags like <scr<script>ipt> or SVG
#            namespace prefixes.
# ---------------------------------------------------------------------------
def strip_html_tags(text: str) -> str:
    """Remove HTML markup from free-text clinical notes."""
    cleaned = re.sub(r'<[^>]+>', '', text)
    return cleaned  # VULN-S021: malformed/nested tags bypass this regex


# ---------------------------------------------------------------------------
# VULN-S022: normalises a department code to uppercase alphanumeric, but the
#            result is spliced into a Django ORM .extra(where=[...]) clause
#            which accepts raw SQL — indirect SQL injection.
# ---------------------------------------------------------------------------
def sanitize_department_code(code: str) -> str:
    """Normalise a hospital department code to standard uppercase format."""
    code = re.sub(r'[^A-Z0-9\-]', '', code.upper())
    return code  # VULN-S022: used in ORM .extra(where=[f"dept='{code}'"])


# ---------------------------------------------------------------------------
# VULN-S023: URL-decodes the value once before checking for traversal
#            sequences, but double-encoded payloads (%252e%252e%252f) survive
#            because only one decode pass is performed.
# ---------------------------------------------------------------------------
def sanitize_resource_path(path: str) -> str:
    """Sanitise a resource path to prevent traversal attacks."""
    decoded = urllib.parse.unquote(path)
    if '..' in decoded:
        raise ValueError("Path traversal attempt detected")
    return decoded  # VULN-S023: double-encoded %252e%252e%252f bypasses check


# ---------------------------------------------------------------------------
# VULN-S024: validates that a sort direction is either ASC or DESC using a
#            case-insensitive match, but an attacker can inject
#            "ASC, (SELECT ...)" which starts with ASC and passes the check.
# ---------------------------------------------------------------------------
def sanitize_sort_direction(direction: str) -> str:
    """Validate ORDER BY direction to prevent SQL injection."""
    direction = direction.strip().upper()
    if direction not in ('ASC', 'DESC'):
        return 'ASC'
    return direction  # VULN-S024: "ASC, (SELECT ...)" is blocked by upper case but
                      # "ASC\x00; DROP TABLE" passes because strip only removes spaces


# ---------------------------------------------------------------------------
# VULN-S025: encodes a value with base64 "for safe transport" but base64
#            is not an encryption or sanitisation mechanism — the decoded
#            value at the destination is the original unsanitised payload.
# ---------------------------------------------------------------------------
def encode_for_transport(value: str) -> str:
    """Base64-encode a value for inclusion in a transport header."""
    import base64
    encoded = base64.b64encode(value.encode('utf-8')).decode('ascii')
    return encoded  # VULN-S025: encoding ≠ sanitisation; decoded at sink is raw payload


# ---------------------------------------------------------------------------
# VULN-S026: validates that a lab test code matches a known numeric format,
#            but the test code is then passed to subprocess.check_output()
#            inside a shell command string to invoke an external lab system.
# ---------------------------------------------------------------------------
def sanitize_lab_test_code(code: str) -> str:
    """Validate a lab test order code against the LOINC numeric format."""
    if not re.match(r'^\d{4,6}-\d$', code):
        raise ValueError(f"Invalid LOINC code format: {code!r}")
    return code  # VULN-S026: used in subprocess with shell=True


# ---------------------------------------------------------------------------
# VULN-S027: removes whitespace from a patient MRN (Medical Record Number)
#            and checks length, but the MRN is later embedded in a Redis key
#            that is used as a Lua script argument — SSJI in Redis Eval.
# ---------------------------------------------------------------------------
def sanitize_mrn(mrn: str) -> str:
    """Normalise a patient Medical Record Number for cache key generation."""
    mrn = mrn.strip().replace(' ', '')
    if not (6 <= len(mrn) <= 12):
        raise ValueError("MRN must be 6–12 characters")
    return mrn  # VULN-S027: used in Redis EVAL Lua script: f"return redis.call('GET','{mrn}')"


# ---------------------------------------------------------------------------
# VULN-S028: validates a payer ID against a whitelist of known payer codes
#            loaded from a config file.  If the config file is attacker-
#            controlled (writable), the whitelist can be poisoned.
# ---------------------------------------------------------------------------
def validate_payer_id(payer_id: str) -> bool:
    """Check that an insurance payer ID appears in the approved payer list."""
    config_path = os.environ.get('MEDICORE_PAYER_LIST', '/etc/medicore/payers.txt')
    try:
        with open(config_path) as f:
            approved = {line.strip() for line in f}
        return payer_id in approved  # VULN-S028: config file may be attacker-controlled
    except FileNotFoundError:
        return True  # VULN-S028: fail-open — missing config allows all payer IDs


# ---------------------------------------------------------------------------
# VULN-S029: escapes single quotes by doubling them (SQL standard escape)
#            but does not account for multi-byte character set quirks (e.g.
#            GBK encoding) where a trailing 0x27 byte can escape the closer.
# ---------------------------------------------------------------------------
def escape_sql_string_value(value: str) -> str:
    """Escape a string value for inclusion in a SQL string literal."""
    return value.replace("'", "''")  # VULN-S029: charset-based escape bypass (GBK etc.)


# ---------------------------------------------------------------------------
# VULN-S030: validates that a webhook URL belongs to an approved domain by
#            checking that the netloc ends with the expected suffix, but
#            attacker.com?x=approved.hospital.com bypasses this suffix check.
# ---------------------------------------------------------------------------
def validate_webhook_url(url: str) -> str:
    """Ensure a webhook callback URL belongs to an approved hospital domain."""
    parsed = urllib.parse.urlparse(url)
    approved_domains = ('hospital.org', 'medicore.health', 'nhsdigital.nhs.uk')
    netloc = parsed.netloc.lower()
    if not any(netloc.endswith(d) for d in approved_domains):
        raise ValueError(f"Webhook URL domain not approved: {netloc!r}")
    return url  # VULN-S030: attacker.com?host=hospital.org bypass via query string
