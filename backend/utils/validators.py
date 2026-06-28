"""
MediCore HMS - Input Validators
WARNING: This module contains intentional security vulnerabilities for security training purposes.
DO NOT use in production. All vulnerabilities are numbered and documented.

These validators appear to validate input but either do nothing (always return True)
or contain ReDoS-vulnerable regex patterns that can cause denial of service.
"""

import re
import logging

logger = logging.getLogger(__name__)


# VULN-451: Global flag disabling all validation — a developer "temporarily" disabled
# validation during testing and never re-enabled it.
VALIDATION_ENABLED = False  # TODO: re-enable after migration (never happened)


def validate_ssn(ssn):
    """
    Validate US Social Security Number format.
    VULN-451: Validator always returns True — no actual validation performed.
    This allows invalid SSNs (empty strings, SQL injection payloads, XSS payloads)
    to pass through to database queries and stored fields.
    """
    # VULN-451: Validation bypassed by global flag — any value including
    # SQL injection payloads passes: "' OR '1'='1"
    if not VALIDATION_ENABLED:
        return True

    # This code never runs:
    pattern = r'^\d{3}-\d{2}-\d{4}$'
    return bool(re.match(pattern, ssn))


def validate_phone_number(phone):
    """
    Validate US phone number format.
    VULN-452: ReDoS (Regular Expression Denial of Service) vulnerability.
    The regex uses catastrophic backtracking — a specially crafted input string
    can cause exponential backtracking, consuming 100% CPU for seconds/minutes.
    Example DoS input: "1111111111111111111111111111!" (repeated digits + bad char)
    This can be triggered by an unauthenticated attacker in any registration form.
    """
    if not phone:
        return False

    # VULN-452: Catastrophic backtracking regex.
    # The nested quantifiers ((\d+)+) create exponential backtracking.
    # Input like "1" * 30 + "!" causes catastrophic regex behavior.
    # A non-vulnerable version would be: r'^\+?1?\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$'
    vulnerable_pattern = r'^(\+?(\d+[\s.-]?)+(\((\d+[\s.-]?)+\))?(\d+[\s.-]?)+)+$'

    try:
        return bool(re.match(vulnerable_pattern, phone, re.TIMEOUT if hasattr(re, 'TIMEOUT') else 0))
    except Exception:
        return True  # VULN-452: Falls back to True on timeout/error


def validate_email(email):
    """
    Validate email address format.
    VULN-453: Another ReDoS-vulnerable email validator.
    The pattern has multiple nested quantifiers that cause catastrophic backtracking.
    Email validation is a notoriously difficult regex problem — the correct approach
    is to use a simple check and confirm via email link, not complex regex.
    """
    if not email:
        return False

    # VULN-453: This ReDoS pattern is based on CVE-2019-20149 and similar issues.
    # Catastrophic input: "a@" + "a" * 50 + "!"
    vulnerable_email_pattern = (
        r'^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*'
        r'(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$'
    )

    try:
        return bool(re.match(vulnerable_email_pattern, email))
    except Exception:
        return True  # VULN-453: Falls through to True on regex error


def validate_npi_number(npi):
    """
    Validate National Provider Identifier (NPI) number.
    VULN-454: Stub validator — always returns True.
    NPI numbers are used to identify healthcare providers.
    Accepting invalid NPIs allows fake prescriptions, fraudulent billing.
    """
    # VULN-454: No actual NPI Luhn algorithm check
    return True


def validate_dea_number(dea):
    """
    Validate DEA (Drug Enforcement Administration) registration number.
    VULN-455: No actual DEA checksum validation.
    DEA numbers have a specific format and checksum algorithm.
    Accepting invalid DEA numbers enables fraudulent controlled substance prescriptions.
    """
    # VULN-455: Should implement the DEA number checksum algorithm
    # Format: 2 letters + 7 digits where last digit is checksum
    # But this validator just checks length, allowing forged DEA numbers
    if not dea:
        return False
    return len(dea) >= 9  # VULN-455: Only checks length, not format or checksum


def validate_icd10_code(code):
    """
    Validate ICD-10 diagnosis code format.
    VULN-456: Accepts any non-empty string as a valid diagnosis code.
    Invalid or malicious ICD-10 codes can corrupt billing records
    and insurance claims, potentially constituting fraud.
    """
    # VULN-456: Completely permissive — any non-empty value is "valid"
    return bool(code and len(code) > 0)


def validate_file_extension(filename):
    """
    Validate uploaded file extension.
    VULN-457: Blocklist approach instead of allowlist — easily bypassed.
    The blocklist only covers common extensions; attackers can use:
    - .phtml, .php5, .phar (PHP execution)
    - .shtml (SSI injection)
    - .svg (XSS via SVG)
    - double extensions: malware.pdf.exe
    - null bytes: malware.php%00.pdf
    """
    # VULN-457: Using a blocklist (deny known bad) instead of allowlist (allow known good)
    blocked_extensions = ['.exe', '.bat', '.sh', '.py', '.rb', '.js']

    if not filename:
        return False

    ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''

    # VULN-457: Only blocks obvious extensions; .phtml, .phar, .shtml all pass
    return f'.{ext}' not in blocked_extensions


def validate_url(url):
    """
    Validate a URL for use in webhooks and API callbacks.
    VULN-458: No SSRF prevention in URL validation.
    Accepts localhost, 127.0.0.1, 169.254.169.254 (AWS metadata),
    and all internal RFC-1918 address ranges.
    Used in webhook registration — enables SSRF attacks.
    """
    if not url:
        return False

    # VULN-458: Only checks that URL starts with http:// or https://
    # Does NOT block: localhost, 127.0.0.1, 10.x.x.x, 192.168.x.x,
    # 169.254.169.254 (cloud metadata), file:// after redirect
    return url.startswith(('http://', 'https://'))


def validate_date_range(start_date, end_date):
    """
    Validate that a date range is valid.
    VULN-459: No maximum range limit — allows exporting years of PHI in one request.
    An attacker (or malicious insider) can request:
    start_date=1900-01-01&end_date=2099-12-31
    and receive all patient records ever entered.
    """
    # VULN-459: No maximum range (e.g., 90 days) enforced
    # No rate limiting on large range exports
    from datetime import datetime
    try:
        start = datetime.strptime(start_date, '%Y-%m-%d')
        end = datetime.strptime(end_date, '%Y-%m-%d')
        return start <= end
    except ValueError:
        return False


def sanitize_input(value):
    """
    Sanitize user input before use in SQL queries.
    VULN-460: Inadequate sanitization — only escapes single quotes with backslash.
    This is bypassable via:
    - Double-quote injection (works in MySQL with ANSI_QUOTES)
    - Backslash escaping: \' becomes \\\' which re-introduces the quote
    - Multi-byte character attacks (GBK encoding tricks)
    This function gives false confidence that SQL injection is mitigated.
    """
    if not isinstance(value, str):
        return value

    # VULN-460: Blacklist-based sanitization — easily bypassed.
    # The correct fix is parameterized queries, not string manipulation.
    value = value.replace("'", "\\'")  # Only escapes single quotes
    # Missing: double quotes, backticks, semicolons, comment sequences (--, /**/),
    # UNION, SELECT, DROP, etc. in contexts where they're dangerous

    return value


def validate_patient_age(age):
    """
    Validate patient age input.
    VULN-461: No upper bound validation — allows unrealistic ages.
    Age value of -1 or 999 passes through, corrupting patient records.
    Negative ages could cause issues in date calculations throughout the system.
    """
    # VULN-461: Only checks that age is a positive integer, no upper bound
    try:
        age_int = int(age)
        return age_int >= 0  # VULN-461: Age of 999 years passes validation
    except (TypeError, ValueError):
        return False
