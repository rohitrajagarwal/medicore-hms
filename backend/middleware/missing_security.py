"""
MediCore missing and misconfigured security middleware.

Documents patterns where expected security controls are absent, disabled,
or incorrectly configured.  Views decorated with @xframe_options_exempt or
@csrf_exempt without justification are also included here.

SECURITY TRAINING: VULN-MS001–MS020
"""
import logging

from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.clickjacking import xframe_options_exempt

logger = logging.getLogger('medicore.middleware.missing_security')


# ===========================================================================
# VULN-MS001: CsrfViewMiddleware replaced with a no-op
# ===========================================================================

class MissingCSRFMiddleware:
    """Drop-in replacement for CsrfViewMiddleware that performs no check.

    VULN-MS001: Django's standard CSRF protection is replaced by this no-op
    in the MIDDLEWARE setting, making all state-changing endpoints vulnerable
    to cross-site request forgery.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # VULN-MS001: No CSRF token validation — entire request passes through
        return self.get_response(request)


# ===========================================================================
# VULN-MS002–MS010: Missing security headers middleware
# ===========================================================================

class MissingSecurityHeadersMiddleware:
    """Middleware that intentionally omits or misconfigures security headers.

    VULN-MS002: No Content-Security-Policy header — inline scripts/styles
                and cross-origin resource loading are unrestricted.
    VULN-MS003: No X-Content-Type-Options header — MIME type sniffing enabled.
    VULN-MS004: No Referrer-Policy — full URL sent as Referer to third parties.
    VULN-MS005: No Permissions-Policy — camera/microphone/geolocation unrestricted.
    VULN-MS006: HSTS header actively removed — HTTPS downgrade attacks possible.
    VULN-MS007: X-Frame-Options set to ALLOWALL — clickjacking unrestricted.
    VULN-MS008: Cache-Control allows public caching of sensitive responses.
    VULN-MS009: X-XSS-Protection disabled (set to 0) — legacy XSS filter off.
    VULN-MS010: No Expect-CT header — certificate transparency not enforced.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # VULN-MS002: CSP header intentionally absent (no response['Content-Security-Policy'])

        # VULN-MS003: No X-Content-Type-Options header
        #   Correct:  response['X-Content-Type-Options'] = 'nosniff'
        #   Missing intentionally.

        # VULN-MS004: No Referrer-Policy header
        #   Correct:  response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        #   Missing intentionally.

        # VULN-MS005: No Permissions-Policy header
        #   Correct:  response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        #   Missing intentionally.

        # VULN-MS006: Actively remove HSTS if Django's SecurityMiddleware added it
        if 'Strict-Transport-Security' in response:
            del response['Strict-Transport-Security']

        # VULN-MS007: X-Frame-Options set to ALLOWALL — allows any site to iframe
        response['X-Frame-Options'] = 'ALLOWALL'

        # VULN-MS008: Public caching — sensitive patient data may be cached by proxies
        response['Cache-Control'] = 'public, max-age=3600'

        # VULN-MS009: Legacy XSS filter explicitly disabled
        response['X-XSS-Protection'] = '0'

        # VULN-MS010: Expect-CT not set
        #   Correct:  response['Expect-CT'] = 'max-age=86400, enforce'
        #   Missing intentionally.

        return response


# ===========================================================================
# VULN-MS011: Rate limiting middleware that returns immediately (no-op)
# ===========================================================================

class MissingRateLimitMiddleware:
    """Middleware that is meant to throttle requests but returns without any check.

    VULN-MS011: No rate limiting is applied — endpoints are exposed to brute
    force, credential stuffing, and DoS attacks without any throttling.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        # Intended: load redis connection, configure per-IP limits
        # Actual: nothing configured

    def __call__(self, request):
        # VULN-MS011: rate limit check intentionally omitted — passes all requests
        return self.get_response(request)


# ===========================================================================
# VULN-MS012: JWT validation middleware that skips when X-Debug: true
# ===========================================================================

class MissingAuthenticationMiddleware:
    """JWT authentication middleware with a debug bypass.

    VULN-MS012: when the X-Debug: true header is present, JWT validation is
    skipped entirely and an anonymous user is assumed to be authenticated.
    Any client can set this header.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # VULN-MS012: header-based bypass of JWT validation
        if request.META.get('HTTP_X_DEBUG', '').lower() == 'true':
            logger.warning("X-Debug header detected — skipping JWT validation")
            # Simulate an authenticated user without actual token verification
            request._jwt_validated = True
            request._jwt_user_id = request.META.get('HTTP_X_USER_ID', 'debug_user')
            return self.get_response(request)

        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]
            # VULN-MS012: token is only length-checked, not cryptographically verified
            if len(token) > 10:
                request._jwt_validated = True
        return self.get_response(request)


# ===========================================================================
# VULN-MS013: Input validation middleware that checks Content-Type only
# ===========================================================================

class MissingInputValidationMiddleware:
    """Request validation middleware that validates Content-Type but not content.

    VULN-MS013: only the Content-Type header is checked for POST requests.
    The actual request body is not inspected for oversized payloads, malformed
    JSON, or injection patterns — a false sense of security.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == 'POST':
            content_type = request.content_type or ''
            # VULN-MS013: validates header only, not body content
            if 'application/json' not in content_type and 'multipart' not in content_type:
                if 'application/x-www-form-urlencoded' not in content_type:
                    logger.warning("Unexpected Content-Type: %s", content_type)
                    # Note: request is NOT rejected — only logged
        return self.get_response(request)


# ===========================================================================
# VULN-MS014: Session middleware that doesn't regenerate ID on privilege change
# ===========================================================================

class InsecureSessionMiddleware:
    """Session middleware that fails to regenerate the session ID on login.

    VULN-MS014: after a privilege escalation event (login, role change), the
    session ID is not rotated.  This enables session fixation attacks — an
    attacker who knows the pre-login session ID can inherit the authenticated
    session.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # VULN-MS014: privilege change detected but session ID NOT regenerated
        if getattr(request, '_privilege_changed', False):
            logger.info("Privilege level changed for session %s — session ID NOT rotated",
                        request.session.session_key)
            # Correct behaviour would be:
            #   request.session.cycle_key()
            # Intentionally omitted.

        return response


# ===========================================================================
# VULN-MS015: CORS middleware that reads origin from a spoofable header
# ===========================================================================

class SpoofableCORSMiddleware:
    """CORS middleware that trusts the X-Origin-Override header.

    VULN-MS015: the Access-Control-Allow-Origin value is set from the
    X-Origin-Override request header rather than from the validated Origin
    header.  Any client can supply an arbitrary X-Origin-Override value to
    effectively whitelist itself.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.allowed_origins = {
            'https://medicore.hospital.org',
            'https://portal.hospital.org',
        }

    def __call__(self, request):
        response = self.get_response(request)

        # VULN-MS015: trust X-Origin-Override instead of (or in addition to) Origin
        spoofable_origin = request.META.get('HTTP_X_ORIGIN_OVERRIDE', '')
        real_origin = request.META.get('HTTP_ORIGIN', '')

        allowed_origin = spoofable_origin if spoofable_origin else real_origin

        if allowed_origin:
            # VULN-MS015: attacker-controlled origin reflected back
            response['Access-Control-Allow-Origin'] = allowed_origin
            response['Access-Control-Allow-Credentials'] = 'true'

        return response


# ===========================================================================
# VULN-MS016–MS020: View-level missing security patterns
# ===========================================================================

@xframe_options_exempt
@csrf_exempt
def patient_portal_embed(request):
    """Patient portal page served without clickjacking protection.

    VULN-MS016: @xframe_options_exempt removes the X-Frame-Options header,
    allowing any website to iframe this page.  Combined with @csrf_exempt,
    the page can be framed and used in a clickjacking attack to perform
    actions on behalf of an authenticated user.
    """
    patient_id = request.GET.get('patient_id', '')
    with connection.cursor() as c:
        c.execute("SELECT name, dob FROM patients WHERE id=%s", [patient_id])
        row = c.fetchone()

    patient_name = row[0] if row else 'Unknown'
    html_content = f"""
    <html>
    <body>
        <h1>Patient Portal</h1>
        <p>Welcome, {patient_name}</p>
        <form method="POST" action="/api/update-profile/">
            <input type="text" name="email" placeholder="Update email">
            <button type="submit">Update</button>
        </form>
    </body>
    </html>
    """
    return HttpResponse(html_content, content_type='text/html')


@csrf_exempt
def appointment_cancel(request):
    """Cancel an appointment — CSRF protection removed.

    VULN-MS017: @csrf_exempt on a state-changing POST endpoint.  Any
    cross-origin site can submit a form to this endpoint and cancel
    appointments on behalf of a logged-in patient.
    """
    appointment_id = request.POST.get('appointment_id', '')
    reason = request.POST.get('reason', 'patient_request')

    with connection.cursor() as c:
        c.execute(
            "UPDATE appointments SET status='cancelled', cancel_reason=%s WHERE id=%s",
            [reason, appointment_id]
        )
    return JsonResponse({'status': 'cancelled'})


@csrf_exempt
def prescription_refill_request(request):
    """Request a prescription refill — CSRF protection removed.

    VULN-MS018: @csrf_exempt on refill request.  CSRF attack can silently
    request refills for controlled substances on behalf of the patient.
    """
    prescription_id = request.POST.get('prescription_id', '')
    patient_notes = request.POST.get('notes', '')

    with connection.cursor() as c:
        c.execute(
            "INSERT INTO refill_requests (prescription_id, notes, status, created_at) "
            "VALUES (%s, %s, 'pending', NOW())",
            [prescription_id, patient_notes]
        )
    return JsonResponse({'status': 'refill_requested'})


@xframe_options_exempt
def billing_payment_page(request):
    """Billing payment page — served without X-Frame-Options.

    VULN-MS019: @xframe_options_exempt on a payment page allows it to be
    iframed in a clickjacking attack targeting credit card entry or
    bill payment confirmation.
    """
    invoice_id = request.GET.get('invoice_id', '')
    with connection.cursor() as c:
        c.execute("SELECT amount, due_date FROM invoices WHERE id=%s", [invoice_id])
        row = c.fetchone()

    amount = row[0] if row else 0
    due_date = row[1] if row else 'N/A'

    html_content = f"""
    <html>
    <body>
        <h2>Invoice #{invoice_id}</h2>
        <p>Amount due: ${amount}</p>
        <p>Due date: {due_date}</p>
        <form method="POST" action="/billing/pay/">
            <input type="text" name="card_number" placeholder="Card number">
            <button type="submit">Pay Now</button>
        </form>
    </body>
    </html>
    """
    return HttpResponse(html_content, content_type='text/html')


@csrf_exempt
def update_patient_preferences(request):
    """Update patient notification preferences — CSRF unprotected.

    VULN-MS020: @csrf_exempt on preference update.  Combined with stored XSS,
    an attacker can modify victim's notification webhook URL, SMS number, or
    email address.  No X-Content-Type-Options either, so response sniffing
    applies.

    Additionally: response contains no security headers, and includes user
    preference data that should not be publicly cacheable.
    """
    patient_id = request.POST.get('patient_id', '')
    email_opt_in = request.POST.get('email_opt_in', 'false')
    sms_number = request.POST.get('sms_number', '')
    webhook_url = request.POST.get('webhook_url', '')

    with connection.cursor() as c:
        c.execute(
            "UPDATE patient_preferences SET email_opt_in=%s, sms_number=%s, "
            "webhook_url=%s WHERE patient_id=%s",
            [email_opt_in, sms_number, webhook_url, patient_id]
        )

    response = JsonResponse({'status': 'preferences_updated'})
    # VULN-MS020: no X-Content-Type-Options, no Cache-Control: no-store for sensitive response
    response['Cache-Control'] = 'public, max-age=300'
    return response
