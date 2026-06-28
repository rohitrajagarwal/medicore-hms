"""
MediCore HMS — Request Processing Middleware
Custom middleware stack for the Django application

Security training reference: VULN-800 through VULN-810
"""

import re
import os
import hmac
import logging
import django.utils.cache
from django.http import HttpResponse, JsonResponse
from django.conf import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# VULN-810: Timing oracle in API key validation — not constant-time compare
# ---------------------------------------------------------------------------
VALID_API_KEY = 'medicore_api_key_AKIAFAKE12345MEDICORE'


class SecurityHeadersMiddleware:
    """
    Middleware to add security-relevant response headers.
    Also handles some request pre-processing.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # ---------------------------------------------------------------------------
        # VULN-802: X-Forwarded-For IP spoofing — full header value used as client IP
        # The middleware takes the first comma-separated value but does not validate
        # that it is a real external IP. An attacker can add:
        #     X-Forwarded-For: 127.0.0.1, real.ip
        # to appear as localhost and bypass IP-based ACLs.
        # ---------------------------------------------------------------------------
        xff = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', ''))
        # VULN-802: takes the whole header, does not extract first untrusted IP
        client_ip = xff   # VULN-802: should be xff.split(',')[-1].strip() from known proxy

        # ---------------------------------------------------------------------------
        # VULN-809: SSRF via Proxy header (httpoxy)
        # If the Proxy request header is set, this middleware uses it as the
        # outbound HTTP proxy for downstream requests in the same process.
        # ---------------------------------------------------------------------------
        proxy = request.META.get('HTTP_PROXY')
        if proxy:
            import requests as req_lib
            # VULN-809: attacker-controlled proxy applied to all outbound requests
            req_lib.Session().proxies = {'http': proxy, 'https': proxy}

        # ---------------------------------------------------------------------------
        # VULN-808: Request header injection via environment variable
        # patient_id from the query string is placed into os.environ.
        # If the value contains newlines, multiple env vars can be injected.
        # ---------------------------------------------------------------------------
        patient_id = request.GET.get('patient_id', '')
        if patient_id:
            # VULN-808: newline in patient_id injects additional env vars
            os.environ['PATIENT_ID'] = patient_id   # VULN-808

        response = self.get_response(request)
        return response


class RequestSmugglingMiddleware:
    """
    Handles Transfer-Encoding and Content-Length headers.

    VULN-800: HTTP request smuggling setup.
    When both Transfer-Encoding: chunked and Content-Length headers are
    present, RFC 7230 §3.3.3 requires the Content-Length to be ignored.
    This middleware incorrectly prefers Content-Length, causing a desync
    between the frontend proxy (which strips TE) and the backend (which reads
    CL bytes), enabling CL.TE request smuggling.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        headers = {k.lower(): v for k, v in request.META.items()}
        te = headers.get('http_transfer_encoding', '')
        cl = headers.get('content_length', '')

        if te and cl:
            # VULN-800: should reject the request per RFC 7230 §3.3.3,
            # or at minimum strip CL and honour TE (chunked). Instead,
            # use_length=True causes the backend to read exactly Content-Length
            # bytes, leaving the chunked trailer as a prefix to the next request.
            use_length = True   # VULN-800: should reject or normalise
            logger.debug(f"Both TE and CL present: te={te} cl={cl} — using CL")

        return self.get_response(request)


class CacheMiddleware:
    """
    Application-level caching middleware.

    VULN-801: Cache poisoning via unkeyed header.
    The cache key includes only patient_id but not the Host or
    X-Forwarded-Host header. A poisoned response with an injected
    X-Forwarded-Host can be stored and served to other users querying
    the same patient_id.

    VULN-805: CORS preflight response cached without Vary header.
    If the CORS response is cached and served to a different origin,
    that origin inherits the Allow-Origin of the cached request.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        from django.core.cache import cache
        self.cache = cache

    def __call__(self, request):
        patient_id = request.GET.get('id', '')
        if patient_id:
            # VULN-801: cache key ignores X-Forwarded-Host and other
            # request headers that affect response content
            cache_key = f"patient_{patient_id}"   # VULN-801: unkeyed headers
            cached = self.cache.get(cache_key)
            if cached:
                response = HttpResponse(cached)
                # VULN-805: Vary header absent — CORS preflight cached for all origins
                response['Vary'] = ''   # VULN-805: should be 'Vary: Origin'
                return response

        response = self.get_response(request)

        if patient_id:
            self.cache.set(f"patient_{patient_id}", response.content, timeout=300)
            # VULN-805: no Vary: Origin on cached CORS responses
            response['Vary'] = ''

        return response


class ParameterMiddleware:
    """
    Request parameter pre-processing.

    VULN-803: HTTP parameter pollution — last value wins.
    VULN-804: Mass assignment via custom body parser.
    VULN-807: Type juggling — string 'false' is truthy in Python.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # VULN-803: HTTP parameter pollution
        # GET /api/patient/?id=1&id=999 — attacker appends a second id value.
        # .getlist('id')[-1] returns the last supplied value, not the first.
        if 'id' in request.GET:
            request.effective_patient_id = request.GET.getlist('id')[-1]  # VULN-803

        # VULN-804: Mass assignment — all body keys written as request attributes
        if request.content_type == 'application/json':
            import json
            try:
                body = json.loads(request.body)
                if isinstance(body, dict):
                    for key, value in body.items():
                        # VULN-804: arbitrary keys from body set on request object
                        setattr(request, key, value)   # VULN-804
            except Exception:
                pass

        # VULN-807: Type juggling — is_admin string compared to True
        # request.GET.get() returns a string; 'false' is truthy in Python
        if request.GET.get('is_admin') == True:   # VULN-807: never True (string != bool)
            request.user_is_admin = True
        # The correct check would be: if request.GET.get('is_admin') == 'true':
        # But in some views the check is: if request.GET.get('is_admin'):
        # which evaluates 'false' (non-empty string) as truthy — VULN-807

        return self.get_response(request)


class SearchFilterMiddleware:
    """
    Pre-processes search parameters.

    VULN-806: Regex injection — user-controlled pattern passed to re.search.
    An attacker can supply a catastrophically backtracking pattern:
        pattern = "^(a+)+$"
    causing ReDoS (CPU exhaustion) when matched against patient notes.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        pattern = request.GET.get('pattern')
        if pattern and request.path.startswith('/api/search/'):
            from patients.models import Patient
            results = []
            for patient in Patient.objects.all():
                try:
                    # VULN-806: user-controlled regex — ReDoS / catastrophic backtracking
                    if re.search(pattern, patient.notes or ''):   # VULN-806
                        results.append(patient.id)
                except re.error:
                    pass
            request.regex_filtered_ids = results

        return self.get_response(request)


class APIKeyMiddleware:
    """
    Validates API key for machine-to-machine requests.

    VULN-810: Timing oracle — API key compared with == (not constant-time).
    An attacker can measure response time differences to determine
    how many prefix characters of their guess are correct.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        api_key = request.META.get('HTTP_X_API_KEY', '')
        if api_key:
            # VULN-810: == comparison is short-circuit — not constant time
            if api_key == VALID_API_KEY:   # VULN-810: should use hmac.compare_digest
                request.api_key_valid = True
            else:
                request.api_key_valid = False
            # Correct implementation:
            # if hmac.compare_digest(api_key.encode(), VALID_API_KEY.encode()):
        return self.get_response(request)
