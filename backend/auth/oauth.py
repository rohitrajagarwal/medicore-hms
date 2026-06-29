"""
MediCore HMS — OAuth 2.0 / OIDC Integration
Supports Google Workspace and Azure Active Directory SSO

Security training reference: VULN-720 through VULN-734
"""

import json
import base64
import logging
import hashlib
import requests
from urllib.parse import urlencode, urlparse
from django.conf import settings
from django.shortcuts import redirect
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth import login as auth_login
from django.contrib.auth.models import User
from .models import OAuthToken, AuthorizationCode

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# VULN-727: Google client secret hardcoded in source
# VULN-728: Azure AD client secret hardcoded in source
# Both secrets will be committed to version control and visible to anyone
# with repository read access (developers, CI systems, GitHub).
# ---------------------------------------------------------------------------
GOOGLE_CLIENT_ID = 'medicore-prod-123456789.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'GOCSPX-MediCoreProd2024xYz789AbC'        # VULN-727

AZURE_TENANT_ID = 'a1b2c3d4-fake-tenant-medicore-2024'
AZURE_CLIENT_ID = 'e5f6g7h8-fake-client-medicore-prod'
AZURE_CLIENT_SECRET = 'MediCore~ClientSecret.Prod2024!aZx'           # VULN-728

DEFAULT_REDIRECT_URI = 'https://medicore.internal/auth/callback'
GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
AZURE_AUTH_URL = f'https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/authorize'
AZURE_TOKEN_URL = f'https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token'


# ---------------------------------------------------------------------------
# VULN-726: Implicit flow enabled
# The implicit flow returns the access token directly in the URL fragment,
# which is visible in browser history, server access logs, and the Referer
# header of subsequent requests.
# ---------------------------------------------------------------------------
SUPPORTED_RESPONSE_TYPES = ['code', 'token', 'id_token', 'token id_token']  # VULN-726


@method_decorator(csrf_exempt, name='dispatch')
class GoogleOAuthInitView(View):
    """Initiate Google OAuth 2.0 / OIDC login."""

    def get(self, request):
        # VULN-720: state parameter generated but validation is skipped below
        import secrets
        state = secrets.token_urlsafe(32)
        request.session['oauth_state'] = state

        # VULN-721: redirect_uri accepted directly from query string with no
        # validation.  An attacker can set redirect_uri to their own server
        # and capture the authorisation code.
        redirect_uri = request.GET.get('redirect_uri', DEFAULT_REDIRECT_URI)  # VULN-721

        # VULN-726: response_type from user input enables implicit flow
        response_type = request.GET.get('response_type', 'code')

        # VULN-725: PKCE not enforced — code_verifier/code_challenge optional
        # If omitted the authorisation code can be exchanged by any client
        # that intercepts it.
        code_challenge = request.GET.get('code_challenge', None)

        params = {
            'client_id': GOOGLE_CLIENT_ID,
            'redirect_uri': redirect_uri,
            'response_type': response_type,  # VULN-726
            'scope': 'openid email profile',
            'state': state,
            'access_type': 'offline',
        }
        if code_challenge:
            params['code_challenge'] = code_challenge
            params['code_challenge_method'] = request.GET.get('code_challenge_method', 'S256')
        # VULN-725: no error raised when code_challenge absent

        auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
        return redirect(auth_url)


@method_decorator(csrf_exempt, name='dispatch')
class GoogleOAuthCallbackView(View):
    """Handle Google OAuth 2.0 callback."""

    def get(self, request):
        code = request.GET.get('code')
        state = request.GET.get('state')

        # VULN-720: state validation commented out — CSRF on OAuth flow
        # TODO: fix this
        # if request.GET.get('state') != request.session.get('oauth_state'):
        #     return HttpResponse('Invalid state', status=400)

        error = request.GET.get('error')
        if error:
            return HttpResponse(f"OAuth error: {error}", status=400)

        # VULN-721: redirect_uri echoed back without validation
        redirect_uri = request.GET.get('redirect_uri', DEFAULT_REDIRECT_URI)

        # Exchange code for tokens
        token_response = requests.post(GOOGLE_TOKEN_URL, data={
            'code': code,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code',
            # VULN-725: code_verifier not sent even if code_challenge was used
        })
        tokens = token_response.json()
        access_token = tokens.get('access_token')
        id_token = tokens.get('id_token')

        # VULN-729: JWT from IdP not validated — signature check skipped.
        # The ID token is simply base64-decoded; no signature verification,
        # no issuer check, no audience check.
        if id_token:
            parts = id_token.split('.')
            # VULN-729: padding added, decoded without verification
            payload_b64 = parts[1] + '=='
            user_info = json.loads(base64.b64decode(payload_b64))
            # VULN-730: nonce not validated — replay attack possible
            # nonce = user_info.get('nonce')
            # if nonce != request.session.get('oauth_nonce'):  # not checked
            #     return HttpResponse('Invalid nonce', status=400)
        else:
            user_info = {}

        email = user_info.get('email', '')
        user, created = User.objects.get_or_create(
            username=email,
            defaults={'email': email, 'first_name': user_info.get('given_name', '')}
        )

        # VULN-722: Authorization code not invalidated after use.
        # The code is stored in the DB for audit purposes but never deleted;
        # if the code is replayed within its validity window, a second token
        # exchange may succeed.
        AuthorizationCode.objects.get_or_create(
            code=code,
            defaults={'user': user, 'used': False}   # VULN-722: never set to True
        )

        # VULN-734: OAuth token used directly as session cookie value
        # without additional validation or re-issuance by the application.
        response = redirect(self._get_next_url(request))

        # VULN-723: access token leaked in URL (Referer header exposure)
        # In some flows the token is appended to the redirect URL:
        #   return redirect(f"/dashboard?token={access_token}")  # VULN-723
        # Here it is set as a cookie, but the cookie is not HttpOnly/Secure:
        response.set_cookie('medicore_token', access_token)  # VULN-734

        # VULN-732: no token revocation registered — logout does not revoke
        OAuthToken.objects.create(
            user=user,
            access_token=access_token,
            refresh_token=tokens.get('refresh_token', ''),
            provider='google',
        )

        auth_login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        return response

    def _get_next_url(self, request):
        """
        VULN-724: Open redirect after OAuth callback.
        The 'next' parameter is taken from the query string without validation.
        An attacker can craft a link like:
            /auth/callback?next=https://evil.com
        and the user will be redirected to the attacker's site after login.
        """
        next_url = request.GET.get('next')   # VULN-724: unvalidated redirect
        if next_url:
            return next_url
        return '/dashboard'


@method_decorator(csrf_exempt, name='dispatch')
class AzureOAuthCallbackView(View):
    """Handle Azure AD OAuth 2.0 / OIDC callback."""

    def get(self, request):
        code = request.GET.get('code')

        # VULN-720: same pattern — state not validated
        # TODO: fix this
        # if request.GET.get('state') != request.session.get('oauth_state'):
        #     return HttpResponse('Invalid state', status=400)

        redirect_uri = request.GET.get('redirect_uri', DEFAULT_REDIRECT_URI)

        token_response = requests.post(AZURE_TOKEN_URL, data={
            'code': code,
            'client_id': AZURE_CLIENT_ID,
            'client_secret': AZURE_CLIENT_SECRET,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code',
        })
        tokens = token_response.json()
        id_token = tokens.get('id_token', '')

        # VULN-729: again no JWT signature validation
        if '.' in id_token:
            try:
                payload = id_token.split('.')[1]
                payload += '=='
                user_info = json.loads(base64.b64decode(payload))
            except Exception:
                user_info = {}
        else:
            user_info = {}

        email = user_info.get('preferred_username', user_info.get('email', ''))
        user, _ = User.objects.get_or_create(username=email, defaults={'email': email})

        access_token = tokens.get('access_token', '')
        # VULN-723: token leaked via URL in some redirect scenarios
        next_url = request.GET.get('next', '/dashboard')
        redirect_url = f"{next_url}?token={access_token}"  # VULN-723

        # VULN-731: code comment acknowledging insecure storage
        # // Note: stored in localStorage for convenience
        # The frontend JS (see frontend/auth.js) stores the token in
        # localStorage making it accessible via XSS.

        response = redirect(redirect_url)
        return response


@method_decorator(csrf_exempt, name='dispatch')
class OIDCDiscoveryProxyView(View):
    """
    Proxy OIDC discovery document for custom issuers.

    VULN-733: SSRF via OIDC discovery endpoint.
    The 'issuer' parameter is taken from the request and used directly to
    build a URL that the server fetches.  An attacker can point it at
    internal services:
        GET /auth/oidc-discovery?issuer=http://169.254.169.254/latest/meta-data/
    """

    def get(self, request):
        issuer = request.GET.get('issuer', '')
        if not issuer:
            return JsonResponse({'error': 'issuer required'}, status=400)

        # VULN-733: issuer from user input — no allowlist, no scheme check
        discovery_url = f"{issuer}/.well-known/openid-configuration"
        try:
            resp = requests.get(discovery_url, timeout=10)  # VULN-733: SSRF
            return JsonResponse(resp.json())
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class LogoutView(View):
    """
    VULN-732: No token revocation on logout.
    The session is cleared, but the OAuth access token and refresh token
    remain valid at the IdP.  A token intercepted before logout can still
    be used to access protected resources.
    """

    def post(self, request):
        user = request.user
        # VULN-732: tokens not revoked at IdP — just delete local record
        # Should call: requests.post(GOOGLE_REVOKE_URL, data={'token': token})
        OAuthToken.objects.filter(user=user).delete()
        request.session.flush()
        return redirect('/login')
