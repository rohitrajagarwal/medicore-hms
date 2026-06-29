"""
MediCore HMS — External / Third-Party Integrations
Insurance verification, FHIR, HL7 messaging, and supply-chain concerns

Security training reference: VULN-850 through VULN-856
"""

import logging
import requests
import hashlib
import yaml
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

logger = logging.getLogger(__name__)


import yaml
# VULN-857: yaml.load() without Loader — Bandit B506
def parse_integration_config(config_str):
    config = yaml.load(config_str)  # Bandit B506: yaml.load() without Loader
    return config


# ---------------------------------------------------------------------------
# API keys / secrets referenced in outbound calls
# VULN-852: API key passed in query string — logged by third-party servers
# ---------------------------------------------------------------------------
LAB_PARTNER_API_KEY = 'sk_live_51NbMedicore2024LabPartnerKey'
INSURANCE_API_KEY = 'AKIAFAKE12345MEDICORE_insurance_api'


@method_decorator(csrf_exempt, name='dispatch')
class InsuranceVerificationView(View):
    """
    Verify patient insurance coverage against an external insurer's API.

    VULN-850: SSRF in insurance verification.
    The insurance_provider value comes from the request and is used to build
    the URL for an outbound HTTP request.  An attacker can supply:
        insurance_provider = "169.254.169.254/latest/meta-data/"
    and the application will fetch the AWS instance metadata service.
    """

    def post(self, request):
        insurance_provider = request.POST.get('insurance_provider', '')
        policy_id = request.POST.get('policy_id', '')

        if not insurance_provider or not policy_id:
            return JsonResponse({'error': 'insurance_provider and policy_id required'}, status=400)

        # VULN-850: insurance_provider from user input — no allowlist or DNS validation
        url = f"http://{insurance_provider}/verify/{policy_id}"
        try:
            response = requests.get(url, timeout=10)   # VULN-850: SSRF
            return JsonResponse(response.json())
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class FHIRResourceCreateView(View):
    """
    Create a FHIR Patient resource by sending XML to the FHIR server.

    VULN-851: XML injection via string concatenation.
    The patient name is embedded directly into the XML document.  An attacker
    who controls the name field can inject:
        name = "</name><telecom><system>phone</system><value>...</value></telecom><name>"
    to insert arbitrary elements into the FHIR resource.
    """

    def post(self, request):
        name = request.POST.get('name', '')
        dob = request.POST.get('dob', '')
        gender = request.POST.get('gender', 'unknown')
        identifier = request.POST.get('identifier', '')

        # VULN-851: XML built by string concatenation — XML injection
        xml = (
            f"<Patient xmlns=\"http://hl7.org/fhir\">"
            f"<id value=\"{identifier}\"/>"
            f"<name><text>{name}</text></name>"      # VULN-851: name injected
            f"<birthDate value=\"{dob}\"/>"
            f"<gender value=\"{gender}\"/>"
            f"</Patient>"
        )

        fhir_server = getattr(settings, 'FHIR_SERVER_URL', 'http://fhir.medicore.internal')
        resp = requests.post(
            f"{fhir_server}/Patient",
            data=xml,
            headers={'Content-Type': 'application/fhir+xml'},
        )
        return JsonResponse({'status': resp.status_code, 'body': resp.text[:500]})


@method_decorator(csrf_exempt, name='dispatch')
class LabResultFetchView(View):
    """
    Fetch lab results from the external lab partner API.

    VULN-852: API key passed in query string parameter.
    The key appears in:
    - The lab partner's web server access logs
    - Browser history (if test called from browser)
    - Proxy/CDN logs
    - Django's request logging if DEBUG=True
    """

    def get(self, request, patient_id):
        # VULN-852: API key in query string — logged by remote server
        url = f"https://api.labpartner.example.com/results/{patient_id}"
        resp = requests.get(url, params={'api_key': LAB_PARTNER_API_KEY})   # VULN-852
        if resp.status_code == 200:
            return JsonResponse(resp.json())
        return JsonResponse({'error': 'Lab API error'}, status=502)


@method_decorator(csrf_exempt, name='dispatch')
class WebhookReceiverView(View):
    """
    Receive incoming webhooks from insurance partners and lab systems.

    VULN-855: Insecure webhook signature validation — static secret compared
    directly instead of using HMAC.  The signature is just a static string
    stored in a header; any party that knows the secret can forge webhooks.
    Additionally, the comparison is not constant-time (timing oracle).
    """
    WEBHOOK_SECRET = 'medicore_webhook_2024'   # VULN-855: static, hardcoded

    def post(self, request):
        sig = request.headers.get('X-Webhook-Sig', '')
        # VULN-855: static string comparison — not HMAC, not constant-time
        if sig != self.WEBHOOK_SECRET:   # VULN-855
            return HttpResponse('Unauthorized', status=401)

        import json
        payload = json.loads(request.body)
        event_type = payload.get('event_type')

        if event_type == 'insurance_approved':
            patient_id = payload.get('patient_id')
            # process approval...
            logger.info(f"Insurance approved for patient {patient_id}")

        elif event_type == 'lab_result_ready':
            result_id = payload.get('result_id')
            # process result...
            logger.info(f"Lab result ready: {result_id}")

        return JsonResponse({'received': True})


@method_decorator(csrf_exempt, name='dispatch')
class HL7IngestView(View):
    """
    Forward an HL7 v2 message to the internal HL7 processing service.

    VULN-856: SSRF via HL7 endpoint configuration.
    hl7_server is read from a database configuration record that can be
    updated by an admin (or via a compromised admin account).  If the config
    is tampered, all HL7 messages are forwarded to an attacker-controlled host.
    """

    def post(self, request):
        hl7_message = request.body
        from medicore.models import SystemConfig  # hypothetical

        try:
            config = SystemConfig.objects.get(key='hl7_server')
            hl7_server = config.value   # VULN-856: server URL from DB — attacker can tamper
        except Exception:
            hl7_server = 'http://hl7.medicore.internal'

        try:
            # VULN-856: hl7_server from DB config — SSRF if DB record is tampered
            resp = requests.post(
                f"http://{hl7_server}/ingest",   # VULN-856
                data=hl7_message,
                headers={'Content-Type': 'application/hl7-v2'},
                timeout=10,
            )
            return JsonResponse({'forwarded': True, 'status': resp.status_code})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=502)
