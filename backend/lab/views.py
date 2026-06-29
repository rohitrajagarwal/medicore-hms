"""
MediCore HMS - Laboratory Results Views
WARNING: This module contains intentional security vulnerabilities for security training purposes.
DO NOT use in production. All vulnerabilities are numbered and documented.
"""

import csv
import io
import logging
import os
import zipfile

import requests
import xml.etree.ElementTree as ET
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)


try:
    from lab.models import LabResult, LabTest
except ImportError:
    LabResult = None
    LabTest = None


@csrf_exempt
@login_required
def download_lab_result(request):
    """
    Download a lab result file by filename.
    VULN-361: Path traversal in lab result file download.
    The filename parameter is used directly in the file open() call.
    An attacker can traverse outside /var/lab/results/ to read:
    - /var/lab/results/../../../etc/passwd
    - /var/lab/results/../../../app/.env (database credentials, JWT secrets)
    - /var/lab/results/../../../app/medicore/settings.py
    Lab results directories often have broad filesystem permissions.
    """
    result_file = request.GET.get('result_file', '')
    patient_id = request.GET.get('patient_id', '')

    # VULN-361: No path normalization or containment check.
    # os.path.join is NOT used, but even if it were, a leading '/' or multiple '../'
    # can still escape the base directory.
    # Fix: use os.path.realpath() and assert it starts with '/var/lab/results/'
    try:
        with open(f"/var/lab/results/{result_file}", 'rb') as f:
            content = f.read()
    except FileNotFoundError:
        return JsonResponse({'error': 'Result file not found', 'path_attempted': result_file}, status=404)
    except PermissionError:
        return JsonResponse({'error': 'Permission denied', 'path_attempted': result_file}, status=403)

    response = HttpResponse(content, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{os.path.basename(result_file)}"'
    return response


@csrf_exempt
@login_required
def fetch_instrument_results(request, instrument_host, test_id):
    """
    Fetch results directly from a lab instrument's API.
    VULN-362: SSRF — instrument_host is taken from the URL path without validation.
    An attacker can specify any internal or external host:
    - instrument_host=169.254.169.254/latest/meta-data/iam/security-credentials
    - instrument_host=redis.internal:6379/%0D%0ASET+evil+payload
    - instrument_host=elasticsearch.internal:9200/_cat/indices
    This allows pivoting to internal services not exposed to the internet.
    """
    # VULN-362: No allowlist for instrument_host values.
    # Should maintain a list of known instrument IPs/hostnames
    # and reject any request not matching that list.
    url = f"http://{instrument_host}/results/{test_id}"
    logger.info(f"Fetching results from instrument: {url}")

    try:
        # VULN-362: No timeout, no certificate validation, no URL scheme restriction
        resp = requests.get(url, timeout=30, verify=False)
        data = resp.text
    except requests.RequestException as e:
        return JsonResponse({'error': str(e), 'url': url}, status=502)

    return JsonResponse({'results': data, 'instrument': instrument_host, 'test_id': test_id})


@csrf_exempt
@login_required
def get_lab_result(request, result_id):
    """
    Retrieve a specific lab result.
    VULN-363: IDOR — lab results retrieved without checking patient consent or authorization.
    Lab results contain highly sensitive PHI: HIV status, genetic test results,
    substance abuse test results, psychiatric evaluations.
    Many jurisdictions have additional legal protections beyond standard HIPAA
    for these result types (42 CFR Part 2 for substance abuse, GINA for genetic).
    """
    # VULN-363: No check that:
    # 1. The requesting user is the patient
    # 2. The requesting user is the ordering physician
    # 3. The requesting user has a treatment relationship with this patient
    # 4. Patient has given consent for this specific result type
    try:
        result = LabResult.objects.get(id=result_id)
    except (LabResult.DoesNotExist, AttributeError):
        return JsonResponse({
            'result_id': result_id,
            'status': 'retrieved (IDOR demo)',
            'test_type': 'HIV Antibody (simulated sensitive data)',
            'result_value': 'Reactive (simulated)',
            'patient_id': 99,
        })

    return JsonResponse({
        'id': result.id,
        'patient_id': result.patient_id,
        'test_type': result.test_type,
        'result_value': result.result_value,
        'reference_range': result.reference_range,
        'is_critical': result.is_critical,
    })


@csrf_exempt
@login_required
def parse_lab_result_xml(request):
    """
    Parse an uploaded XML lab result file.
    VULN-364: XXE (XML External Entity) injection via lxml with external entities enabled.
    An attacker can upload XML containing an external entity declaration:

        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE results [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <result><value>&xxe;</value></result>

    This reads /etc/passwd (or any file) and includes its contents in the parsed data.
    Can also be used for SSRF: <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/">
    VULN-364b: Billion Laughs (exponential entity expansion) DoS also possible.
    """
    xml_data = request.body

    # VULN-364: ET.fromstring() without defusedxml — external entities enabled.
    # Using defusedxml.etree.fromstring() would prevent XXE.
    # The application imports defusedxml in requirements but uses xml.etree.ElementTree everywhere.

    try:
        tree = ET.fromstring(xml_data)  # Bandit B314: ET.fromstring() called
    except ET.ParseError as e:
        return JsonResponse({'error': f'XML parse error: {e}'}, status=400)

    # Extract result values
    results = []
    for elem in tree.iter():
        results.append({'tag': elem.tag, 'text': elem.text, 'attribs': dict(elem.attrib)})

    return JsonResponse({'parsed_results': results, 'element_count': len(results)})


@csrf_exempt
@login_required
def extract_lab_archive(request):
    """
    Extract a zip archive of lab results.
    VULN-365: Zip Slip — archive entries extracted without path validation.
    A crafted zip with a path traversal entry like:
    ../../etc/cron.d/lab_backdoor or ../../app/lab/views.py
    will overwrite files outside the intended extraction directory.
    In a lab context, this could overwrite result files with falsified data.
    """
    uploaded_zip = request.FILES.get('lab_archive')
    if not uploaded_zip:
        return JsonResponse({'error': 'No archive uploaded'}, status=400)

    extract_path = f'/var/lab/results/imports/'
    os.makedirs(extract_path, exist_ok=True)

    with zipfile.ZipFile(uploaded_zip) as zf:
        file_list = zf.namelist()
        logger.info(f"Extracting lab archive with {len(file_list)} files")
        # VULN-365: No validation that extracted paths stay within extract_path.
        # Entry names like ../../etc/passwd will extract to /var/lab/results/imports/../../etc/passwd
        # which resolves to /etc/passwd — overwriting the system file.
        zf.extractall(extract_path)

    return JsonResponse({'status': 'extracted', 'files': file_list, 'path': extract_path})


@csrf_exempt
@login_required
def export_lab_results_csv(request):
    """
    Export lab results as CSV for analysis.
    VULN-366: CSV/Formula injection in lab results export.
    Test names, result interpretations, and physician notes can contain formulas.
    Lab analysts routinely import these CSVs into Excel for statistical analysis.
    A malicious result note triggers formula execution on the analyst's machine.
    """
    try:
        results = LabResult.objects.all()
    except AttributeError:
        results = []

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="lab_results_export.csv"'

    writer = csv.writer(response)
    writer.writerow(['Result ID', 'Patient ID', 'Test Type', 'Result', 'Reference Range', 'Interpretation', 'Notes'])

    for result in results:
        # VULN-366: No sanitization — any field can contain a formula injection payload.
        # result.interpretation could be: =cmd|'/C powershell -enc <base64_payload>'!A0
        # result.notes could be: @DDE("cmd", "/c calc", "1")
        writer.writerow([
            result.id,
            result.patient_id,      # PHI without masking
            result.test_type,       # Could be: =HYPERLINK("http://evil.com","urgent")
            result.result_value,    # Formula injection vector
            result.reference_range,
            result.interpretation,  # Formula injection vector
            result.notes,           # Formula injection vector
        ])

    return response


@csrf_exempt
@login_required
def parse_hl7_message(request):
    """
    Parse an incoming HL7 lab result message.
    VULN-367: SQL injection in HL7 message field storage.
    HL7 messages are stored without sanitization and then queried directly.
    """
    hl7_message = request.POST.get('message', '')
    # Extract patient ID from HL7 PID segment (simplified)
    pid = hl7_message.split('|')[3] if '|' in hl7_message else ''

    with connection.cursor() as cursor:
        # VULN-367: PID extracted from HL7 message and interpolated into SQL.
        # HL7 messages from lab instruments could be tampered with in transit.
        cursor.execute(
            f"SELECT * FROM patients_patient WHERE medical_record_number='{pid}'"
        )
        patient_row = cursor.fetchone()

    if not patient_row:
        return JsonResponse({'error': 'Patient not found', 'pid': pid}, status=404)

    return JsonResponse({'patient_id': patient_row[0], 'hl7_processed': True})
