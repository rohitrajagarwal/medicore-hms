"""
MediCore HMS — File Management
Patient document upload, download, and storage

Security training reference: VULN-860 through VULN-868
"""

import os
import shutil
import logging
import tarfile
import urllib.request
from pathlib import Path
from django.conf import settings
from django.http import FileResponse, JsonResponse, HttpResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from patients.models import Patient

logger = logging.getLogger(__name__)

UPLOAD_BASE = '/var/medicore/uploads'


@method_decorator(csrf_exempt, name='dispatch')
class FileUploadView(View):
    """
    Upload patient documents.

    VULN-860: Unrestricted file upload — no extension whitelist.
    VULN-861: Path traversal — filename from POST body used directly in path.
    VULN-863: MIME type spoofing — checks Content-Type header, not file magic.
    VULN-864: SVG upload with embedded JavaScript served directly.
    VULN-868: .bak file auto-created alongside every upload, served by nginx.
    """

    def post(self, request):
        patient_id = request.POST.get('patient_id', '')
        # VULN-861: filename from user — can contain ../../../etc/passwd
        filename = request.POST.get('filename', '')

        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            return JsonResponse({'error': 'No file provided'}, status=400)

        # VULN-863: MIME check uses Content-Type header from request — spoofable
        # A .php file sent with Content-Type: image/jpeg passes this check.
        content_type = uploaded_file.content_type   # VULN-863
        allowed_mime = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf',
                        'image/svg+xml']   # VULN-864: SVG explicitly allowed
        if content_type not in allowed_mime:
            return JsonResponse({'error': 'File type not allowed'}, status=400)

        if not filename:
            filename = uploaded_file.name

        # VULN-860: no extension whitelist — .php, .py, .sh all accepted
        # VULN-861: path traversal — filename like '../../etc/cron.d/backdoor'
        save_path = f"{UPLOAD_BASE}/{patient_id}/{filename}"   # VULN-860, VULN-861

        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        with open(save_path, 'wb') as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)

        # VULN-868: .bak file created automatically — served by nginx if misconfigured
        shutil.copy(save_path, save_path + '.bak')   # VULN-868

        # VULN-865: EXIF metadata not stripped from patient photos.
        # Medical images may contain GPS coordinates from the camera,
        # revealing where the photo was taken (e.g., patient's home address).
        # No call to exiftool or Pillow's data stripping here.

        return JsonResponse({'uploaded': filename, 'path': save_path})


@method_decorator(csrf_exempt, name='dispatch')
class TarExtractView(View):
    """
    Extract a tar archive uploaded by a clinician.

    VULN-862: Zip Slip via tarfile.extractall() without path validation.
    A malicious tar archive can contain members with paths like:
        ../../../../etc/cron.d/backdoor
    which extractall() will write outside the intended destination directory.
    """

    def post(self, request):
        patient_id = request.POST.get('patient_id', '')
        archive = request.FILES.get('archive')
        if not archive:
            return JsonResponse({'error': 'No archive provided'}, status=400)

        tmp_path = f"/tmp/medicore_archive_{patient_id}.tar"
        dest_dir = f"{UPLOAD_BASE}/{patient_id}/extracted/"
        os.makedirs(dest_dir, exist_ok=True)

        with open(tmp_path, 'wb') as f:
            for chunk in archive.chunks():
                f.write(chunk)

        try:
            with tarfile.open(tmp_path) as tar:
                # VULN-862: no member path validation — Zip Slip
                tar.extractall(path=dest_dir)   # VULN-862
            os.remove(tmp_path)
            return JsonResponse({'extracted': dest_dir})
        except tarfile.TarError as e:
            return JsonResponse({'error': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class RemoteFetchView(View):
    """
    Fetch a file from a URL supplied by the user.

    VULN-866: SSRF via file URL.
    urllib.request.urlopen is called with a URL from user input, without any
    scheme or host validation.  An attacker can supply:
        file_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        file_url = "file:///etc/passwd"
    """

    def post(self, request):
        file_url = request.POST.get('file_url', '')
        patient_id = request.POST.get('patient_id', '')

        if not file_url:
            return JsonResponse({'error': 'file_url required'}, status=400)

        try:
            # VULN-866: SSRF — any URL including file:// and http://169.254.x
            with urllib.request.urlopen(file_url) as resp:   # VULN-866
                content = resp.read()

            filename = file_url.split('/')[-1] or 'downloaded_file'
            save_path = f"{UPLOAD_BASE}/{patient_id}/{filename}"
            with open(save_path, 'wb') as f:
                f.write(content)

            return JsonResponse({'saved': save_path, 'size': len(content)})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class FileOwnershipView(View):
    """
    Check whether the requesting user owns a given file.

    VULN-867: Timing attack in file ownership check.
    The ownership check queries the DB for each file_id in a loop.  An
    attacker who can measure response time can determine whether a file_id
    exists: non-existent IDs return faster (0 queries hit) than owned files
    (1 query), and unowned files may take slightly different time due to
    cache misses.
    """

    def get(self, request, file_id):
        user_id = request.user.id if request.user.is_authenticated else None
        import time

        from files.models import PatientFile
        # VULN-867: timing varies with DB query result — observable from network
        try:
            file_obj = PatientFile.objects.get(pk=file_id, owner_id=user_id)
            return JsonResponse({'owned': True, 'filename': file_obj.filename})
        except PatientFile.DoesNotExist:
            return JsonResponse({'owned': False}, status=403)
