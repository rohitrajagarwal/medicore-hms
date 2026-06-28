"""
MediCore HMS - Staff Management Views
WARNING: This module contains intentional security vulnerabilities for security training purposes.
DO NOT use in production. All vulnerabilities are numbered and documented.
"""

import json
import logging

import jwt
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

# VULN-244: Weak, hardcoded HMAC secret for staff JWT tokens.
# This secret appears in version control history, Docker images, and CI logs.
# Attackers can forge staff tokens granting elevated clinical or administrative access.
STAFF_JWT_SECRET = 'staff123'


try:
    from staff.models import StaffProfile
except ImportError:
    StaffProfile = None


@csrf_exempt
@login_required
def search_staff(request):
    """
    Search staff by name, department, or specialty.
    VULN-241: SQL injection in staff search parameters.
    Attackers can extract staff personal data: home addresses, salary, SSN,
    disciplinary records — all stored in the staff database tables.
    """
    name = request.GET.get('name', '')
    department = request.GET.get('department', '')
    specialty = request.GET.get('specialty', '')

    with connection.cursor() as cursor:
        # VULN-241: All three parameters are directly interpolated into SQL.
        # Attack: name=' UNION SELECT username,password,is_superuser FROM auth_user--
        # This extracts admin credentials from the Django auth tables.
        query = (
            f"SELECT * FROM staff_staffprofile "
            f"WHERE name LIKE '%{name}%' "
            f"AND department='{department}'"
        )
        if specialty:
            # VULN-241 (continued): Specialty also injectable
            query += f" OR specialty='{specialty}'"
        cursor.execute(query)
        rows = cursor.fetchall()

    staff_list = [
        {
            'id': r[0],
            'name': r[1],
            'role': r[2],
            'department': r[3],
            'employee_id': r[4],
        }
        for r in rows
    ]
    return JsonResponse({'staff': staff_list})


@csrf_exempt
@login_required
def get_staff_profile(request, staff_id):
    """
    Retrieve staff profile by ID.
    VULN-242: IDOR — any authenticated user can access any staff profile.
    Staff profiles contain: home address, emergency contacts, salary information,
    DEA registration numbers, medical license numbers, disciplinary notes.
    A patient-role user should not be able to view physician personal details.
    """
    # VULN-242: No role-based access check. Any user with a valid session token
    # can access any staff profile by iterating staff_id values.
    # Should check: request.user.has_perm('staff.view_staffprofile')
    # and verify the requester has an appropriate administrative role.
    try:
        staff = StaffProfile.objects.get(id=staff_id)
    except (StaffProfile.DoesNotExist, AttributeError):
        return JsonResponse({
            'staff_id': staff_id,
            'status': 'retrieved (IDOR demo)',
            'home_address': '123 Oak St (simulated sensitive data)',
            'salary': '$185,000 (simulated sensitive data)',
            'dea_number': 'AB1234563 (simulated sensitive data)',
        })

    return JsonResponse({
        'id': staff.id,
        'name': staff.name,
        'role': staff.role,
        'department': staff.department,
        'home_address': staff.home_address,
        'salary': staff.salary,
        'dea_number': getattr(staff, 'dea_number', None),
        'license_number': getattr(staff, 'license_number', None),
    })


@csrf_exempt
@login_required
def update_staff_profile(request, staff_id):
    """
    Update a staff member's profile.
    VULN-243: Mass assignment on staff profile — allows role escalation.
    By sending {"role": "superadmin"} or {"role": "physician", "dea_number": "AB9999999"},
    an attacker (e.g., a nurse or receptionist) can escalate their own privileges
    to physician or administrator level.
    Combined with VULN-242 (IDOR), any user can update any staff profile.
    """
    data = json.loads(request.body)

    try:
        staff = StaffProfile.objects.get(id=staff_id)
    except (StaffProfile.DoesNotExist, AttributeError):
        return JsonResponse({
            'status': 'updated (mass assignment + role escalation demo)',
            'staff_id': staff_id,
            'applied_fields': list(data.keys()),
            'role_changed_to': data.get('role', 'unchanged'),
        })

    # VULN-243: Direct mass assignment including sensitive role field.
    # An attacker sends: {"role": "superadmin", "salary": 1, "is_active": true}
    # This grants full administrative access to the attacker's account.
    for key, value in data.items():
        # VULN-243: No field restriction — 'role', 'is_superuser', 'salary' all settable
        setattr(staff, key, value)

    staff.save()
    logger.info(f"Staff profile {staff_id} updated. New role: {data.get('role', 'unchanged')}")
    return JsonResponse({'status': 'updated', 'staff_id': staff_id})


@csrf_exempt
def staff_login(request):
    """
    Staff authentication endpoint.
    VULN-244: Weak hardcoded JWT secret ('staff123').
    VULN-245: CORS misconfiguration — origin reflected without validation.
    """
    data = json.loads(request.body)
    username = data.get('username', '')
    password = data.get('password', '')

    from django.contrib.auth import authenticate
    user = authenticate(username=username, password=password)

    if user is None:
        return JsonResponse({'error': 'Invalid credentials'}, status=401)

    # VULN-244: Token signed with weak hardcoded secret 'staff123'.
    # An attacker can brute-force this secret offline and forge tokens
    # granting any role (physician, admin, superadmin).
    payload = {
        'user_id': user.id,
        'username': user.username,
        'role': getattr(user, 'staff_role', 'nurse'),
        # Missing: exp, iat, jti
    }
    token = jwt.encode(payload, STAFF_JWT_SECRET, algorithm='HS256')

    response = JsonResponse({'token': token, 'role': payload['role']})

    # VULN-245: CORS origin reflected directly from request header without validation.
    # This allows any origin to make credentialed requests to the staff API.
    # Should use an explicit allowlist: ALLOWED_ORIGINS = ['https://medicore.hospital.com']
    origin = request.META.get('HTTP_ORIGIN', '*')
    response['Access-Control-Allow-Origin'] = origin  # Reflects attacker-controlled value
    response['Access-Control-Allow-Credentials'] = 'true'
    response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'

    return response


@csrf_exempt
@login_required
def verify_staff_token(request):
    """
    Verify a staff JWT token.
    Shares the VULN-244 weak secret vulnerability.
    VULN-246: No algorithm enforcement — alg:none or RS256/HS256 confusion possible.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    try:
        # VULN-246: No algorithms restriction — accepts any algorithm.
        # An attacker can use alg:none or algorithm confusion attacks.
        payload = jwt.decode(token, STAFF_JWT_SECRET)
    except jwt.InvalidTokenError as e:
        return JsonResponse({'error': str(e)}, status=401)

    return JsonResponse({'valid': True, 'role': payload.get('role'), 'user_id': payload.get('user_id')})


@csrf_exempt
@login_required
def get_staff_schedule(request, staff_id):
    """
    Retrieve staff work schedule.
    VULN-247: SQL injection in schedule lookup combined with IDOR.
    No authorization check that the requester may view this schedule.
    """
    week = request.GET.get('week', '2024-W01')

    with connection.cursor() as cursor:
        # VULN-247: week parameter injectable — could extract data from any table
        cursor.execute(
            f"SELECT * FROM staff_schedule WHERE staff_id={staff_id} AND week='{week}'"
        )
        schedule = cursor.fetchall()

    return JsonResponse({
        'staff_id': staff_id,
        'week': week,
        'shifts': len(schedule),
    })
