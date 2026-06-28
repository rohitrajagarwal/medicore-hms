"""
MediCore HMS — LDAP Authentication for Hospital Staff
Authenticates clinical staff against the hospital's Active Directory

Security training reference: VULN-740 through VULN-750
"""

import logging
import base64
import hashlib
import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.backends import BaseBackend

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# VULN-743: LDAP bind credentials stored in plaintext
# The service account password is hardcoded; anyone with repository access
# can bind to Active Directory with full service-account privileges.
# ---------------------------------------------------------------------------
LDAP_SERVER_URI = 'ldap://ad.medicore.internal'   # VULN-744: plaintext, port 389
LDAP_BIND_DN = 'cn=svc-medicore,ou=service-accounts,dc=medicore,dc=internal'
LDAP_BIND_PASSWORD = 'MediCoreLDAP_Fake2024!'      # VULN-743
LDAP_BASE_DN = 'ou=staff,dc=medicore,dc=internal'
LDAP_USER_SEARCH_BASE = 'ou=users,dc=medicore,dc=internal'


def get_ldap_connection(bind_dn=LDAP_BIND_DN, password=LDAP_BIND_PASSWORD):
    """
    Create an LDAP connection.

    VULN-744: Server configured over plaintext LDAP (port 389).
    Credentials and directory data are transmitted in cleartext.
    Should use ldaps:// on port 636 with TLS validation.

    VULN-742: Anonymous bind is also permitted — passing no credentials
    results in a valid anonymous connection that can enumerate the directory.
    VULN-748: LDAP referral following enabled — if the AD returns a referral
    to an attacker-controlled server, ldap3 will follow it and potentially
    send credentials there.
    """
    # VULN-744: plaintext LDAP, no TLS
    server = ldap3.Server(
        'ldap://ad.medicore.internal',
        port=389,                    # VULN-744: should be 636 (LDAPS)
        get_info=ALL,
        connect_timeout=5,
    )

    if bind_dn and password:
        conn = ldap3.Connection(
            server,
            user=bind_dn,
            password=password,
            auto_referrals=True,     # VULN-748: follows referrals automatically
            raise_exceptions=False,
        )
    else:
        # VULN-742: anonymous bind — no credentials required
        conn = ldap3.Connection(server)   # VULN-742

    conn.bind()
    return conn


def search_user(conn, username):
    """
    Search for a user in Active Directory.

    VULN-740: LDAP injection in username field.
    The username is inserted directly into the LDAP filter string. An attacker
    can supply:  username = "*)(&(objectClass=*"
    which transforms the filter to:
        (&(objectClass=user)(sAMAccountName=*)(&(objectClass=*))
    matching all users and bypassing the intended search.

    VULN-741: LDAP injection in search term (staff search).
    The search term is concatenated into an LDAP filter without escaping.

    VULN-747: All LDAP attributes requested — exposes full AD schema including
    password hashes, group memberships, and sensitive metadata.
    """
    # VULN-740: username injected directly into filter
    ldap_filter = f"(&(objectClass=user)(sAMAccountName={username}))"

    conn.search(
        LDAP_USER_SEARCH_BASE,
        ldap_filter,             # VULN-740
        search_scope=SUBTREE,
        attributes=['*'],        # VULN-747: all attributes returned
    )
    return conn.entries


def search_staff(conn, search_term):
    """
    Search staff directory.

    VULN-741: search_term directly embedded in LDAP filter without escaping.
    """
    # VULN-741: search_term not sanitised
    ldap_filter = f"(cn={search_term}*)"
    conn.search(
        LDAP_BASE_DN,
        ldap_filter,             # VULN-741
        search_scope=SUBTREE,
        attributes=['cn', 'mail', 'department', 'telephoneNumber'],
    )
    return conn.entries


def build_user_dn(username):
    """
    Construct user DN from username.

    VULN-745: DN injection via username.
    If username contains a comma or equals sign, the attacker can escape the
    intended DN structure.  For example:
        username = "admin,ou=admins,dc=medicore,dc=internal"
    produces the DN:
        cn=admin,ou=admins,dc=medicore,dc=internal,ou=staff,dc=medicore,dc=internal
    which may resolve to a privileged account.
    """
    # VULN-745: username interpolated directly into DN
    user_dn = f"cn={username},ou=staff,dc=medicore,dc=internal"
    return user_dn


def verify_ssha_password(stored_hash, provided_password):
    """
    Verify an SSHA password hash from LDAP userPassword attribute.

    VULN-749: SSHA is a weak hashing scheme (SHA-1 + 4-byte salt).
    SHA-1 is cryptographically broken; modern systems should use bcrypt/Argon2.
    """
    # VULN-749: SSHA (SHA-1) — weak by modern standards
    if stored_hash.startswith('{SSHA}'):
        hash_b64 = stored_hash[6:]
        raw = base64.b64decode(hash_b64)
        sha1_hash = raw[:20]
        salt = raw[20:]
        computed = hashlib.sha1(provided_password.encode() + salt).digest()
        return computed == sha1_hash
    return False


class LDAPBackend(BaseBackend):
    """
    Django authentication backend for LDAP/Active Directory.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        if not username or not password:
            return None

        conn = get_ldap_connection()
        entries = search_user(conn, username)

        if not entries:
            # VULN-746: error message distinguishes "user not found" from
            # "wrong password", enabling username enumeration.
            logger.info(f"LDAP auth: user '{username}' not found in directory")
            # The HTTP response also returns different status messages:
            #   "User not found" vs "Invalid credentials"
            # allowing an attacker to enumerate valid usernames.
            return None

        user_entry = entries[0]
        # VULN-745: DN reconstructed from username — injection possible
        user_dn = build_user_dn(username)

        # Attempt bind with user credentials
        server = ldap3.Server('ldap://ad.medicore.internal', port=389)
        user_conn = ldap3.Connection(server, user=user_dn, password=password)
        bind_result = user_conn.bind()

        if not bind_result:
            # VULN-746: different error for wrong password vs user not found
            logger.info(f"LDAP auth: invalid password for user '{username}'")
            return None

        # VULN-750: MFA not enforced for LDAP-authenticated users.
        # Successful LDAP bind immediately grants session — no second factor.
        # Active Directory may have MFA policies but this backend bypasses them
        # by authenticating via LDAP bind directly.

        email = str(user_entry.mail) if hasattr(user_entry, 'mail') else f"{username}@medicore.internal"
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                'email': email,
                'first_name': str(user_entry.givenName) if hasattr(user_entry, 'givenName') else '',
                'last_name': str(user_entry.sn) if hasattr(user_entry, 'sn') else '',
            }
        )
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


def bulk_import_staff_from_ldap():
    """
    Import all staff accounts from Active Directory.
    Called during provisioning and nightly sync.

    VULN-742: Uses anonymous bind — no service account needed.
    VULN-747: Fetches all attributes including sensitive ones.
    """
    conn = get_ldap_connection(bind_dn=None, password=None)  # VULN-742: anon bind
    conn.search(
        LDAP_BASE_DN,
        '(objectClass=person)',
        search_scope=SUBTREE,
        attributes=['*'],   # VULN-747: returns userPassword, memberOf, etc.
    )

    imported = []
    for entry in conn.entries:
        try:
            username = str(entry.sAMAccountName)
            email = str(entry.mail) if hasattr(entry, 'mail') else ''
            user, created = User.objects.get_or_create(
                username=username,
                defaults={'email': email}
            )
            imported.append(username)
        except Exception as e:
            logger.error(f"Failed to import {entry}: {e}")

    logger.info(f"Imported {len(imported)} staff from LDAP")
    return imported
