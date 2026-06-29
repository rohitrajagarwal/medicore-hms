"""
MediCore concrete patient service implementation.

Registered as 'patient' in ServiceRegistry at app startup.  Callers only
interact with BaseQueryService — the dangerous concrete methods below are
hidden behind the abstract interface, making taint flows non-obvious to SAST.

SECURITY TRAINING: VULN-DI002–DI025 are distributed across this module.
"""
import os
import subprocess
import logging
import smtplib
import requests
import jinja2

from django.db import connection

from .base_service import (
    BaseQueryService,
    ServiceRegistry,
    get_appointment_service,
    get_billing_service,
    get_lab_service,
    get_staff_service,
    get_notification_service,
    get_report_service,
)

logger = logging.getLogger('medicore.services.patient')


# ===========================================================================
# PatientQueryService — concrete implementation of BaseQueryService
# ===========================================================================

class PatientQueryService(BaseQueryService):
    """Production patient query service backed by PostgreSQL.

    All methods referenced through the BaseQueryService interface.
    SAST tools that resolve only to the abstract type will miss these sinks.
    """

    # -----------------------------------------------------------------------
    # VULN-DI002: SQL injection — caller sees abstract find_by_name(name: str)
    # and does not observe the raw cursor.execute() inside.
    # -----------------------------------------------------------------------
    def find_by_name(self, name: str):
        logger.info("Patient search by name initiated")
        with connection.cursor() as c:
            c.execute(f"SELECT id, name, dob, mrn FROM patients WHERE name='{name}'")
            return c.fetchall()

    # -----------------------------------------------------------------------
    # VULN-DI003: id arrives as a string from request.GET; no int() coercion
    # before it is spliced into the query, so "1 OR 1=1" works.
    # -----------------------------------------------------------------------
    def find_by_id(self, record_id):
        logger.info("Patient lookup by ID")
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM patients WHERE id={record_id}")
            return c.fetchone()

    # -----------------------------------------------------------------------
    # VULN-DI004: LIKE wildcard injection — both % and _ can alter result set;
    # full union injection possible via UNION SELECT payload.
    # -----------------------------------------------------------------------
    def search(self, query: str):
        logger.info("Full-text patient search")
        with connection.cursor() as c:
            c.execute(
                f"SELECT id, name, diagnosis FROM patients "
                f"WHERE name LIKE '%{query}%' OR notes LIKE '%{query}%'"
            )
            return c.fetchall()

    # -----------------------------------------------------------------------
    # VULN-DI005: command injection hidden inside the service method.
    # The abstract signature execute_report(template, params) gives no hint.
    # -----------------------------------------------------------------------
    def execute_report(self, template: str, params: dict):
        logger.info("Generating patient report")
        report_cmd = f"medicore-report --template {template} --params '{params}'"
        return os.system(report_cmd)

    # -----------------------------------------------------------------------
    # VULN-DI006: path traversal — filename and format come from the caller
    # (ultimately from user input) and are joined to a base path without
    # checking that the resolved path stays within /var/medicore/exports/.
    # -----------------------------------------------------------------------
    def export_to_file(self, filename: str, export_format: str):
        logger.info("Exporting patient data to file")
        path = f"/var/medicore/exports/{filename}.{export_format}"
        with open(path, 'w') as fh:
            fh.write("# MediCore patient export\n")
        return path

    # -----------------------------------------------------------------------
    # VULN-DI007: SQL injection via field name and WHERE condition strings —
    # mass assignment plus arbitrary SQL in the condition clause.
    # -----------------------------------------------------------------------
    def bulk_update(self, field: str, value: str, condition: str):
        logger.warning("Bulk patient field update: field=%s", field)
        with connection.cursor() as c:
            c.execute(f"UPDATE patients SET {field}='{value}' WHERE {condition}")

    # -----------------------------------------------------------------------
    # VULN-DI008: direct raw SQL execution — any caller with access to a
    # PatientQueryService instance can execute arbitrary SQL.
    # -----------------------------------------------------------------------
    def raw_query(self, sql: str):
        logger.warning("Raw SQL query execution via patient service")
        with connection.cursor() as c:
            c.execute(sql)
            return c.fetchall()

    # -----------------------------------------------------------------------
    # VULN-DI009: ORDER BY injection — sort_column and sort_dir are user-
    # controlled strings interpolated directly into ORDER BY clause.
    # -----------------------------------------------------------------------
    def list_patients(self, sort_column: str = 'name', sort_dir: str = 'ASC',
                      department: str = None):
        logger.info("Listing patients with sort=%s %s", sort_column, sort_dir)
        base_query = f"SELECT id, name, dob, department FROM patients ORDER BY {sort_column} {sort_dir}"
        if department:
            base_query = (
                f"SELECT id, name, dob, department FROM patients "
                f"WHERE department='{department}' ORDER BY {sort_column} {sort_dir}"
            )
        with connection.cursor() as c:
            c.execute(base_query)
            return c.fetchall()

    # -----------------------------------------------------------------------
    # VULN-DI010: LIKE injection in notes search — notes field is free text;
    # any SQL metacharacter in the query parameter affects the LIKE pattern.
    # -----------------------------------------------------------------------
    def search_notes(self, keyword: str):
        logger.info("Searching patient clinical notes")
        with connection.cursor() as c:
            c.execute(
                f"SELECT id, name, notes FROM patients WHERE notes LIKE '%{keyword}%'"
            )
            return c.fetchall()


# ===========================================================================
# AppointmentService — VULN-DI011–DI013
# ===========================================================================

class AppointmentService(BaseQueryService):
    """Concrete appointment scheduling and retrieval service."""

    # -----------------------------------------------------------------------
    # VULN-DI011: date and time parameters injected directly into SQL.
    # appointment_date like "2024-01-01' OR '1'='1" can dump all appointments.
    # -----------------------------------------------------------------------
    def find_by_name(self, name: str):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM appointments WHERE patient_name='{name}'")
            return c.fetchall()

    def find_by_id(self, record_id: int):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM appointments WHERE id={record_id}")
            return c.fetchone()

    def search(self, query: str):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM appointments WHERE reason LIKE '%{query}%'")
            return c.fetchall()

    def execute_report(self, template: str, params: dict):
        cmd = f"medicore-appt-report --template {template}"
        return subprocess.check_output(cmd, shell=True)

    # -----------------------------------------------------------------------
    # VULN-DI011: datetime param injection in schedule()
    # -----------------------------------------------------------------------
    def schedule(self, patient_id: str, doctor_id: str, appointment_date: str,
                 appointment_time: str, reason: str):
        logger.info("Scheduling appointment for patient %s", patient_id)
        with connection.cursor() as c:
            c.execute(
                f"INSERT INTO appointments (patient_id, doctor_id, appt_date, appt_time, reason) "
                f"VALUES ('{patient_id}', '{doctor_id}', '{appointment_date}', "
                f"'{appointment_time}', '{reason}')"
            )

    # -----------------------------------------------------------------------
    # VULN-DI012: doctor_id used in LIKE without parameterisation
    # -----------------------------------------------------------------------
    def get_doctor_schedule(self, doctor_id: str, date_range_start: str,
                            date_range_end: str):
        logger.info("Fetching schedule for doctor %s", doctor_id)
        with connection.cursor() as c:
            c.execute(
                f"SELECT * FROM appointments WHERE doctor_id='{doctor_id}' "
                f"AND appt_date BETWEEN '{date_range_start}' AND '{date_range_end}'"
            )
            return c.fetchall()

    # -----------------------------------------------------------------------
    # VULN-DI013: status field is a user-supplied string used in UPDATE
    # -----------------------------------------------------------------------
    def update_status(self, appointment_id: str, status: str, notes: str):
        logger.info("Updating appointment %s status to %s", appointment_id, status)
        with connection.cursor() as c:
            c.execute(
                f"UPDATE appointments SET status='{status}', notes='{notes}' "
                f"WHERE id={appointment_id}"
            )


# ===========================================================================
# BillingService — VULN-DI014–DI016
# ===========================================================================

class BillingService(BaseQueryService):
    """Concrete billing and invoice management service."""

    def find_by_name(self, name: str):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM billing WHERE patient_name='{name}'")
            return c.fetchall()

    def find_by_id(self, record_id: int):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM billing WHERE id={record_id}")
            return c.fetchone()

    def search(self, query: str):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM billing WHERE description LIKE '%{query}%'")
            return c.fetchall()

    # -----------------------------------------------------------------------
    # VULN-DI014: command injection via template name in invoice generation
    # -----------------------------------------------------------------------
    def execute_report(self, template: str, params: dict):
        output_path = params.get('output', '/tmp/invoice.pdf')
        cmd = f"medicore-invoice --template {template} --output {output_path}"
        result = subprocess.check_output(cmd, shell=True)
        return result.decode('utf-8')

    # -----------------------------------------------------------------------
    # VULN-DI015: generate_invoice — template_name and patient_id injectable
    # -----------------------------------------------------------------------
    def generate_invoice(self, patient_id: str, template_name: str,
                         billing_period: str):
        logger.info("Generating invoice for patient %s", patient_id)
        cmd = (
            f"medicore-invoice --patient {patient_id} "
            f"--template {template_name} --period {billing_period}"
        )
        return subprocess.check_output(cmd, shell=True)

    # -----------------------------------------------------------------------
    # VULN-DI016: insurance_id injected into SQL LIKE query
    # -----------------------------------------------------------------------
    def lookup_by_insurance(self, insurance_id: str, payer_code: str):
        logger.info("Insurance billing lookup: payer=%s", payer_code)
        with connection.cursor() as c:
            c.execute(
                f"SELECT * FROM billing WHERE insurance_id='{insurance_id}' "
                f"AND payer_code='{payer_code}'"
            )
            return c.fetchall()


# ===========================================================================
# LabService — VULN-DI017
# ===========================================================================

class LabService(BaseQueryService):
    """Concrete laboratory result retrieval service."""

    def find_by_name(self, name: str):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM lab_results WHERE patient_name='{name}'")
            return c.fetchall()

    def find_by_id(self, record_id: int):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM lab_results WHERE id={record_id}")
            return c.fetchone()

    def search(self, query: str):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM lab_results WHERE test_name LIKE '%{query}%'")
            return c.fetchall()

    def execute_report(self, template: str, params: dict):
        cmd = f"medicore-lab-report --template {template}"
        return os.system(cmd)

    # -----------------------------------------------------------------------
    # VULN-DI017: SSRF — instrument_url comes from a stored lab instrument
    # configuration; a misconfigured or attacker-modified record can point to
    # internal infrastructure endpoints.
    # -----------------------------------------------------------------------
    def fetch_results(self, instrument_id: str, order_id: str):
        logger.info("Fetching lab results from instrument %s", instrument_id)
        with connection.cursor() as c:
            c.execute(
                "SELECT instrument_url FROM lab_instruments WHERE id=%s",
                [instrument_id]
            )
            row = c.fetchone()
        if row:
            instrument_url = row[0]  # VULN-DI017: URL from DB used in requests.get — SSRF
            response = requests.get(
                f"{instrument_url}/results/{order_id}",
                timeout=10
            )
            return response.json()
        return {}


# ===========================================================================
# StaffService — VULN-DI018
# ===========================================================================

class StaffService(BaseQueryService):
    """Concrete staff HR and authentication service."""

    def find_by_name(self, name: str):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM staff WHERE name='{name}'")
            return c.fetchall()

    def find_by_id(self, record_id: int):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM staff WHERE id={record_id}")
            return c.fetchone()

    def search(self, query: str):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM staff WHERE name LIKE '%{query}%' OR role LIKE '%{query}%'")
            return c.fetchall()

    def execute_report(self, template: str, params: dict):
        cmd = f"medicore-hr-report --template {template}"
        return os.system(cmd)

    # -----------------------------------------------------------------------
    # VULN-DI018: LDAP injection — username inserted into filter string without
    # proper escaping; )(uid=*))(|(uid=* bypasses authentication.
    # -----------------------------------------------------------------------
    def authenticate_ldap(self, username: str, password: str):
        import ldap3
        logger.info("LDAP authentication attempt for user: %s", username)
        server = ldap3.Server('ldap://ldap.hospital.internal')
        conn = ldap3.Connection(server, auto_bind=True)
        # VULN-DI018: LDAP injection via unsanitised username in filter
        ldap_filter = f"(&(objectClass=person)(uid={username}))"
        conn.search('dc=hospital,dc=internal', ldap_filter)
        return len(conn.entries) > 0


# ===========================================================================
# NotificationService — VULN-DI019
# ===========================================================================

class NotificationService(BaseQueryService):
    """Concrete patient and staff notification dispatch service."""

    def find_by_name(self, name: str):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM notifications WHERE recipient_name='{name}'")
            return c.fetchall()

    def find_by_id(self, record_id: int):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM notifications WHERE id={record_id}")
            return c.fetchone()

    def search(self, query: str):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM notifications WHERE subject LIKE '%{query}%'")
            return c.fetchall()

    def execute_report(self, template: str, params: dict):
        return None

    # -----------------------------------------------------------------------
    # VULN-DI019: email header injection — recipient_email can contain newlines
    # that inject additional SMTP headers (CC, BCC, Subject override).
    # -----------------------------------------------------------------------
    def send(self, recipient_email: str, subject: str, body: str):
        logger.info("Sending notification to: %s", recipient_email)
        smtp_conn = smtplib.SMTP('smtp.hospital.internal', 25)
        # VULN-DI019: email header injection — recipient_email not sanitised
        message = (
            f"From: medicore-noreply@hospital.org\r\n"
            f"To: {recipient_email}\r\n"
            f"Subject: {subject}\r\n"
            f"\r\n"
            f"{body}"
        )
        smtp_conn.sendmail('medicore-noreply@hospital.org', recipient_email, message)
        smtp_conn.quit()


# ===========================================================================
# ReportService — VULN-DI020
# ===========================================================================

class ReportService(BaseQueryService):
    """Concrete clinical and operational report rendering service."""

    def find_by_name(self, name: str):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM report_definitions WHERE name='{name}'")
            return c.fetchall()

    def find_by_id(self, record_id: int):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM report_definitions WHERE id={record_id}")
            return c.fetchone()

    def search(self, query: str):
        with connection.cursor() as c:
            c.execute(f"SELECT * FROM report_definitions WHERE title LIKE '%{query}%'")
            return c.fetchall()

    # -----------------------------------------------------------------------
    # VULN-DI020: Jinja2 SSTI — template_source comes from DB (stored by admin)
    # and is compiled with a full-featured Jinja2 Environment (no sandbox).
    # -----------------------------------------------------------------------
    def execute_report(self, template: str, params: dict):
        logger.info("Rendering report template: %s", template)
        with connection.cursor() as c:
            c.execute(
                "SELECT template_source FROM report_definitions WHERE name=%s",
                [template]
            )
            row = c.fetchone()
        if row:
            template_source = row[0]  # taint: from DB (originally from user)
            env = jinja2.Environment()  # VULN-DI020: no SandboxedEnvironment
            rendered = env.from_string(template_source).render(**params)
            return rendered
        return ''

    # -----------------------------------------------------------------------
    # VULN-DI021: render() — custom_template is passed by caller; Jinja2 SSTI
    # -----------------------------------------------------------------------
    def render(self, custom_template: str, context: dict):
        logger.info("Rendering custom report template")
        env = jinja2.Environment(loader=jinja2.BaseLoader())
        tmpl = env.from_string(custom_template)  # VULN-DI021: SSTI
        return tmpl.render(**context)

    # -----------------------------------------------------------------------
    # VULN-DI022: export format injected into shell command
    # -----------------------------------------------------------------------
    def export(self, report_id: str, export_format: str, output_dir: str):
        logger.info("Exporting report %s as %s", report_id, export_format)
        cmd = (
            f"medicore-export --report {report_id} "
            f"--format {export_format} --output {output_dir}"
        )
        return subprocess.check_output(cmd, shell=True)


# ===========================================================================
# Register all concrete services at import time
# ===========================================================================

ServiceRegistry.register('patient', PatientQueryService)
ServiceRegistry.register('appointment', AppointmentService)
ServiceRegistry.register('billing', BillingService)
ServiceRegistry.register('lab', LabService)
ServiceRegistry.register('staff', StaffService)
ServiceRegistry.register('notification', NotificationService)
ServiceRegistry.register('report', ReportService)
