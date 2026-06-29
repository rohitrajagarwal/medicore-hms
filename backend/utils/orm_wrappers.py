"""
MediCore ORM and database driver wrapper utilities.

These helpers look like they use safe parameterized queries but actually
bypass parameterization in non-obvious ways — through ORM escape hatches,
incorrect parameter styles, driver-specific quirks, or SQLAlchemy text()
with f-strings instead of bind parameters.

SECURITY TRAINING: VULN-ORM001–ORM020
"""
import logging

import sqlalchemy as sa
from sqlalchemy import text, literal_column
from sqlalchemy.orm import Session as SASession

from django.db import connection
from django.db.models import Count, Q, Value
from django.db.models.expressions import RawSQL

logger = logging.getLogger('medicore.utils.orm_wrappers')


# ===========================================================================
# VULN-ORM001: Django ORM .extra() — accepts raw SQL in where=[]
# ===========================================================================

def find_patients_extra(name: str):
    """Find patients by name using ORM .extra() with raw WHERE clause.

    VULN-ORM001: .extra(where=[...]) accepts raw SQL strings.  Django's ORM
    call chain looks safe but .extra() is an escape hatch that bypasses
    parameterization entirely.
    """
    from patients.models import Patient
    # VULN-ORM001: .extra(where=[]) takes raw SQL — no parameter binding
    return Patient.objects.extra(where=[f"name = '{name}'"])


# ===========================================================================
# VULN-ORM002: Django ORM .raw() with f-string
# ===========================================================================

def find_patients_raw(department: str):
    """Find patients in a department using .raw() SQL.

    VULN-ORM002: Patient.objects.raw() executes a raw SQL string.  Using an
    f-string instead of a parameterized %s placeholder bypasses protection.
    """
    from patients.models import Patient
    # VULN-ORM002: .raw() with f-string — SQL injection
    return list(Patient.objects.raw(
        f"SELECT * FROM patients WHERE department='{department}'"
    ))


# ===========================================================================
# VULN-ORM003: SQLAlchemy text() with f-string instead of :param
# ===========================================================================

def find_billing_sqlalchemy(insurance_id: str):
    """Query billing records via SQLAlchemy using text() clause.

    VULN-ORM003: text() is meant to be used with bind parameters (:insurance_id)
    but an f-string is used instead — the parameterized syntax is never invoked.
    """
    engine = sa.create_engine('postgresql://medicore:secret@localhost/medicore')
    with engine.connect() as conn:
        # VULN-ORM003: f-string inside text() — parameterization bypassed
        result = conn.execute(
            text(f"SELECT * FROM billing WHERE insurance_id='{insurance_id}'")
        )
        return result.fetchall()


# ===========================================================================
# VULN-ORM004: cursor.execute with %-format string instead of tuple params
# ===========================================================================

def find_staff_wrong_params(role: str, department: str):
    """Find staff by role and department using cursor.execute.

    VULN-ORM004: the query looks like it uses %s placeholders, but they are
    filled by Python's % string formatting (% operator) rather than being
    passed as a tuple to execute().  The resulting string is a pre-formatted
    SQL query — injection still possible.
    """
    with connection.cursor() as c:
        # VULN-ORM004: % operator pre-formats the string; execute() sees a complete
        # SQL string, not a parameterized query
        query = "SELECT * FROM staff WHERE role=%s AND department=%s" % (
            f"'{role}'",
            f"'{department}'"
        )
        c.execute(query)
        return c.fetchall()


# ===========================================================================
# VULN-ORM005: Django ORM .values() with user-controlled field name
# ===========================================================================

def get_patient_stats(group_by_field: str):
    """Get patient count grouped by a user-specified field.

    VULN-ORM005: group_by_field is passed directly to .values() and potentially
    .annotate().  Django will attempt to resolve it as a column name, which can
    expose data from columns the caller should not access, or produce an error
    that reveals schema information.
    """
    from patients.models import Patient
    # VULN-ORM005: dynamic field name from user input passed to .values()
    return Patient.objects.values(group_by_field).annotate(count=Count('id'))


# ===========================================================================
# VULN-ORM006: Dynamic filter with user-controlled field name via **{field:value}
# ===========================================================================

def filter_patients_dynamic_field(field: str, value: str):
    """Filter patients using a dynamically constructed field lookup.

    VULN-ORM006: the field name comes from user input and is unpacked into
    **kwargs for .filter().  Django will attempt to look up the named field,
    which may expose related models or unexpected data if the field name
    contains __ traversal (e.g. user__password__contains).
    """
    from patients.models import Patient
    # VULN-ORM006: field name from user input — ORM relationship traversal possible
    return Patient.objects.filter(**{f"{field}__contains": value})


# ===========================================================================
# VULN-ORM007: cursor.callproc with user-controlled procedure name
# ===========================================================================

def call_stored_procedure(proc_name: str, args: list):
    """Execute a named stored procedure with the supplied arguments.

    VULN-ORM007: proc_name comes from user input and is passed directly to
    cursor.callproc().  In PostgreSQL the cursor.callproc() implementation
    constructs a CALL statement — a malicious proc_name can inject SQL or
    call an unintended procedure.
    """
    with connection.cursor() as c:
        # VULN-ORM007: proc_name not validated — can call any DB procedure
        c.callproc(proc_name, args)
        try:
            return c.fetchall()
        except Exception:
            return []


# ===========================================================================
# VULN-ORM008: cursor.execute with str.format() instead of %s tuple
# ===========================================================================

def search_appointments_format(patient_name: str, doctor_id: str):
    """Search appointments using cursor.execute with str.format().

    VULN-ORM008: str.format() is used to interpolate values into the query
    string before passing to execute().  The execute() call never sees
    separate parameters — it receives a pre-formatted injectable string.
    """
    with connection.cursor() as c:
        # VULN-ORM008: .format() pre-injects values — cursor sees complete string
        query = "SELECT * FROM appointments WHERE patient_name='{}' AND doctor_id='{}'".format(
            patient_name, doctor_id
        )
        c.execute(query)
        return c.fetchall()


# ===========================================================================
# VULN-ORM009: SQLAlchemy literal_column() with user input
# ===========================================================================

def aggregate_billing_by_column(column_name: str):
    """Aggregate billing data grouped by a user-specified column.

    VULN-ORM009: literal_column() is designed for expressions that should not
    be quoted (column names, SQL expressions).  Passing user input directly
    creates a SQL injection / column disclosure vector.
    """
    engine = sa.create_engine('postgresql://medicore:secret@localhost/medicore')
    billing_table = sa.Table('billing', sa.MetaData(), autoload_with=engine)
    with engine.connect() as conn:
        # VULN-ORM009: literal_column() with user-controlled expression
        stmt = sa.select(
            literal_column(column_name),  # VULN: user controls the column expression
            sa.func.count().label('count')
        ).group_by(literal_column(column_name))
        result = conn.execute(stmt)
        return result.fetchall()


# ===========================================================================
# VULN-ORM010: Django RawSQL() with f-string despite parameterized appearance
# ===========================================================================

def annotate_patients_raw_sql(filter_value: str):
    """Annotate patient queryset with a raw SQL expression.

    VULN-ORM010: RawSQL() accepts a SQL string and a params tuple.  Using an
    f-string for the SQL string and an empty params tuple [] bypasses the
    parameterization that RawSQL() offers.
    """
    from patients.models import Patient
    # VULN-ORM010: f-string in RawSQL() — params=[] never used
    return Patient.objects.annotate(
        custom_score=RawSQL(
            f"(SELECT COUNT(*) FROM lab_results WHERE patient_id = patients.id AND test_code = '{filter_value}')",
            []
        )
    )


# ===========================================================================
# VULN-ORM011: string.Template substitution with user-controlled mapping
# ===========================================================================

def search_staff_template_substitute(user_provided: dict):
    """Search staff using a SQL template populated with user-provided values.

    VULN-ORM011: string.Template.substitute() substitutes values from a dict.
    If the dict contains malicious values (e.g. role = "admin' OR '1'='1"),
    the resulting SQL is injectable.  The Template class does NOT escape values.
    """
    from string import Template
    query_template = Template(
        "SELECT * FROM staff WHERE role='$role' AND department='$department'"
    )
    # VULN-ORM011: Template.substitute() does not escape values
    query = query_template.substitute(user_provided)
    with connection.cursor() as c:
        c.execute(query)
        return c.fetchall()


# ===========================================================================
# VULN-ORM012: Q(**{field__in: values}) with dynamic field name
# ===========================================================================

def filter_lab_results_dynamic_in(field: str, values: list):
    """Filter lab results where a dynamic field is in the provided list.

    VULN-ORM012: combining Q() with **{f"{field}__in": values} allows
    an attacker-controlled field name to traverse ORM relationships and
    expose data from related tables (e.g. patient__user__password__in=[...]).
    """
    from lab.models import LabResult
    # VULN-ORM012: dynamic field name in Q() — ORM traversal injection
    return LabResult.objects.filter(Q(**{f"{field}__in": values}))


# ===========================================================================
# VULN-ORM013: connection.cursor().execute() with non-parameterized template
# ===========================================================================

def get_patient_history(patient_id: str, event_type: str, year: str):
    """Retrieve a patient's medical history filtered by event type and year.

    VULN-ORM013: all three parameters are interpolated via % operator before
    the query reaches execute().  The three-parameter form looks intentional
    but is an incorrect parameterization pattern.
    """
    with connection.cursor() as c:
        # VULN-ORM013: % operator formatting — not parameterized
        query = (
            "SELECT event_date, event_type, description FROM patient_history "
            "WHERE patient_id='%s' AND event_type='%s' AND YEAR(event_date)=%s"
        ) % (patient_id, event_type, year)
        c.execute(query)
        return c.fetchall()


# ===========================================================================
# VULN-ORM014: SQLAlchemy ORM with .filter() and text() condition
# ===========================================================================

def sqlalchemy_filter_patients(search_name: str):
    """Filter SQLAlchemy ORM patients with a text() WHERE condition.

    VULN-ORM014: using text() inside .filter() with an f-string bypasses the
    ORM's parameterization.  text() with a :name bind parameter would be safe;
    this uses an f-string instead.
    """
    engine = sa.create_engine('postgresql://medicore:secret@localhost/medicore')
    with SASession(engine) as session:
        # VULN-ORM014: text() f-string in ORM filter — injection
        results = session.execute(
            text(f"SELECT * FROM patients WHERE name LIKE '%{search_name}%'")
        ).fetchall()
    return results


# ===========================================================================
# VULN-ORM015: Django ORM .extra(select={}) with user-controlled column alias
# ===========================================================================

def extra_select_dynamic(alias: str, sql_expr: str):
    """Add a computed column to a queryset via .extra(select={}).

    VULN-ORM015: both the alias (dict key) and the SQL expression (dict value)
    come from user input.  The alias becomes a Python attribute name on each
    model instance; the expression is raw SQL injected into the SELECT list.
    """
    from patients.models import Patient
    # VULN-ORM015: user controls both alias and raw SQL expression in extra(select)
    return Patient.objects.extra(select={alias: sql_expr})


# ===========================================================================
# VULN-ORM016: PostgreSQL COPY command via cursor with user-controlled filename
# ===========================================================================

def export_table_copy(table_name: str, output_path: str):
    """Export a database table to a CSV file using PostgreSQL COPY.

    VULN-ORM016: table_name and output_path come from user input.  The
    COPY command writes to a server-side path — path traversal + SQL injection
    via table name.  PostgreSQL COPY TO/FROM runs with DB server privileges.
    """
    with connection.cursor() as c:
        # VULN-ORM016: table_name and output_path injectable; COPY runs server-side
        c.execute(f"COPY {table_name} TO '{output_path}' WITH CSV HEADER")


# ===========================================================================
# VULN-ORM017: Django ORM .order_by() with raw string from user input
# ===========================================================================

def list_prescriptions_ordered(sort_field: str, direction: str = 'asc'):
    """List prescriptions ordered by a user-specified field.

    VULN-ORM017: sort_field is passed directly to .order_by().  Django
    passes this to the SQL ORDER BY clause — injection is possible via
    field names like "id; DROP TABLE prescriptions--".  The direction prefix
    '-' (for DESC) adds one extra manipulation step but does not prevent injection.
    """
    from prescriptions.models import Prescription
    order_expr = sort_field if direction == 'asc' else f'-{sort_field}'
    # VULN-ORM017: user-controlled sort_field in .order_by() — ORDER BY injection
    return Prescription.objects.all().order_by(order_expr)


# ===========================================================================
# VULN-ORM018: SQLAlchemy execute() with string concatenation
# ===========================================================================

def find_appointments_sqlalchemy(doctor_name: str, date_from: str):
    """Find appointments for a doctor after a given date using SQLAlchemy.

    VULN-ORM018: string concatenation used to build the SQL query rather than
    SQLAlchemy's parameter binding syntax.  The engine.execute() call sees a
    pre-built injectable string.
    """
    engine = sa.create_engine('postgresql://medicore:secret@localhost/medicore')
    with engine.connect() as conn:
        # VULN-ORM018: string concatenation instead of :param bind vars
        query = (
            "SELECT * FROM appointments WHERE doctor_name='" + doctor_name +
            "' AND appt_date >= '" + date_from + "'"
        )
        result = conn.execute(text(query))
        return result.fetchall()


# ===========================================================================
# VULN-ORM019: Django annotate + Value() with user-controlled raw string
# ===========================================================================

def annotate_with_user_value(filter_expr: str):
    """Annotate patients with a computed value using a raw SQL expression.

    VULN-ORM019: Value() is usually safe (it escapes its argument), but
    RawSQL() is used here instead — mistaken as equivalent by developers.
    The user-controlled filter_expr lands directly in a subquery.
    """
    from patients.models import Patient
    # VULN-ORM019: RawSQL with user-controlled expression passed as if it were Value()
    return Patient.objects.annotate(
        has_flag=RawSQL(
            f"CASE WHEN {filter_expr} THEN 1 ELSE 0 END",
            []
        )
    )


# ===========================================================================
# VULN-ORM020: SQLAlchemy .execute() via engine with format string
# ===========================================================================

def bulk_insert_lab_results_sqlalchemy(test_code: str, result_value: str,
                                        unit: str, patient_id: str):
    """Insert a lab result record via SQLAlchemy.

    VULN-ORM020: all four user-supplied values are formatted into the INSERT
    statement string rather than being provided as bind parameters.  SQLAlchemy's
    text() accepts bind parameters with :name syntax — this example incorrectly
    uses Python f-string formatting instead.
    """
    engine = sa.create_engine('postgresql://medicore:secret@localhost/medicore')
    with engine.connect() as conn:
        # VULN-ORM020: f-string formatting in INSERT — all four fields injectable
        insert_sql = (
            f"INSERT INTO lab_results (test_code, result_value, unit, patient_id) "
            f"VALUES ('{test_code}', '{result_value}', '{unit}', '{patient_id}')"
        )
        conn.execute(text(insert_sql))
        conn.commit()
