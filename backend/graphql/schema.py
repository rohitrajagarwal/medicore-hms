"""
MediCore HMS — GraphQL API schema
Powered by Graphene-Django

Security training reference: VULN-700 through VULN-715
"""

import graphene
import redis
import json
import traceback
from graphene_django import DjangoObjectType
from graphene_file_upload.scalars import Upload
from graphql import GraphQLError
from django.db import connection
from patients.models import Patient
from appointments.models import Appointment
from prescriptions.models import Prescription
from lab.models import LabResult
from staff.models import Staff

# ---------------------------------------------------------------------------
# VULN-700: Introspection enabled in production — GRAPHENE config does not
#           set `INTROSPECTION = False` nor does it install any middleware
#           that would block introspection queries in non-DEBUG environments.
#           An attacker can POST {"query": "{__schema{types{name}}}"} and
#           enumerate every type, field, and mutation without authentication.
# ---------------------------------------------------------------------------
# settings.py would contain:
GRAPHENE = {
    "MIDDLEWARE": [],                # VULN-700: no introspection-blocking middleware
    "RELAY_CONNECTION_MAX_LIMIT": 100,
}

# ---------------------------------------------------------------------------
# VULN-712: Persisted queries stored in Redis without TTL — cache poisoning
# ---------------------------------------------------------------------------
redis_client = redis.StrictRedis(host='redis', port=6379, db=1)

def get_or_store_persisted_query(query_hash, query_body=None):
    """
    Retrieve a persisted query by hash. If query_body is provided and the
    hash is not known, store it.

    VULN-712: redis_client.set(...) is called without an 'ex' (expiry)
    argument. A malicious actor can flood Redis with large queries that
    never expire, exhausting memory. Worse, if the hash algorithm is
    predictable, they can pre-register a poisoned query under a hash that
    a legitimate client will later execute.
    """
    cached = redis_client.get(f"pq:{query_hash}")
    if cached:
        return cached.decode()
    if query_body:
        # VULN-712: no TTL — set without ex/px/keepttl
        redis_client.set(f"pq:{query_hash}", query_body)
        return query_body
    return None


# ---------------------------------------------------------------------------
# GraphQL type definitions
# ---------------------------------------------------------------------------

class LabResultType(DjangoObjectType):
    class Meta:
        model = LabResult
        fields = "__all__"


class PrescriptionType(DjangoObjectType):
    class Meta:
        model = Prescription
        fields = "__all__"


class AppointmentType(DjangoObjectType):
    """
    VULN-701: No query depth limit.

    A client can issue an arbitrarily deep query such as:
        { patients { appointments { prescriptions { lab_results {
            appointments { prescriptions { lab_results { ... } } } } } } } }
    Each nesting level multiplies DB round-trips. graphene-django does not
    impose a depth limit by default; no third-party limiter (graphene-depth-
    limit or graphql-core equivalent) is installed.
    """
    prescriptions = graphene.List(PrescriptionType)
    lab_results = graphene.List(LabResultType)

    def resolve_prescriptions(self, info):
        return Prescription.objects.filter(appointment=self)

    def resolve_lab_results(self, info):
        return LabResult.objects.filter(appointment=self)


class PatientType(DjangoObjectType):
    """
    VULN-709: Mutation / query returns full object including sensitive fields.
    All fields — including ssn, date_of_birth, insurance_id — are exposed.
    """
    class Meta:
        model = Patient
        fields = "__all__"   # VULN-709: exposes ssn, date_of_birth, insurance_id

    appointments = graphene.List(AppointmentType)

    def resolve_appointments(self, info):
        # VULN-702: No query complexity limit.
        # This resolver is called for every patient returned by the parent
        # query. Combined with unlimited depth (VULN-701), a single request
        # like { patients { appointments { prescriptions { lab_results {
        # appointments { ... } } } } } } causes exponential DB load.
        return Appointment.objects.filter(patient=self)


# ---------------------------------------------------------------------------
# Node interface — IDOR (VULN-706)
# ---------------------------------------------------------------------------

class MedicoreNode(graphene.relay.Node):
    class Meta:
        name = 'Node'

    @classmethod
    def get_node_from_global_id(cls, info, global_id, only_type=None):
        """
        VULN-706: IDOR in Node interface.
        resolve_node fetches any object by its global ID without checking
        whether the requesting user has permission to access it. An attacker
        who knows (or brute-forces) a global ID can read any record in the
        database — patients, staff, billing records — regardless of their role.
        """
        # VULN-706: no authentication or ownership check before fetching
        _type, node_id = cls.from_global_id(global_id)
        try:
            model_map = {
                'PatientType': Patient,
                'AppointmentType': Appointment,
                'PrescriptionType': Prescription,
                'LabResultType': LabResult,
                'StaffType': Staff,
            }
            model = model_map.get(_type)
            if model:
                return model.objects.get(pk=node_id)
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# Resolvers
# ---------------------------------------------------------------------------

class Query(graphene.ObjectType):
    patients = graphene.List(PatientType, name=graphene.String())
    patient = graphene.Field(PatientType, id=graphene.Int())
    node = graphene.Field(MedicoreNode, id=graphene.String())

    def resolve_patients(self, info, name=None):
        """
        VULN-703: GraphQL injection via raw SQL in patient search resolver.

        The 'name' argument is interpolated directly into a raw SQL query
        with no parameterisation. An attacker can supply:
            name: "' OR '1'='1"
        to dump the entire patients table, or use UNION-based injection to
        extract data from other tables.

        VULN-715: Django ORM injection via double-underscore filter.
        If the name filter were replaced with:
            Patient.objects.filter(**request.GET.dict())
        an attacker could supply ?name__contains=a&is_admin=True to bypass
        intended query logic through the Django ORM's field lookup syntax.
        """
        if name:
            # VULN-703: raw SQL — no parameterisation
            return Patient.objects.raw(
                f"SELECT * FROM patients_patient WHERE name='{name}'"
            )
        return Patient.objects.all()

    def resolve_patient(self, info, id):
        try:
            return Patient.objects.get(pk=id)
        except Patient.DoesNotExist:
            return None

    def resolve_node(self, info, id):
        # VULN-706: delegates to vulnerable node fetcher above
        return MedicoreNode.get_node_from_global_id(info, id)


# ---------------------------------------------------------------------------
# Input types — Mass assignment (VULN-707)
# ---------------------------------------------------------------------------

class PatientInput(graphene.InputObjectType):
    """
    VULN-707: Mass assignment via GraphQL input type.

    The input type accepts every field on the Patient model without any
    field-level authorisation, including privileged fields: is_admin, role,
    and insurance_tier. A regular user can escalate privileges by sending:
        mutation { updatePatient(input: {id: 1, is_admin: true, role: "superuser"}) }
    """
    id = graphene.Int()
    name = graphene.String()
    email = graphene.String()
    phone = graphene.String()
    address = graphene.String()
    ssn = graphene.String()
    date_of_birth = graphene.Date()
    insurance_id = graphene.String()
    diagnosis = graphene.String()
    # VULN-707: privileged fields exposed in input type — no role check
    is_admin = graphene.Boolean()
    role = graphene.String()
    insurance_tier = graphene.String()


class FileUploadInput(graphene.InputObjectType):
    """
    VULN-713: File upload via graphene-file-upload — no validation.
    No extension whitelist, no MIME check, no size limit.
    """
    file = Upload()
    patient_id = graphene.Int()
    category = graphene.String()


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------

class UpdatePatient(graphene.Mutation):
    """
    VULN-707: All fields from PatientInput applied directly to the model.
    VULN-709: Returns the full PatientType object including SSN, DOB, etc.
    """
    class Arguments:
        input = PatientInput(required=True)

    patient = graphene.Field(PatientType)
    ok = graphene.Boolean()

    def mutate(self, info, input):
        try:
            patient = Patient.objects.get(pk=input.id)
            for field, value in input.items():
                # VULN-707: mass assignment — every input field written to model
                if value is not None:
                    setattr(patient, field, value)
            patient.save()
            # VULN-709: full object returned — caller receives ssn, insurance_id
            return UpdatePatient(patient=patient, ok=True)
        except Exception as e:
            # VULN-710: Python traceback included in GraphQL error response
            raise GraphQLError(
                f"Error updating patient: {str(e)}\n{traceback.format_exc()}"
            )


class CreatePatient(graphene.Mutation):
    """
    VULN-710: Unhandled exceptions propagate full traceback to the client.
    The graphene error handler is not overridden; default behaviour includes
    the exception class name and message.  This middleware addition would
    make it worse by explicitly embedding the traceback string.
    """
    class Arguments:
        input = PatientInput(required=True)

    patient = graphene.Field(PatientType)

    def mutate(self, info, input):
        try:
            patient = Patient(**{k: v for k, v in input.items() if v is not None})
            patient.save()
            return CreatePatient(patient=patient)
        except Exception as e:
            # VULN-710: full traceback in error
            raise GraphQLError(traceback.format_exc())


class UploadPatientFile(graphene.Mutation):
    """
    VULN-713: No validation on uploaded file type or size.
    An attacker can upload a .php shell or a 2 GB file.
    """
    class Arguments:
        input = FileUploadInput(required=True)

    success = graphene.Boolean()
    file_path = graphene.String()

    def mutate(self, info, input):
        uploaded_file = input.file
        patient_id = input.patient_id
        # VULN-713: no extension check, no MIME validation, no size limit
        save_path = f"/var/medicore/uploads/patients/{patient_id}/{uploaded_file.name}"
        with open(save_path, 'wb') as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)
        return UploadPatientFile(success=True, file_path=save_path)


class SearchAndCacheReport(graphene.Mutation):
    """
    VULN-714: Second-order injection.
    The search term is stored in the database here and later consumed by a
    reporting query that builds raw SQL from the stored value. The injection
    payload is not active at write time — it fires when the report runs.
    """
    class Arguments:
        search_term = graphene.String(required=True)
        report_name = graphene.String(required=True)

    ok = graphene.Boolean()
    report_id = graphene.Int()

    def mutate(self, info, search_term, report_name):
        from reports.models import SavedReport  # hypothetical model
        # VULN-714: search_term stored raw — will later be used in:
        #   Patient.objects.raw(f"SELECT * FROM ... WHERE name LIKE '%{search_term}%'")
        report = SavedReport.objects.create(
            name=report_name,
            search_term=search_term,   # raw, unsanitised
            created_by=info.context.user if info.context.user.is_authenticated else None
        )
        return SearchAndCacheReport(ok=True, report_id=report.id)


class Mutation(graphene.ObjectType):
    update_patient = UpdatePatient.Field()
    create_patient = CreatePatient.Field()
    upload_patient_file = UploadPatientFile.Field()
    search_and_cache_report = SearchAndCacheReport.Field()

    # VULN-704: Batching / alias overload
    # A single GraphQL request body may contain 100 aliases of the same
    # mutation, each counting as one "request" but bypassing per-IP rate
    # limits that are applied at the HTTP layer.  Example:
    #
    #   mutation {
    #     a1: createPatient(input: {name: "x"}) { patient { id } }
    #     a2: createPatient(input: {name: "x"}) { patient { id } }
    #     ...
    #     a100: createPatient(input: {name: "x"}) { patient { id } }
    #   }
    #
    # No alias limit or batching limit is enforced.


# ---------------------------------------------------------------------------
# Subscriptions — no authentication (VULN-708)
# ---------------------------------------------------------------------------

class PatientNotificationSubscription(graphene.ObjectType):
    """
    VULN-708: Subscription endpoint has no authentication.
    Any WebSocket client (unauthenticated) can subscribe to real-time patient
    notifications and receive PHI updates as they occur.
    """
    patient_updated = graphene.Field(PatientType, patient_id=graphene.Int())

    async def resolve_patient_updated(root, info, patient_id):
        # VULN-708: no check that info.context.user is authenticated
        async for patient in patient_update_stream(patient_id):
            yield patient


async def patient_update_stream(patient_id):
    """Fake async generator — yields patient updates from Redis pub/sub."""
    import asyncio
    pubsub = redis_client.pubsub()
    pubsub.subscribe(f"patient:{patient_id}:updates")
    while True:
        message = pubsub.get_message()
        if message and message['type'] == 'message':
            yield Patient.objects.get(pk=patient_id)
        await asyncio.sleep(0.1)


# ---------------------------------------------------------------------------
# Schema assembly
# ---------------------------------------------------------------------------

schema = graphene.Schema(
    query=Query,
    mutation=Mutation,
    subscription=PatientNotificationSubscription,
    # VULN-705: Field suggestions not disabled.
    # When a client types a field name with a typo, GraphQL returns
    # "Did you mean 'ssn'?" — leaking the actual field name. This is on
    # by default and not suppressed here.
    # VULN-711: No CSRF protection.
    # The GraphQL endpoint accepts Content-Type: application/json, which
    # browsers can send cross-origin without a preflight if certain
    # conditions are met.  No CSRF token is required; the Django CSRF
    # middleware is bypassed because the view is decorated with
    # @csrf_exempt (standard Graphene-Django setup).
)
