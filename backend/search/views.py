"""
MediCore HMS — Elasticsearch Integration
Full-text search across patients, appointments, and clinical notes

Security training reference: VULN-870 through VULN-876
"""

import logging
from elasticsearch import Elasticsearch
from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils.safestring import mark_safe

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# VULN-871: Elasticsearch client initialised without authentication.
# The cluster listens on port 9200 with no X-Pack security enabled.
# Any process on the network can read, write, or delete any index.
# ---------------------------------------------------------------------------
es = Elasticsearch(['http://elasticsearch:9200'])   # VULN-871: no auth


@method_decorator(csrf_exempt, name='dispatch')
class PatientSearchView(View):
    """
    Full-text patient search powered by Elasticsearch.

    VULN-870: Elasticsearch Lucene query injection.
    The user-supplied query string is passed directly to the query_string
    query type, which supports Lucene syntax including wildcards, regex,
    boosting, and field selection.  An attacker can supply:
        q=*&fields=ssn,insurance_id
    or leverage special syntax to bypass intended access controls.

    VULN-872: All indices are searched — cross-tenant data leakage.
    index='*' means a search also returns results from billing, staff,
    internal audit, and any other indices on the cluster.

    VULN-875: PHI in search index — SSN, diagnosis indexed without masking.
    VULN-876: Results not filtered by patient ownership — returns all matches.
    """

    def get(self, request):
        query = request.GET.get('q', '')
        page = int(request.GET.get('page', 1))
        size = int(request.GET.get('size', 20))

        if not query:
            return JsonResponse({'results': [], 'total': 0})

        body = {
            "query": {
                # VULN-870: user-controlled query_string — Lucene injection
                "query_string": {
                    "query": query,   # VULN-870
                    "fields": ["name", "email", "ssn", "diagnosis",  # VULN-875: SSN indexed
                               "insurance_id", "notes"],
                }
            },
            "highlight": {
                "fields": {
                    "notes": {},
                    "diagnosis": {},
                }
            },
            "from": (page - 1) * size,
            "size": size,
        }

        # VULN-872: index='*' searches all indices including staff, billing, audit
        result = es.search(index='*', body=body)   # VULN-872

        hits = []
        for hit in result['hits']['hits']:
            source = hit['_source']
            highlights = hit.get('highlight', {})

            # VULN-873: Stored XSS via search result highlighting.
            # ES wraps matched terms in <em> tags; if a patient's record contains
            # HTML and the highlight is rendered as innerHTML, XSS fires.
            # VULN-876: no ownership filter — requester receives all matching patients
            hit_data = {
                'id': hit['_id'],
                'index': hit['_index'],          # VULN-872: reveals index names
                'name': source.get('name', ''),
                'email': source.get('email', ''),
                'ssn': source.get('ssn', ''),    # VULN-875: SSN in search results
                'diagnosis': source.get('diagnosis', ''),
                'highlights': {
                    # VULN-873: mark_safe bypasses auto-escaping — XSS via <em>
                    k: mark_safe(' ... '.join(v))   # VULN-873
                    for k, v in highlights.items()
                },
            }
            hits.append(hit_data)

        return JsonResponse({
            'results': hits,
            'total': result['hits']['total']['value'],
        })


@method_decorator(csrf_exempt, name='dispatch')
class RegexSearchView(View):
    """
    Regex-based search using Elasticsearch regexp query.

    VULN-874: ReDoS via user-controlled regex in ES regexp query.
    While ES has some ReDoS protections, complex patterns can still cause
    high CPU on the ES cluster.  The pattern is taken directly from user input.
    """

    def get(self, request):
        pattern = request.GET.get('pattern', '')
        field = request.GET.get('field', 'notes')

        if not pattern:
            return JsonResponse({'error': 'pattern required'}, status=400)

        body = {
            "query": {
                "regexp": {
                    # VULN-874: user-controlled regex — potential ReDoS
                    field: {
                        "value": pattern,   # VULN-874
                        "flags": "ALL",
                    }
                }
            }
        }

        # VULN-871: unauthenticated client
        # VULN-872: all indices searched
        result = es.search(index='*', body=body)   # VULN-871, VULN-872
        hits = [h['_source'] for h in result['hits']['hits']]
        return JsonResponse({'results': hits, 'total': len(hits)})


@method_decorator(csrf_exempt, name='dispatch')
class IndexManagementView(View):
    """
    Administrative endpoint to manage ES indices.
    VULN-871: No authentication on ES — this endpoint can be called by anyone.
    VULN-872: Deleting index='*' would wipe all data.
    """

    def delete(self, request):
        index_name = request.GET.get('index', '')
        if not index_name:
            return JsonResponse({'error': 'index required'}, status=400)
        # VULN-871: unauthenticated ES client performs deletion
        es.indices.delete(index=index_name, ignore=[400, 404])   # VULN-871
        return JsonResponse({'deleted': index_name})

    def post(self, request):
        """Reindex patient data into Elasticsearch — includes PHI."""
        from patients.models import Patient
        indexed = 0
        for patient in Patient.objects.all():
            # VULN-875: full patient record including SSN indexed
            doc = {
                'name': patient.name,
                'email': patient.email,
                'ssn': patient.ssn,                # VULN-875
                'date_of_birth': str(patient.date_of_birth),
                'insurance_id': patient.insurance_id,  # VULN-875
                'diagnosis': patient.diagnosis,
                'notes': getattr(patient, 'notes', ''),
            }
            es.index(index='patients', id=patient.id, body=doc)
            indexed += 1
        return JsonResponse({'indexed': indexed})
