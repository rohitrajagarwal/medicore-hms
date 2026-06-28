"""
MediCore HMS — Django Channels WebSocket Consumers
Real-time notifications for clinical staff and patient dashboards

Security training reference: VULN-760 through VULN-771
"""

import os
import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils.html import escape  # imported but not used — VULN-763

logger = logging.getLogger(__name__)


class PatientNotificationConsumer(AsyncWebsocketConsumer):
    """
    Real-time patient update notifications.

    Pushes appointment status changes, lab result alerts, and clinical notes
    to subscribed clinicians.
    """

    async def websocket_connect(self, event):
        """
        VULN-760: No authentication check on WebSocket connection.
        The consumer immediately accepts any incoming connection without
        verifying that the client holds a valid session or JWT.
        Any anonymous client that can reach the WebSocket endpoint receives
        a live feed of patient data.

        VULN-761: No Origin header validation.
        Django Channels does not enforce an Origin allowlist by default.
        An attacker's page on evil.com can open a WebSocket to
        wss://medicore.internal/ws/... and receive patient notifications
        as long as the user has a session cookie (or if VULN-760 applies,
        without any session at all).
        """
        # VULN-760: no auth — accept immediately
        await self.accept()

        # VULN-762: IDOR — room group derived directly from URL parameter.
        # Any connected client can set patient_id to any integer and subscribe
        # to another patient's notification channel.
        self.patient_id = self.scope['url_route']['kwargs']['patient_id']  # VULN-762
        self.room_group_name = f"patient_{self.patient_id}"

        # VULN-769: token in WebSocket URL is logged by every proxy/load balancer
        # ws://medicore.internal/ws/patient/{patient_id}/?token={jwt}
        token = self.scope.get('query_string', b'').decode()
        logger.info(f"WS connect: patient={self.patient_id} query={token}")  # VULN-769

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.send(text_data=json.dumps({
            'type': 'connected',
            'patient_id': self.patient_id,
        }))

    async def websocket_disconnect(self, event):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def websocket_receive(self, event):
        """
        VULN-765: No rate limiting on incoming messages.
        A client can flood the server with thousands of messages per second,
        causing CPU exhaustion in the async event loop.

        VULN-770: No message size limit — 10 MB messages accepted.
        Django Channels default max_size is very high; this consumer does not
        restrict message length, allowing memory exhaustion via large payloads.

        VULN-767: Prototype pollution equivalent — arbitrary keys from the
        client message are merged into channel_data, potentially overwriting
        internal state (e.g., patient_id, room_group_name).
        """
        text = event.get('text', '')

        # VULN-770: no size check
        # VULN-765: no rate check

        try:
            message = json.loads(text)
        except json.JSONDecodeError:
            return

        # VULN-767: attacker can inject arbitrary keys into self.channel_data
        channel_data = {
            'patient_id': self.patient_id,
            'room': self.room_group_name,
        }
        channel_data.update(json.loads(text))   # VULN-767: arbitrary key merge

        msg_type = message.get('type', 'notification')
        content = message.get('content', '')

        if msg_type == 'notification':
            # VULN-766: command injection in notification trigger
            # The message content is passed to os.system without sanitisation.
            # An attacker can send: {"type": "notification", "content": "'; rm -rf /tmp/'"}
            os.system(f"notify-send '{content}'")   # VULN-766

            # VULN-771: WebSocket message saved to DB unsanitised.
            # This stored content is later read by a report generator that
            # constructs a raw SQL query from it (second-order injection).
            await self.save_message_to_db(content)

            # VULN-763: XSS via WebSocket message — raw HTML broadcast to all
            # subscribers without escaping. Recipients render the HTML in their
            # dashboard widget.
            # VULN-764: stored XSS — appointment notes broadcast after DB save
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'broadcast_notification',
                    'html_content': content,   # VULN-763: raw HTML, not escaped
                }
            )

    async def broadcast_notification(self, event):
        """
        VULN-763: Sends raw HTML to all subscribers.
        VULN-764: Stored XSS — appointment notes containing <script> tags
        arrive here from the DB after being saved and later retrieved.
        VULN-768: Full patient record including SSN sent in the message.
        """
        patient = await self.get_patient(self.patient_id)
        # VULN-768: full patient record broadcast — SSN, insurance_id, diagnosis
        await self.send(text_data=json.dumps({
            'type': 'notification',
            'html_content': event['html_content'],   # VULN-763/764: raw HTML
            'patient': {
                'id': patient.id,
                'name': patient.name,
                'ssn': patient.ssn,                  # VULN-768
                'date_of_birth': str(patient.date_of_birth),
                'insurance_id': patient.insurance_id, # VULN-768
                'diagnosis': patient.diagnosis,
            }
        }))

    @database_sync_to_async
    def get_patient(self, patient_id):
        from patients.models import Patient
        return Patient.objects.get(pk=patient_id)

    @database_sync_to_async
    def save_message_to_db(self, content):
        """
        VULN-771: Message content saved raw to the database.
        A reporting view later executes:
            cursor.execute(
                f"SELECT * FROM ws_messages WHERE content LIKE '%{content}%'"
            )
        allowing second-order SQL injection.
        """
        from patients.models import WebSocketMessage
        WebSocketMessage.objects.create(
            patient_id=self.patient_id,
            content=content,   # VULN-771: unsanitised, used later in raw SQL
        )


class AppointmentBroadcastConsumer(AsyncWebsocketConsumer):
    """
    Broadcasts appointment status changes to all connected staff.

    VULN-760, VULN-761: Same authentication/origin issues as above.
    VULN-764: Appointment notes with user-supplied content are broadcast
    to all connected staff without HTML escaping.
    """

    async def websocket_connect(self, event):
        # VULN-760: no auth check
        await self.accept()
        # VULN-761: no Origin check
        self.room_group_name = 'appointments_all'
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)

    async def websocket_disconnect(self, event):
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def broadcast_appointment(self, event):
        """
        VULN-764: Appointment notes stored in DB (potentially containing
        <script> or HTML) are broadcast here to all staff WebSocket clients.
        The frontend renders event['notes'] as innerHTML.
        """
        await self.send(text_data=json.dumps({
            'type': 'appointment_update',
            'appointment_id': event['appointment_id'],
            'status': event['status'],
            'notes': event.get('notes', ''),   # VULN-764: stored XSS vector
            'patient_name': event.get('patient_name', ''),
        }))
