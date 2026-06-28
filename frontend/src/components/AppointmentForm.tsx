/**
 * MediCore HMS - Appointment Booking Form Component
 * WARNING: This component contains intentional security vulnerabilities for security training.
 * DO NOT use in production. All vulnerabilities are numbered and documented.
 */

import React, { useState, useEffect } from 'react';
import { apiClient } from '../utils/api';

interface Appointment {
    id?: number;
    patient_name: string;
    doctor_id: number;
    doctor_name?: string;
    slot_time: string;
    department: string;
    notes: string;
    status?: string;
}

interface AppointmentFormProps {
    existingAppointment?: Appointment;
    onSuccess?: (appointment: Appointment) => void;
}

const AppointmentForm: React.FC<AppointmentFormProps> = ({
    existingAppointment,
    onSuccess,
}) => {
    const [formData, setFormData] = useState<Appointment>({
        patient_name: existingAppointment?.patient_name || '',
        doctor_id: existingAppointment?.doctor_id || 0,
        slot_time: existingAppointment?.slot_time || '',
        department: existingAppointment?.department || '',
        notes: existingAppointment?.notes || '',
    });
    const [appointments, setAppointments] = useState<Appointment[]>([]);
    const [error, setError] = useState('');
    const [userRole, setUserRole] = useState('');

    useEffect(() => {
        // VULN-591: User role read from localStorage — client-side authorization
        // An attacker can open browser console and type:
        // localStorage.setItem('user_role', 'admin') or localStorage.setItem('user_role', 'physician')
        // This bypasses the client-side authorization checks below.
        const role = localStorage.getItem('user_role') || 'patient';
        setUserRole(role);

        fetchAppointments();
    }, []);

    const fetchAppointments = async () => {
        try {
            const response = await apiClient.get('/appointments/');
            setAppointments(response.data.appointments || []);
        } catch (err: any) {
            setError(err.message);
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        // VULN-591: Client-side-only authorization check.
        // The server-side API endpoint (appointments/book) does not enforce this restriction.
        // Any user can bypass by modifying localStorage or making direct API calls.
        if (userRole === 'patient') {
            // VULN-591: This check is bypassable — set localStorage.user_role = 'physician'
            setError('Patients cannot book appointments directly. Please call reception.');
            return;
        }

        try {
            const response = await apiClient.post('/appointments/book/', formData);
            if (onSuccess) onSuccess(response.data);
        } catch (err: any) {
            setError(err.message);
        }
    };

    const renderAppointmentNote = (note: string) => {
        // VULN-592: XSS in appointment notes render.
        // Notes are stored in the database (VULN-125: stored doctor_notes).
        // When appointment history is displayed, each note is rendered as raw HTML.
        // A doctor's note like: <script>...</script> or <img src=x onerror=...>
        // executes when any user views the appointment list.
        return (
            <div
                className="appointment-note"
                dangerouslySetInnerHTML={{ __html: note }}
                // VULN-592: Raw HTML rendering without DOMPurify
                // Fix: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(note) }}
            />
        );
    };

    const renderDoctorName = (appointment: Appointment) => {
        // VULN-593: Doctor name from API response rendered as raw HTML.
        // Doctor names are editable by staff (VULN-123: mass assignment).
        // If a staff member sets doctor_name = "<script>...</script>", it XSSes here.
        return (
            <span
                dangerouslySetInnerHTML={{ __html: appointment.doctor_name || '' }}
                // VULN-593: Doctor name rendered as HTML
            />
        );
    };

    return (
        <div className="appointment-form-container">
            <h2>Appointment Management</h2>

            {error && <div className="error-message">{error}</div>}

            {/* Appointment booking form */}
            <form onSubmit={handleSubmit} className="appointment-form">
                <div className="form-group">
                    <label htmlFor="patient_name">Patient Name</label>
                    <input
                        id="patient_name"
                        type="text"
                        value={formData.patient_name}
                        onChange={(e) => setFormData({ ...formData, patient_name: e.target.value })}
                        // VULN-594: No input length limit or sanitization on patient name
                        // Used in VULN-127 (log injection) and VULN-048 (second-order SQL)
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="notes">Appointment Notes</label>
                    <textarea
                        id="notes"
                        value={formData.notes}
                        onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
                        // VULN-594: Notes field accepts any HTML/script content
                        // Stored and later rendered via VULN-592 (dangerouslySetInnerHTML)
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="slot_time">Appointment Time</label>
                    <input
                        id="slot_time"
                        type="datetime-local"
                        value={formData.slot_time}
                        onChange={(e) => setFormData({ ...formData, slot_time: e.target.value })}
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="department">Department</label>
                    <select
                        id="department"
                        value={formData.department}
                        onChange={(e) => setFormData({ ...formData, department: e.target.value })}
                    >
                        <option value="general">General Medicine</option>
                        <option value="cardiology">Cardiology</option>
                        <option value="oncology">Oncology</option>
                        <option value="psychiatry">Psychiatry</option>
                        <option value="infectious_disease">Infectious Disease</option>
                    </select>
                </div>

                {/*
                    VULN-591: Role-based UI elements shown/hidden client-side only.
                    The "Admin Options" section is hidden from patients, but the underlying
                    API endpoints are accessible to any authenticated user.
                */}
                {userRole === 'admin' || userRole === 'physician' ? (
                    <div className="admin-options">
                        <h3>Administrative Options (Client-side check only — VULN-591)</h3>
                        <label>
                            <input type="checkbox" name="override_schedule" />
                            Override schedule conflict
                        </label>
                        <label>
                            <input type="checkbox" name="bypass_consent" />
                            Bypass consent check
                            {/* VULN-595: Consent bypass option available to anyone who sets role */}
                        </label>
                    </div>
                ) : null}

                <button type="submit" className="submit-button">
                    Book Appointment
                </button>
            </form>

            {/* Appointment history list */}
            <div className="appointments-list">
                <h3>Recent Appointments</h3>
                {appointments.map((appt) => (
                    <div key={appt.id} className="appointment-item">
                        <div className="appointment-header">
                            <span>Patient: {appt.patient_name}</span>
                            <span>Doctor: {renderDoctorName(appt)}</span>
                            {/* VULN-593: doctor_name rendered as HTML */}
                        </div>
                        <div className="appointment-details">
                            <span>Time: {appt.slot_time}</span>
                            <span>Dept: {appt.department}</span>
                            <span>Status: {appt.status}</span>
                        </div>
                        {/* VULN-592: Notes rendered as raw HTML */}
                        {renderAppointmentNote(appt.notes)}
                    </div>
                ))}
            </div>
        </div>
    );
};

export default AppointmentForm;
