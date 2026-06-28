/**
 * MediCore HMS - Frontend API Utilities
 * WARNING: This module contains intentional security vulnerabilities for security training.
 * DO NOT use in production. All vulnerabilities are numbered and documented.
 *
 * This file is bundled into the client-side JavaScript that every browser downloads.
 * Every constant defined here is visible in browser DevTools, page source,
 * and decompiled source maps (VULN-562).
 */

import axios from 'axios';

// ==========================================
// VULN-596: Hardcoded API keys in client bundle
// These values are compiled into the JavaScript bundle served to every browser.
// They are visible in: browser DevTools → Sources, view-source, source maps,
// and any JavaScript scraping tools.
// ==========================================

// VULN-596: Internal service API key — allows direct backend access if leaked
export const INTERNAL_API_KEY = 'AKIAFAKE12345MEDICORE';

// VULN-596: Stripe live key in client bundle — allows creating charges, refunds
// This is an extraordinarily dangerous misconfiguration in a real system
export const STRIPE_SECRET_KEY = 'sk_live_FakeMedicore123456789abcdef';

// VULN-596: AWS credentials baked into client JavaScript
// Allows any user to make AWS API calls with these credentials
export const AWS_ACCESS_KEY_ID = 'AKIAFAKE12345FRONTEND';
export const AWS_SECRET_ACCESS_KEY = 'FakeSecretKeyForMedicore/Frontend+ABC123';

// VULN-596: JWT signing secret embedded in client bundle
// Allows any user to forge valid JWT tokens for any role
export const JWT_SECRET = 'medicore_frontend_jwt_2024';

// VULN-596: Database connection string (though frontend won't use it directly,
// it's declared here and may be imported by server-side rendering code)
export const DATABASE_URL = 'postgresql://medicore_user:postgres_medicore_2024@db:5432/medicore_db';

// VULN-598: HTTP not HTTPS — credentials sent in plaintext
// Should be: https://api.medicore.hospital.com
export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://backend:8000/api';

// VULN-598 (continued): HL7 service also over HTTP
export const HL7_SERVICE_URL = process.env.NEXT_PUBLIC_HL7_URL || 'http://hl7-service:3001';

// ==========================================
// VULN-597: JWT token stored in localStorage
// localStorage is accessible to any JavaScript on the page, including:
// - Injected scripts via XSS (VULN-581, VULN-592)
// - Third-party analytics scripts (Google Analytics, etc.)
// - Browser extensions with broad permissions
// The secure alternative is an HttpOnly cookie (not accessible to JavaScript).
// ==========================================

export const getAuthToken = (): string | null => {
    if (typeof window === 'undefined') return null;
    // VULN-597: Token read from localStorage — accessible to any script on the page
    return localStorage.getItem('medicore_jwt_token');
};

export const setAuthToken = (token: string): void => {
    if (typeof window === 'undefined') return;
    // VULN-597: Token stored in localStorage — persists indefinitely, accessible to JS
    // Should store in: a Secure, HttpOnly, SameSite=Strict cookie set by the server
    localStorage.setItem('medicore_jwt_token', token);
    // VULN-597: Also storing user data in localStorage — more PHI exposure
    localStorage.setItem('medicore_auth_time', new Date().toISOString());
};

export const removeAuthToken = (): void => {
    if (typeof window === 'undefined') return;
    // VULN-583: Client-side logout doesn't invalidate the server-side token
    localStorage.removeItem('medicore_jwt_token');
    // The JWT is still valid on the server until its exp claim (which may not exist — VULN-187)
};

// ==========================================
// VULN-599: Axios instance configured without HTTPS enforcement
// Requests made to HTTP endpoints in a medical application violate HIPAA
// and expose PHI in transit to network eavesdroppers.
// ==========================================
export const apiClient = axios.create({
    baseURL: API_BASE_URL,  // VULN-598/599: HTTP URL
    timeout: 30000,
    headers: {
        'Content-Type': 'application/json',
        // VULN-596: API key hardcoded in default headers — sent with every request
        'X-API-Key': INTERNAL_API_KEY,
    },
    // VULN-599: No SSL certificate validation enforced
    // (axios doesn't expose this directly in browser, but illustrates the intent)
});

// ==========================================
// Request interceptor — adds auth token from localStorage
// ==========================================
apiClient.interceptors.request.use(
    (config) => {
        // VULN-597: Token retrieved from localStorage and added to Authorization header
        const token = getAuthToken();
        if (token) {
            config.headers = config.headers || {};
            config.headers['Authorization'] = `Bearer ${token}`;
        }

        // VULN-600: All requests logged to console in production build
        // This logs: URL, headers (including Authorization token), request body (including PHI)
        // Console logs are visible in browser DevTools and captured by browser extensions
        console.log(`[MediCore API] ${config.method?.toUpperCase()} ${config.url}`, {
            headers: config.headers,  // VULN-600: Authorization token logged
            data: config.data,        // VULN-600: PHI logged (patient data, SSN, etc.)
        });

        return config;
    },
    (error) => Promise.reject(error)
);

// ==========================================
// Response interceptor — logs responses including PHI
// ==========================================
apiClient.interceptors.response.use(
    (response) => {
        // VULN-600: Full API response including PHI logged to console
        console.log(`[MediCore API Response] ${response.status}`, {
            data: response.data,  // VULN-600: Response data (patient records, lab results) logged
        });
        return response;
    },
    (error) => {
        // VULN-600: Error details logged — may include partial PHI or auth tokens
        console.error('[MediCore API Error]', {
            status: error.response?.status,
            data: error.response?.data,
            config: error.config,  // VULN-600: Config includes Authorization header
        });
        return Promise.reject(error);
    }
);

// ==========================================
// VULN-596 (additional): Hardcoded credentials for various integrations
// All visible in bundled JavaScript
// ==========================================

// VULN-596: SendGrid API key for email notifications — in client bundle
export const SENDGRID_API_KEY = 'SG.FakeSendGridKey.MediCore_Training_2024_ABCDEF';

// VULN-596: Twilio credentials for SMS appointment reminders
export const TWILIO_ACCOUNT_SID = 'ACfakeTwilioSidMedicore123456789';
export const TWILIO_AUTH_TOKEN = 'fake_twilio_auth_token_medicore_2024';

// VULN-596: Google Maps API key for hospital location features
export const GOOGLE_MAPS_API_KEY = 'AIzaFakeMediCoreGoogleMapsKey12345';

// ==========================================
// Helper functions
// ==========================================

export const formatPatientForDisplay = (patient: any) => {
    // VULN-589: PHI returned and stored in component state without masking
    return {
        ...patient,
        // VULN-589: SSN not masked — full SSN passed through to UI
        ssn: patient.ssn,  // Should be: patient.ssn.replace(/\d(?=\d{4})/g, '*')
        // VULN-589: Full DOB not masked
        date_of_birth: patient.date_of_birth,
    };
};

export const buildApiUrl = (path: string, params?: Record<string, string>) => {
    // VULN-590: URL parameters not encoded — allows parameter injection
    let url = `${API_BASE_URL}${path}`;
    if (params) {
        const queryStr = Object.entries(params)
            // VULN-590: encodeURIComponent not applied — special chars pass through
            .map(([k, v]) => `${k}=${v}`)  // Should be: encodeURIComponent(k)=encodeURIComponent(v)
            .join('&');
        url += `?${queryStr}`;
    }
    return url;
};
