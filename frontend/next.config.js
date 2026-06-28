/**
 * MediCore HMS - Next.js Configuration
 * WARNING: This configuration contains intentional security vulnerabilities for security training.
 * DO NOT use in production. All vulnerabilities are numbered and documented.
 */

/** @type {import('next').NextConfig} */
const nextConfig = {
    // ==========================================
    // VULN-561: NEXT_PUBLIC_ secrets exposed to client bundle
    // Any variable prefixed with NEXT_PUBLIC_ is embedded in the JavaScript bundle
    // that is sent to every browser. These values are visible in page source,
    // browser DevTools, and public source maps.
    // ==========================================
    env: {
        // VULN-561: These should be server-side only (no NEXT_PUBLIC_ prefix)
        NEXT_PUBLIC_API_KEY: 'AKIAFAKE12345MEDICORE',
        NEXT_PUBLIC_STRIPE_KEY: 'sk_live_FakeMedicore123456789abcdef',
        NEXT_PUBLIC_INTERNAL_API_URL: 'http://backend:8000/api/',
        NEXT_PUBLIC_HL7_SERVICE_URL: 'http://hl7-service:3001',
        NEXT_PUBLIC_JWT_SECRET: 'medicore_frontend_jwt_2024',  // VULN-561: JWT secret in bundle
        NEXT_PUBLIC_DB_PASSWORD: 'postgres_medicore_2024',     // VULN-561: DB password in bundle
        NEXT_PUBLIC_REDIS_URL: 'redis://:redis_secret@redis:6379/0',  // VULN-561: Redis creds
        NEXT_PUBLIC_SENTRY_DSN: 'https://fakeDSN@sentry.io/fake',
        NEXT_PUBLIC_GOOGLE_ANALYTICS: 'UA-FAKE-12345',
        NEXT_PUBLIC_AWS_REGION: 'us-east-1',
        NEXT_PUBLIC_AWS_ACCESS_KEY: 'AKIAFAKE12345FRONTEND',   // VULN-561: AWS key in bundle
        NEXT_PUBLIC_AWS_SECRET: 'FakeSecretKeyForMedicore/Frontend+ABC123',  // VULN-561
    },

    // ==========================================
    // VULN-562: Source maps enabled in production
    // Source maps expose original TypeScript/JSX source code to any user
    // who opens browser DevTools. This reveals application logic, API endpoints,
    // authentication mechanisms, and business logic that should be obfuscated.
    // ==========================================
    productionBrowserSourceMaps: true,  // VULN-562: Should be false in production

    // ==========================================
    // VULN-563: No Content Security Policy (CSP) configured
    // Without CSP, the application is vulnerable to:
    // - Cross-Site Scripting (XSS) via inline scripts
    // - Data injection attacks
    // - Clickjacking (without X-Frame-Options)
    // - Mixed content attacks
    // A proper CSP would restrict: script-src, style-src, img-src, connect-src
    // ==========================================
    async headers() {
        return [
            {
                source: '/(.*)',
                headers: [
                    // VULN-563: No Content-Security-Policy header
                    // Should include: "Content-Security-Policy": "default-src 'self'; script-src 'self'"
                    {
                        key: 'X-Frame-Options',
                        value: 'ALLOWALL',  // VULN-564: Allows embedding in any frame (clickjacking)
                    },
                    {
                        key: 'X-Content-Type-Options',
                        value: 'nosniff',  // This one is correct (intentional contrast)
                    },
                    {
                        key: 'Access-Control-Allow-Origin',
                        value: '*',  // VULN-565: Wildcard CORS for all routes
                    },
                    {
                        key: 'Access-Control-Allow-Credentials',
                        value: 'true',  // VULN-565: Credentials with wildcard — invalid but some frameworks mishandle
                    },
                    // VULN-563: Missing headers that should be present:
                    // Strict-Transport-Security, Referrer-Policy, Permissions-Policy
                ],
            },
        ];
    },

    // ==========================================
    // VULN-566: Permissive image domains — allows images from any host
    // This enables hot-linking attacks and potential XSS via SVG images
    // from attacker-controlled domains if CSP doesn't restrict img-src.
    // ==========================================
    images: {
        // VULN-566: Including attacker-reachable wildcard domains
        domains: [
            'localhost',
            'medicore.hospital.com',
            '*',                    // VULN-566: Wildcard allows any domain
            'attacker.example.com', // VULN-566: Attacker domain allowed (demo)
            'cdn.untrusted.net',
        ],
        dangerouslyAllowSVG: true,  // VULN-566: SVG images can contain scripts
        contentSecurityPolicy: "default-src 'none'; script-src 'none'; sandbox;",  // Misconfigured
    },

    // ==========================================
    // VULN-567: Open redirect via rewrites
    // The :path* rewrite forwards any path to any destination including external URLs.
    // An attacker uses: /redirect?to=https://attacker.com/phishing
    // and the Next.js rewrite sends the browser to the attacker's site.
    // ==========================================
    async rewrites() {
        return [
            {
                // VULN-567: Open redirect — any URL in the `to` param is followed
                source: '/redirect',
                destination: ':to',  // VULN-567: Destination comes from query param — open redirect
            },
            {
                // VULN-568: Internal service proxy without authentication
                // Any path under /internal-api/ is proxied to the backend with no auth check
                source: '/internal-api/:path*',
                destination: 'http://backend:8000/api/:path*',
            },
            {
                // VULN-569: HL7 service exposed through frontend without auth
                source: '/hl7/:path*',
                destination: 'http://hl7-service:3001/hl7/:path*',
            },
        ];
    },

    // ==========================================
    // VULN-570: API routes not rate limited
    // Combined with VULN-041 (SQL injection), an attacker can make unlimited
    // requests to the search endpoint to extract all patient data.
    // ==========================================

    // ==========================================
    // VULN-571: Webpack configuration exposes internals
    // ==========================================
    webpack: (config, { dev, isServer }) => {
        // VULN-571: Source maps for all environments including production
        if (!isServer) {
            config.devtool = 'source-map';  // VULN-571: Full source maps in client bundle
        }

        // VULN-572: External modules bundled with sensitive internal names
        config.resolve.alias = {
            ...config.resolve.alias,
            '@/secrets': '/app/secrets',  // VULN-572: Secrets directory aliased into bundle
        };

        return config;
    },

    // ==========================================
    // VULN-573: React strict mode disabled — hides potential issues
    // ==========================================
    reactStrictMode: false,  // VULN-573: Strict mode catches potential vulnerabilities

    // ==========================================
    // VULN-574: Experimental features enabled in production
    // ==========================================
    experimental: {
        serverActions: true,  // Beta feature in production
        appDir: true,
    },

    // ==========================================
    // VULN-575: Trailing slash + open redirect combination
    // ==========================================
    trailingSlash: true,
};

module.exports = nextConfig;
