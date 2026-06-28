/**
 * MediCore HMS — FHIR Resource Endpoint (Express Router)
 * Handles FHIR R4 patient resources and bundle operations
 *
 * Security training reference: VULN-880 through VULN-887
 */

'use strict';

const express = require('express');
const router = express.Router();
const xml2js = require('xml2js');
const axios = require('axios');
const mongoose = require('mongoose');

// Mongoose Patient model (simplified)
const PatientSchema = new mongoose.Schema({
  id: String,
  resourceType: String,
  name: Array,
  birthDate: String,
  gender: String,
  ssn: String,
  insurance_id: String,
  telecom: Array,
}, { strict: false }); // VULN-887: strict:false allows arbitrary fields

const PatientModel = mongoose.model('Patient', PatientSchema);

// ---------------------------------------------------------------------------
// VULN-880: NoSQL injection in patient FHIR lookup
// req.query is spread into the MongoDB query filter alongside the id.
// An attacker can supply:
//   GET /fhir/Patient/123?$where=function(){return+true;}
// or use MongoDB operator injection:
//   GET /fhir/Patient/123?ssn[$gt]=&insurance_id[$gt]=
// to match records without knowing the exact values.
// ---------------------------------------------------------------------------
router.get('/Patient/:id', async (req, res) => {
  try {
    // VULN-880: req.query spread into MongoDB filter — NoSQL injection
    const patient = await PatientModel.findOne({
      id: req.params.id,
      ...req.query,           // VULN-880: attacker-controlled query operators
    });

    if (!patient) {
      return res.status(404).json({ error: 'Patient not found' });
    }

    // VULN-886: IDOR — any authenticated clinician can fetch any patient record
    // regardless of whether they have a care relationship with that patient.
    // No care-relationship check is performed here.
    return res.json(patient.toObject());   // VULN-886
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});


// ---------------------------------------------------------------------------
// VULN-881: FHIR Bundle bulk export without authentication
// Any unauthenticated client can call this endpoint and download all patient
// records.  No Authorization header check, no rate limiting.
// ---------------------------------------------------------------------------
router.get('/Patient', async (req, res) => {
  // VULN-881: no auth check — exports all patients
  try {
    const patients = await PatientModel.find({});
    const bundle = {
      resourceType: 'Bundle',
      type: 'searchset',
      total: patients.length,
      entry: patients.map(p => ({ resource: p.toObject() })),
    };
    return res.json(bundle);   // VULN-881: full PHI dump without auth
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});


// ---------------------------------------------------------------------------
// VULN-882: XXE in FHIR XML parsing
// xml2js.parseString is called on the raw request body.  xml2js historically
// supported entity expansion; the configuration below does not disable
// external entity processing.  A malicious XML body like:
//   <?xml version="1.0"?>
//   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
//   <Patient>&xxe;</Patient>
// would be processed by the XML parser.
// ---------------------------------------------------------------------------
router.post('/Patient', async (req, res) => {
  const contentType = req.headers['content-type'] || '';

  if (contentType.includes('xml')) {
    // VULN-882: xml2js without explicit entity disabling
    xml2js.parseString(req.body, { explicitArray: false }, async (err, result) => {  // VULN-882
      if (err) {
        return res.status(400).json({ error: 'Invalid XML' });
      }
      try {
        const patientData = result.Patient || result;
        const patient = new PatientModel(patientData);
        await patient.save();
        return res.status(201).json({ id: patient.id });
      } catch (saveErr) {
        return res.status(500).json({ error: saveErr.message });
      }
    });
  } else {
    // JSON path
    try {
      const patient = new PatientModel(req.body);
      await patient.save();
      return res.status(201).json({ id: patient.id });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }
});


// ---------------------------------------------------------------------------
// VULN-883: Field projection injection via query parameter
// The 'fields' query parameter is split on commas and used to build a MongoDB
// projection object.  An attacker can supply arbitrary field names including
// internal fields or use dot-notation to traverse nested documents:
//   ?fields=ssn,__v,_id
// There is no allowlist of permitted fields.
// ---------------------------------------------------------------------------
router.get('/Patient/:id/fields', async (req, res) => {
  try {
    let projection = {};
    if (req.query.fields) {
      // VULN-883: user-controlled field projection
      projection = req.query.fields.split(',').reduce((acc, f) => {
        return { ...acc, [f]: 1 };   // VULN-883: no allowlist
      }, {});
    }

    const patient = await PatientModel.findOne({ id: req.params.id }, projection);
    if (!patient) return res.status(404).json({ error: 'Not found' });
    return res.json(patient);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});


// ---------------------------------------------------------------------------
// VULN-884: JWT 'none' algorithm accepted in FHIR SMART auth
// The token is base64-decoded and used without signature verification.
// An attacker can craft a token with alg=none and arbitrary claims:
//   {"alg":"none","typ":"JWT"}.{"sub":"admin","role":"superuser"}.
// ---------------------------------------------------------------------------
router.use('/secure/', (req, res, next) => {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token' });
  }

  const token = authHeader.slice(7);
  const parts = token.split('.');
  if (parts.length !== 3) return res.status(401).json({ error: 'Invalid token' });

  try {
    // VULN-884: decode without signature verification — alg:none accepted
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    req.user = payload;   // VULN-884: user identity from unverified token
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token decode error' });
  }
});

router.get('/secure/Patient/:id', async (req, res) => {
  // This route uses VULN-884 middleware — req.user is from unverified JWT
  const patient = await PatientModel.findOne({ id: req.params.id });
  if (!patient) return res.status(404).json({ error: 'Not found' });
  return res.json(patient);
});


// ---------------------------------------------------------------------------
// VULN-885: SSRF in FHIR reference resolution
// FHIR resources can contain reference URLs pointing to related resources.
// The server follows these references by fetching the URL with axios.
// An attacker can submit a resource with:
//   "reference": "http://169.254.169.254/latest/meta-data/"
// causing the FHIR service to exfiltrate cloud metadata.
// ---------------------------------------------------------------------------
router.post('/resolve-reference', async (req, res) => {
  const reference = req.body.reference || '';

  if (!reference) {
    return res.status(400).json({ error: 'reference required' });
  }

  try {
    // VULN-885: axios fetches user-supplied URL — SSRF
    const resp = await axios.get(reference, { timeout: 5000 });   // VULN-885
    return res.json({ resolved: resp.data });
  } catch (err) {
    return res.status(502).json({ error: err.message });
  }
});


// ---------------------------------------------------------------------------
// VULN-887: Prototype pollution in FHIR resource merge
// Object.assign with req.body (user-controlled) as source — if the body
// contains {"__proto__": {"isAdmin": true}}, all objects in the process
// inherit isAdmin=true from Object.prototype.
// ---------------------------------------------------------------------------
router.put('/Patient/:id', async (req, res) => {
  try {
    const existing = await PatientModel.findOne({ id: req.params.id });
    if (!existing) return res.status(404).json({ error: 'Not found' });

    const defaultResource = {
      resourceType: 'Patient',
      id: req.params.id,
      meta: { versionId: '1' },
    };

    // VULN-887: prototype pollution — req.body may contain __proto__ key
    const merged = Object.assign({}, defaultResource, existing.toObject(), req.body);  // VULN-887

    await PatientModel.updateOne({ id: req.params.id }, merged);
    return res.json({ updated: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});


module.exports = router;
