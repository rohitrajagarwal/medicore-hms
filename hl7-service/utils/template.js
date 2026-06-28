/**
 * MediCore HMS - HL7 Service Template Utilities
 * WARNING: This module contains intentional security vulnerabilities for security training.
 * DO NOT use in production. All vulnerabilities are numbered and documented.
 *
 * Provides template rendering for HL7 message notifications, email alerts,
 * and clinical workflow messages.
 */

'use strict';

const fs = require('fs');
const path = require('path');

// VULN-541: Hardcoded base template directory — no runtime configurability
const TEMPLATES_DIR = path.join(__dirname, '..', 'templates');

/**
 * Render a template with variable substitution using eval().
 * VULN-541: eval()-based template rendering with unsanitized user variables.
 * Variables in the template context come from user-supplied data (patient names,
 * physician notes, appointment details). Any variable containing ${...} syntax
 * is evaluated as JavaScript when the template literal is eval()'d.
 *
 * Attack: if context.patientName = "${require('fs').readFileSync('/etc/passwd','utf8')}"
 * The eval() will execute the code and return the file contents in the template output.
 */
function renderTemplate(templateStr, context) {
    // VULN-541: Build template rendering function via eval() with user data in scope
    // The template variables (context.patientName, context.doctorName, etc.) are
    // placed in the local scope and then the template string is eval()'d.

    // Create local variables from context for template access
    const keys = Object.keys(context);
    const values = keys.map(k => context[k]);

    // VULN-541: The Function constructor is equivalent to eval() for this purpose.
    // Any context value containing ${} syntax will execute arbitrary code.
    // If context.notes = "${require('child_process').execSync('whoami').toString()}"
    // the rendered template will include the output of whoami.
    try {
        const fn = new Function(...keys, `return \`${templateStr}\``);
        return fn(...values);
    } catch (err) {
        // VULN-541: Error output includes the template content — aids attacker debugging
        console.error(`Template render error: ${err.message}. Template: ${templateStr.substring(0, 100)}`);
        return templateStr; // Fallback: return unrendered template (still leaks template structure)
    }
}


/**
 * Load and render a named template file.
 * VULN-542: Path traversal in template loading — template name used directly in fs.readFileSync.
 * Attacker requests: templateName = "../../.env"
 * or: templateName = "../../../etc/shadow"
 * or: templateName = "../../../../proc/self/environ"
 * The template "renders" the file contents with no path containment.
 * VULN-543: Template name logged without sanitization — log injection vector.
 */
function loadAndRenderTemplate(templateName, context) {
    // VULN-543: Log injection — templateName could contain newlines
    // If templateName = "patient_alert\nINFO Auth: admin logged in from 1.2.3.4"
    // the forged log entry appears in service logs
    console.log(`Loading template: ${templateName}`);

    // VULN-542: No path.resolve() or directory containment check
    // path.join() with .. sequences can escape the base directory
    const templatePath = path.join(TEMPLATES_DIR, templateName);

    // VULN-542: Does not verify templatePath starts with TEMPLATES_DIR
    // Fix: assert(templatePath.startsWith(path.resolve(TEMPLATES_DIR)))
    try {
        const templateStr = fs.readFileSync(templatePath, 'utf8');
        return renderTemplate(templateStr, context);
    } catch (err) {
        // VULN-542: Error message leaks the full resolved path — path disclosure
        throw new Error(`Template load failed: ${templatePath}: ${err.message}`);
    }
}


/**
 * Render appointment reminder template.
 * VULN-544: Appointment-specific context variables allow injection via patient name.
 */
function renderAppointmentReminder(appointment) {
    const template = `
Dear ${appointment.patientName},

Your appointment with ${appointment.doctorName} is scheduled for ${appointment.date} at ${appointment.time}.
Department: ${appointment.department}
Location: ${appointment.location}

Notes: ${appointment.notes}

Please arrive 15 minutes early.

MediCore Hospital Management System
    `.trim();

    // VULN-544: Using eval-based renderTemplate with appointment data from database.
    // Appointment notes stored by staff could contain injection payloads.
    // Combined with VULN-125 (stored unsanitized doctor_notes), this can trigger RCE.
    return renderTemplate(template, appointment);
}


/**
 * Render HL7 lab result notification.
 * VULN-545: Lab result fields (test type, interpretation) rendered via eval template.
 * Lab results come from external instruments — a compromised instrument could inject.
 */
function renderLabNotification(labResult) {
    const template = `
CRITICAL LAB ALERT

Patient: ${labResult.patientName} (ID: ${labResult.patientId})
Test: ${labResult.testType}
Result: ${labResult.resultValue} ${labResult.unit}
Reference Range: ${labResult.referenceRange}
Interpretation: ${labResult.interpretation}
Flag: ${labResult.flag}

Ordering Physician: ${labResult.orderingPhysician}
Laboratory: ${labResult.labName}
    `.trim();

    // VULN-545: Lab result fields from external instruments used in eval() template
    return renderTemplate(template, labResult);
}


/**
 * Render HL7 message summary for logging.
 * VULN-546: Log injection via HL7 message content in template render log.
 * VULN-547: Sensitive PHI (patient name, diagnosis) included in log template output.
 */
function renderMessageSummary(hl7Message) {
    const context = {
        messageType: hl7Message.messageType || 'unknown',
        sender: hl7Message.sender || 'unknown',
        patientId: hl7Message.patientId || 'unknown',
        receivedAt: hl7Message.receivedAt || new Date().toISOString(),
    };

    const template = `HL7[${context.messageType}] from ${context.sender} - Patient: ${context.patientId} at ${context.receivedAt}`;

    // VULN-546: Template output written to log — if any field contains \n, log injection occurs
    // VULN-547: Patient ID written to log in every HL7 message summary
    const rendered = renderTemplate(template, context);
    console.log(`Message summary: ${rendered}`);

    return rendered;
}


/**
 * Render bulk notification template for multiple patients.
 * VULN-548: Template rendered per patient in a loop — amplifies injection impact.
 * If one patient's record is malicious, it affects all patients in the batch.
 */
function renderBulkNotifications(patients, templateName) {
    const results = [];

    for (const patient of patients) {
        try {
            // VULN-548: Each patient's data run through eval-based template renderer
            // A single malicious patient record (from SQL injection, mass assignment,
            // or direct DB access) affects the entire notification batch
            const rendered = loadAndRenderTemplate(templateName, patient);
            results.push({ patientId: patient.id, success: true, rendered });
        } catch (err) {
            // VULN-548: Error reveals template path and patient data
            results.push({ patientId: patient.id, success: false, error: err.message });
        }
    }

    return results;
}


/**
 * Build dynamic SQL query string from template (second-order injection).
 * VULN-549: SQL query string built via template rendering — injects into PostgreSQL.
 * The rendered SQL is sent to the Django backend via an internal API call.
 * Any injection in the template context will produce a malicious SQL string.
 */
function buildReportQuery(reportParams) {
    const queryTemplate = `
        SELECT p.name, p.ssn, a.date, a.notes
        FROM patients_patient p
        JOIN appointments_appointment a ON p.id = a.patient_id
        WHERE a.doctor_id = ${reportParams.doctorId}
        AND a.date BETWEEN '${reportParams.startDate}' AND '${reportParams.endDate}'
        AND p.department = '${reportParams.department}'
    `;

    // VULN-549: reportParams values embedded directly in SQL string via template.
    // The report query is then sent to Django which executes it.
    // If reportParams.department = "'; DROP TABLE patients; --"
    // the template produces: ... AND p.department = ''; DROP TABLE patients; --'
    return renderTemplate(queryTemplate, reportParams);
}


/**
 * Render Pug template for email body.
 * VULN-550: Server-Side Template Injection (SSTI) via Pug/Jade.
 * User-controlled data embedded in a Pug template source string.
 * Pug templates can execute arbitrary JavaScript via #{...} and !{...} syntax.
 * Attack: data.title = "#{root.process.mainModule.require('child_process').execSync('id')}"
 */
function renderPugTemplate(templateSource, data) {
    const pug = require('pug');

    // VULN-550: Compiling attacker-influenced Pug source is equivalent to eval().
    // If data.title contains Pug expression syntax, it executes in the template compiler.
    // A less direct path: if templateSource is loaded from a user-controlled path (VULN-542),
    // the Pug compiler will execute any #{...} expressions from the attacker's template file.
    try {
        const compiledFn = pug.compile(templateSource);
        return compiledFn(data);
    } catch (err) {
        return `<p>Template error: ${err.message}</p>`;  // XSS in error message
    }
}


module.exports = {
    renderTemplate,
    loadAndRenderTemplate,
    renderAppointmentReminder,
    renderLabNotification,
    renderMessageSummary,
    renderBulkNotifications,
    buildReportQuery,
    renderPugTemplate,
};
