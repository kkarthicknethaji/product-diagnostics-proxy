// AI Cost Control Tower: AI Trace Layer — Payload Capture Infrastructure (D.7)
// Spec: ai-trace-layer-payload-infra-followup-spec-v0.7.md, Section 3.3.
//
// Composed check for POST/GET /v1/trace-payloads (proxy/routes/v1/
// tracePayloads.js, v9.33.02) — collapses two independently-remembered
// checks (the credential's own payloads:write scope, and the app's
// payload_capture_enabled toggle) into one middleware, so a future
// implementer can't wire only one of the two.
// Route-level only — never mount this globally in server.js, unlike
// apiKeyAuth (see apiKeyAuth.js's own header comment).
//
// Depends on req.scopes/req.payloadCaptureEnabled, both attached by
// apiKeyAuth.js after its credential lookup.

function requirePayloadCaptureWrite(req, res, next) {
  if (!req.scopes || !req.scopes.payloadsWrite) {
    return res.status(403).json({ error: { type: 'forbidden', message: 'This credential does not have the payloadsWrite scope.' } });
  }
  if (!req.payloadCaptureEnabled) {
    return res.status(403).json({ error: { type: 'forbidden', message: 'Payload capture is not enabled for this app.' } });
  }
  next();
}

module.exports = { requirePayloadCaptureWrite };
