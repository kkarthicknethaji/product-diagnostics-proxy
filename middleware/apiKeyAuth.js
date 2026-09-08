// AI Cost Control Tower: OpenAPI Ingestion Layer — API-key auth middleware
// Spec: ai-cost-tower-openapi-ingestion-spec.md v0.11, Sections 5, 6, 7.
//
// This is deliberately NOT built on requireAuthStrict/requireActiveCompanyMember
// (server.js's existing JWT-based middlewares) — those assume a human Supabase
// Auth session via current_app_user(), which a machine credential never has.
// That exact assumption breaking under a multi-tenant credentialed caller is
// the bug class findings #5/#10/#20 identified elsewhere in this spec; this
// middleware is the one auth path in the whole app that intentionally never
// touches a Supabase Auth session at all.
//
// Resolves the presented Bearer token to (company_id, app_id) by hashing it
// and matching mt_company_apps.credential_hash — the same SHA-256 format
// admin_issue_company_app_credential/admin_rotate_company_app_credential
// write (sql/ai-cost-tower-openapi-ingestion-credential-functions.sql).
// Attaches req.companyId/req.appId, mirroring the existing req.companyId
// convention from requireActiveCompanyMember, so downstream route code reads
// the same shape regardless of which auth path resolved it.
//
// Exported as a factory (not a bare middleware function) because it needs
// server.js's existing supabaseAdmin client — server.js doesn't export that
// client as a module, so the factory pattern avoids a require() cycle.

const crypto = require('crypto');

// Throttled credential_last_used_at write (Section 13, item 4) — same
// in-memory Map + fixed window pattern server.js already uses for
// _budgetAlertLastCheckedAt, just keyed on company/app instead of company.
// Module-level state is fine here: this proxy runs as a single Node
// process per instance, same assumption the existing throttle map makes.
const _credentialLastUsedThrottle = new Map(); // `${company_id}:${app_id}` -> ms timestamp
const CREDENTIAL_LAST_USED_THROTTLE_MS = 5 * 60 * 1000; // 5 minutes

function _touchCredentialLastUsedOpportunistic(supabaseAdmin, companyId, appId) {
  const key = companyId + ':' + appId;
  const now = Date.now();
  const last = _credentialLastUsedThrottle.get(key) || 0;
  if (now - last < CREDENTIAL_LAST_USED_THROTTLE_MS) return;
  _credentialLastUsedThrottle.set(key, now);
  // Fire-and-forget, never awaited by the request path and never throws
  // outward — a stale credential_last_used_at is a cosmetic gap, not
  // something worth adding latency or failure risk to every ingestion call.
  supabaseAdmin
    .from('mt_company_apps')
    .update({ credential_last_used_at: new Date().toISOString() })
    .eq('company_id', companyId)
    .eq('app_id', appId)
    .then(function(result) {
      if (result && result.error) console.error('[V1 AUTH] credential_last_used_at update failed:', result.error.message);
    }, function(e) {
      console.error('[V1 AUTH] credential_last_used_at update exception:', e.message);
    });
}

// factory(supabaseAdmin) -> Express middleware
module.exports = function apiKeyAuthFactory(supabaseAdmin) {
  return async function apiKeyAuth(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const presentedKey = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

    if (!presentedKey) {
      return res.status(401).json({
        error: { type: 'auth_error', message: 'Missing or malformed Authorization header. Expected: Bearer <api_key>' }
      });
    }

    if (!supabaseAdmin) {
      console.error('[V1 AUTH] supabaseAdmin not configured — SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY missing');
      return res.status(500).json({ error: { type: 'server_error', message: 'Ingestion API is not configured.' } });
    }

    // Canonical hash format per Section 4.4: sha256, hex-encoded, plain
    // string comparison against credential_hash. No bytea handling on
    // either side — both functions that mint credentials store this same
    // encode(digest(...), 'hex') shape.
    const presentedHash = crypto.createHash('sha256').update(presentedKey).digest('hex');

    let row;
    try {
      const { data, error } = await supabaseAdmin
        .from('mt_company_apps')
        .select('company_id, app_id, is_active')
        .eq('credential_hash', presentedHash)
        .maybeSingle();
      if (error) throw error;
      row = data;
    } catch (e) {
      console.error('[V1 AUTH] credential lookup failed:', e.message);
      return res.status(500).json({ error: { type: 'server_error', message: 'Could not verify credential.' } });
    }

    if (!row || !row.is_active) {
      return res.status(401).json({ error: { type: 'auth_error', message: 'Invalid or inactive credential.' } });
    }

    // company_id/app_id resolved here, server-side, from the credential —
    // never accepted as payload fields from the request body (Section 2).
    req.companyId = row.company_id;
    req.appId = row.app_id;

    _touchCredentialLastUsedOpportunistic(supabaseAdmin, row.company_id, row.app_id);

    next();
  };
};
