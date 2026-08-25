// ─────────────────────────────────────────────────────────────────────────────
// AI PM Toolkit — Multi-Provider AI Proxy (v9.23.03 — multi-provider since v9.14; /api/embed + /api/embed-info added v9.23.03, RA-Persistent-Doc-RAG-Spec-v14)
// Render.com deployment
//
// Responsibilities:
//   - Receive POST /api/anthropic from browser (Netlify frontend)
//   - Verify Supabase JWT from X-Auth-Token header using JWKS (ES256 / ECC P-256)
//   - Resolve the company's ACTUAL configured provider server-side (never
//     trust the client-sent `provider` field for dispatch/billing/usage —
//     see requireActiveCompanyMember + _resolveCompanyProvider below)
//   - Forward to the resolved provider (Anthropic, OpenAI, or Gemini — see
//     proxy/providerAdapters.js) via its adapter
//   - API key priority per provider: user BYOK key → org env var fallback
//   - Returns structured JSON errors — never raw HTML
//   - Rate limit: RATE_LIMIT_MAX req/min per IP
//
// Required env vars (set in Render dashboard):
//   ALLOWED_ORIGIN        — comma-separated list of allowed origins, e.g.
//                           https://productdiagnostics.netlify.app,https://white-ocean-059656610.7.azurestaticapps.net
//                           (name kept singular for continuity with existing Render env var config —
//                           it now holds one or more origins, not exactly one)
//   SUPABASE_URL          — from Supabase project → Settings → API → Project URL
//                           JWKS endpoint derived automatically: SUPABASE_URL/auth/v1/.well-known/jwks.json
//   ANTHROPIC_API_KEY     — optional shared org key; if unset, requires user BYOK key
//   OPENAI_API_KEY        — optional shared org key for OpenAI; same fallback role as ANTHROPIC_API_KEY
//   GEMINI_API_KEY        — optional shared org key for Gemini; same fallback role as ANTHROPIC_API_KEY
//   AZURE_OPENAI_ENDPOINT — Requirement Agent persistent-doc RAG (v14): Azure OpenAI
//                           resource endpoint, e.g. https://vspm-azureai.openai.azure.com
//   AZURE_OPENAI_KEY      — Azure OpenAI resource API key (api-key header auth)
//   AZURE_OPENAI_EMBED_DEPLOYMENT — the embedding deployment name (sent as the
//                           request body's `model` field — Azure's v1 embeddings
//                           API resolves deployments this way, not via a URL path
//                           segment; see /api/embed below)
//
// Removed env vars (no longer needed — Supabase migrated from HS256 to ECC P-256):
//   SUPABASE_JWT_SECRET — delete from Render dashboard; JWKS verification replaces it
// ─────────────────────────────────────────────────────────────────────────────

const express   = require('express');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const jwt       = require('jsonwebtoken');
const jwksRsa   = require('jwks-rsa');
const { createClient } = require('@supabase/supabase-js');
const { getAdapter, isKnownModel } = require('./providerAdapters');

const app  = express();
const PORT = process.env.PORT || 3001;

// Trust Render's load balancer so express-rate-limit reads the real client IP
// from X-Forwarded-For instead of the proxy IP. Fixes rate-limit log warning.
app.set('trust proxy', 1);

// ── Rate limit config ─────────────────────────────────────────────────────────
// Centralised so the error message always matches the configured limit.
const RATE_LIMIT_MAX        = 100; // requests per window per IP
const RATE_LIMIT_WINDOW_MIN = 1;   // window size in minutes

// ── Env vars ──────────────────────────────────────────────────────────────────
// ALLOWED_ORIGIN now holds one or more comma-separated origins (was a single
// exact-match string). Parsed the same way as INVITE_REDIRECT_ALLOWLIST below
// — split, trim, filter empties, normalize via the URL constructor so a
// trailing-slash typo in the env var can't silently fail to match. Supports
// this proxy being called from multiple hosted frontends at once (Netlify +
// Azure Static Web Apps) without branching on which platform is calling.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGIN || '')
  .split(',')
  .map(function(s){ return s.trim(); })
  .filter(Boolean)
  .map(function(s){
    try { return new URL(s).origin; }
    catch(e) { console.warn('[WARN] invalid ALLOWED_ORIGIN entry, ignoring:', s); return ''; }
  })
  .filter(Boolean);
const SUPABASE_URL   = process.env.SUPABASE_URL   || '';

// v14 (RA-Persistent-Doc-RAG-Spec-v14, D4/D6) — Requirement Agent persistent-
// document embeddings, via Azure OpenAI. Trimmed of any trailing slash so the
// path built in _embedAzure() below never ends up with a doubled "//".
const AZURE_OPENAI_ENDPOINT = (process.env.AZURE_OPENAI_ENDPOINT || '').replace(/\/+$/, '');
const AZURE_OPENAI_KEY      = process.env.AZURE_OPENAI_KEY || '';
const AZURE_OPENAI_EMBED_DEPLOYMENT = process.env.AZURE_OPENAI_EMBED_DEPLOYMENT || '';

// ── Invite redirect allow-list (Phase 4, v8.112) ────────────────────────────
// Comma-separated exact origins, parsed once at boot. Deliberately NOT a
// hardcoded array baked into this file — server.js is deployed unmodified to
// BOTH the dev and prod Render services from one repo, so a hardcoded list
// containing "localhost:3000" would let the PROD deployment of this same
// file also accept localhost as a valid invite-redirect target. Each Render
// service sets its own value: dev includes localhost + dev Netlify, prod
// includes only prod Netlify. Adding another allowed origin later is an env
// var change, never a code change.
const INVITE_REDIRECT_ALLOWLIST = (process.env.INVITE_REDIRECT_ALLOWLIST || '')
  .split(',')
  .map(function(s){ return s.trim(); })
  .filter(Boolean)
  // Normalized to a canonical origin (protocol+host+port, no trailing
  // slash/path) via the URL constructor — closes a real config-fragility
  // risk (a trailing slash typo in the env var silently never matching
  // anything) without weakening the exact-match security property at all;
  // it's still exact match, just against a canonical form on both sides.
  .map(function(s){
    try { return new URL(s).origin; }
    catch(e) { console.warn('[WARN] invalid INVITE_REDIRECT_ALLOWLIST entry, ignoring:', s); return ''; }
  })
  .filter(Boolean);
const INVITE_REDIRECT_PATH = '/login.html';

// Shared by /api/team/invite and /api/team/resend — returns ONLY the
// resolved redirect URL string (or undefined), never a method-specific
// options shape. inviteUserByEmail() and generateLink() take redirectTo
// at genuinely different nesting levels (confirmed against the actual
// shipped @supabase/auth-js types, not assumed) — a helper that tried to
// return a ready-made options object for one of them would silently be
// wrong for the other. Each call site applies this value using its own
// real API shape.
function _resolveInviteRedirect(req) {
  const rawOrigin = req.headers.origin || '';
  if (!rawOrigin) return undefined;
  let requestOrigin;
  try { requestOrigin = new URL(rawOrigin).origin; }
  catch(e) { console.warn('[TEAM] invalid request origin, omitting redirectTo:', rawOrigin); return undefined; }
  if (INVITE_REDIRECT_ALLOWLIST.includes(requestOrigin)) {
    return requestOrigin + INVITE_REDIRECT_PATH;
  }
  console.warn('[TEAM] origin not in INVITE_REDIRECT_ALLOWLIST, omitting redirectTo:', requestOrigin);
  return undefined;
}
// v9.14: same fallback role each provider's own env var plays — replaces the
// old single ORG_API_KEY (Anthropic-only) constant.
const ORG_API_KEY_BY_PROVIDER = {
  anthropic: process.env.ANTHROPIC_API_KEY || '',
  openai:    process.env.OPENAI_API_KEY || '',
  gemini:    process.env.GEMINI_API_KEY || ''
};
// New for Phase 1 — required for /api/check-company-name (and Phase 4's admin
// routes later). This is the first time this proxy talks to the Supabase
// database directly rather than only verifying JWTs; @supabase/supabase-js
// is a new dependency as of this change, it wasn't needed before.
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

// Warn on startup if critical env vars are missing
if (!SUPABASE_URL)    console.warn('[WARN] SUPABASE_URL not set — JWT verification will fail');
if (!ALLOWED_ORIGINS.length) console.warn('[WARN] ALLOWED_ORIGIN not set (or contains no valid origins) — all origins will be blocked');
if (!SUPABASE_SERVICE_ROLE_KEY) console.warn('[WARN] SUPABASE_SERVICE_ROLE_KEY not set — /api/check-company-name and admin routes will fail');
if (!INVITE_REDIRECT_ALLOWLIST.length) console.warn('[WARN] INVITE_REDIRECT_ALLOWLIST not set — invite links will use the Supabase project default Site URL only');
if (!AZURE_OPENAI_ENDPOINT || !AZURE_OPENAI_KEY || !AZURE_OPENAI_EMBED_DEPLOYMENT) console.warn('[WARN] AZURE_OPENAI_ENDPOINT/AZURE_OPENAI_KEY/AZURE_OPENAI_EMBED_DEPLOYMENT not fully set — /api/embed and /api/embed-info will fail');

// Admin client — bypasses RLS by design, used only for the narrow set of
// server-side operations that need it (pre-auth company name checks here;
// invite/disable/delete in Phase 4). Never exposed to the browser.
const supabaseAdmin = (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
  : null;

// ── AI usage-tracking insert helper (v9.13) ──────────────────────────────────
// Writes one row to mt_ai_usage_events per /api/anthropic call, on BOTH the
// success/response-received path and the error/timeout path (two call sites
// below use this same helper — see the main handler). Awaited, not fire-and-
// forget: an un-awaited insert on a long-running Express process is usually
// safe, but not safe against Render replacing/restarting this instance mid-
// request, which would silently drop the row with no way to know it happened.
// Awaiting costs a little latency per call but guarantees the row exists (or
// its failure is at least logged) before the response is sent.
// Never throws — a usage-tracking failure must never surface to the user as
// an AI-generation failure, so any error here is caught and logged only.
async function _insertAiUsageEvent(fields) {
  if (!supabaseAdmin) return; // telemetry is best-effort; never block on missing config
  try {
    const { error } = await supabaseAdmin.from('mt_ai_usage_events').insert(fields);
    if (error) console.error('[AI USAGE] insert failed:', error.message);
  } catch (e) {
    console.error('[AI USAGE] insert exception:', e.message);
  }
  // Opportunistic budget-alert check (AI Cost Control Tower, v9.28/v9.28.01)
  // — fire-and-forget, never awaited by the caller, so it adds no latency to
  // the AI response. Never throws outward, same discipline as the insert
  // above: a telemetry/alerting failure must never surface as a generation
  // failure to the end user.
  _checkBudgetAlertsOpportunistic(fields.company_id).catch(function(e) {
    console.error('[AI BUDGET ALERT] check exception:', e.message);
  });
}

// ── Budget-alert opportunistic check (v9.28.01) ──────────────────────────────
// No cron infrastructure exists in this app (AI Cost Control Tower spec,
// Section 6.6) — piggybacked onto the highest-frequency write this app
// already makes (a usage-event insert) rather than standing up new
// scheduling. Throttled per company so a burst of calls doesn't re-run the
// full spend computation on every single one; a few-minute staleness on
// alert timing is an accepted tradeoff, not a correctness requirement.
const _budgetAlertLastCheckedAt = new Map(); // company_id -> ms timestamp
const BUDGET_ALERT_CHECK_THROTTLE_MS = 5 * 60 * 1000; // 5 minutes

// A generous, explicit cap rather than relying on whatever PostgREST's
// unconfigured default max-rows happens to be — makes the limit a documented
// fact instead of an implicit one, and cheap to raise later if real volume
// ever approaches it.
const MONTH_TO_DATE_SPEND_ROW_CAP = 20000;

// Month boundary in UTC, not the Node process's host-local time. The
// dashboard (scripts/cost-tower.js) computes "this month" in the admin's
// browser-local time, so neither reference can match arbitrary browser
// timezones exactly — but UTC is at least a fixed, documented reference
// point that doesn't silently shift if the proxy is ever redeployed to a
// different server region, which host-local time would. Closing the gap
// with the admin's actual timezone would need a stored per-company
// timezone preference; not attempted here.
function _utcMonthBoundary(offsetMonths) {
  var d = new Date();
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + offsetMonths, 1));
}

// Recomputes calculated_cost the same way mt_ai_cost_events_list() does
// (sql/ai-cost-tower.sql), in JS rather than SQL — supabaseAdmin runs under
// the service role with no authenticated-user JWT context, so the RPC's own
// _cost_tower_is_admin() gate (which depends on current_app_user()) cannot
// be satisfied from here; querying the two tables directly and joining in
// JS sidesteps that without weakening the RPC's admin gate for real callers.
// Mirrors the RPC's COALESCE(response_model, requested_model) — falls back
// only on a real null, not on any other falsy value — so the two formulas
// can't disagree on which price row a call matches.
async function _computeMonthToDateSpend(companyId) {
  const monthStartIso = _utcMonthBoundary(0).toISOString();

  const [{ data: events, error: evErr }, { data: pricing, error: pErr }] = await Promise.all([
    supabaseAdmin
      .from('mt_ai_usage_events')
      .select('provider, requested_model, response_model, input_tokens, output_tokens, cache_creation_5m_tokens, cache_creation_1h_tokens, cache_read_tokens, request_started_at')
      .eq('company_id', companyId)
      .gte('request_started_at', monthStartIso)
      .limit(MONTH_TO_DATE_SPEND_ROW_CAP),
    supabaseAdmin
      .from('mt_model_pricing')
      .select('provider, model_name, input_price_per_mtok, output_price_per_mtok, cache_write_5m_price_per_mtok, cache_write_1h_price_per_mtok, cache_read_price_per_mtok, effective_from, effective_to')
  ]);
  if (evErr || !events) {
    if (evErr) console.warn('[AI BUDGET ALERT] usage-events query failed:', evErr.message);
    return null;
  }
  if (pErr || !pricing) {
    if (pErr) console.warn('[AI BUDGET ALERT] pricing query failed:', pErr.message);
    return null;
  }

  // Pre-index pricing by provider|model_name with epoch-ms bounds computed
  // once, so each event does a short scan within its own model's price
  // history instead of the whole pricing table, and never allocates a Date
  // per comparison (was O(events x pricing_rows) with 2 Date allocations
  // per comparison; now O(events + pricing_rows)).
  const pricingByKey = {};
  pricing.forEach(function(p) {
    const key = p.provider + '|' + p.model_name;
    (pricingByKey[key] = pricingByKey[key] || []).push({
      input_price_per_mtok: p.input_price_per_mtok,
      output_price_per_mtok: p.output_price_per_mtok,
      cache_write_5m_price_per_mtok: p.cache_write_5m_price_per_mtok,
      cache_write_1h_price_per_mtok: p.cache_write_1h_price_per_mtok,
      cache_read_price_per_mtok: p.cache_read_price_per_mtok,
      effectiveFromMs: new Date(p.effective_from).getTime(),
      effectiveToMs: p.effective_to ? new Date(p.effective_to).getTime() : null
    });
  });

  let total = 0;
  for (const e of events) {
    const modelKey = e.response_model != null ? e.response_model : e.requested_model;
    const candidates = pricingByKey[e.provider + '|' + modelKey];
    if (!candidates) continue; // unpriced call — excluded, same as the RPC's LEFT JOIN + NULL calculated_cost
    const atMs = new Date(e.request_started_at).getTime();
    const match = candidates.find(function(p) {
      return atMs >= p.effectiveFromMs && (p.effectiveToMs === null || atMs < p.effectiveToMs);
    });
    if (!match) continue;
    total += (e.input_tokens || 0) / 1000000 * match.input_price_per_mtok
      + (e.output_tokens || 0) / 1000000 * match.output_price_per_mtok
      + (e.cache_creation_5m_tokens || 0) / 1000000 * match.cache_write_5m_price_per_mtok
      + (e.cache_creation_1h_tokens || 0) / 1000000 * match.cache_write_1h_price_per_mtok
      + (e.cache_read_tokens || 0) / 1000000 * match.cache_read_price_per_mtok;
  }
  return total;
}

async function _checkBudgetAlertsOpportunistic(companyId) {
  if (!supabaseAdmin || !companyId) return;
  const lastChecked = _budgetAlertLastCheckedAt.get(companyId) || 0;
  if (Date.now() - lastChecked < BUDGET_ALERT_CHECK_THROTTLE_MS) return;
  _budgetAlertLastCheckedAt.set(companyId, Date.now());

  const { data: budget, error: budgetErr } = await supabaseAdmin
    .from('mt_ai_budgets')
    .select('*')
    .eq('company_id', companyId)
    .eq('scope_type', 'overall')
    .eq('is_active', true)
    .maybeSingle();
  if (budgetErr || !budget) return; // no active budget configured — nothing to check against

  const spend = await _computeMonthToDateSpend(companyId);
  if (spend === null) return;

  const periodStart = _utcMonthBoundary(0).toISOString().slice(0, 10);
  const periodEnd = _utcMonthBoundary(1).toISOString().slice(0, 10);
  const pct = (spend / Number(budget.amount)) * 100;

  // Both thresholds are checked independently (not else-if) — if spend jumps
  // past both between two opportunistic checks, both get their own alert
  // row, matching how a real-time check would have fired them separately.
  // The UNIQUE(budget_id, threshold_type, period_start) constraint is what
  // actually enforces "once per threshold per period," not this code —
  // a duplicate insert attempt fails with 23505 (unique_violation), caught
  // and ignored below as the expected, silent outcome.
  const thresholdsCrossed = [];
  if (pct >= Number(budget.warn_threshold_pct)) thresholdsCrossed.push({ threshold_type: 'warn', threshold_pct: budget.warn_threshold_pct });
  if (pct >= Number(budget.escalate_threshold_pct)) thresholdsCrossed.push({ threshold_type: 'escalate', threshold_pct: budget.escalate_threshold_pct });

  for (const t of thresholdsCrossed) {
    const { error } = await supabaseAdmin.from('mt_ai_alerts').insert({
      budget_id: budget.budget_id,
      threshold_type: t.threshold_type,
      threshold_pct: t.threshold_pct,
      current_spend: spend,
      period_start: periodStart,
      period_end: periodEnd
    });
    if (error && error.code !== '23505') {
      console.warn('[AI BUDGET ALERT] alert insert failed:', error.message);
    }
  }
}

// ── JWKS client ───────────────────────────────────────────────────────────────
// Verifies Supabase JWTs signed with ECC P-256 (ES256) via the JWKS endpoint.
// Keys are lazy-loaded on first verification request — not at startup.
// Cache: 5 min TTL, background refresh every 10 min.
// Timeout: 5s per JWKS fetch — prevents hanging on cold start.
const jwksClient = SUPABASE_URL ? jwksRsa({
  jwksUri:              SUPABASE_URL + '/auth/v1/.well-known/jwks.json',
  cache:                true,
  cacheMaxAge:          5 * 60 * 1000,   // 5 minutes
  rateLimit:            true,
  jwksRequestsPerMinute: 10,
  requestHeaders:       { 'Accept': 'application/json' },
  timeout:              5000             // 5s JWKS fetch timeout
}) : null;

// ── getSigningKey — callback for jwt.verify ───────────────────────────────────
function getSigningKey(header, callback) {
  if (!jwksClient) {
    return callback(new Error('JWKS client not initialised — SUPABASE_URL missing'));
  }
  jwksClient.getSigningKey(header.kid, function(err, key) {
    if (err) {
      console.warn('[AUTH] JWKS key fetch failed:', err.message);
      return callback(err);
    }
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

// ── CORS ──────────────────────────────────────────────────────────────────────
const LOCAL_ORIGINS = [
  'http://localhost',
  'http://127.0.0.1',
  'null' // file:// origin (local open-in-browser)
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // curl, Postman, server-to-server
    if (
      ALLOWED_ORIGINS.includes(origin) ||
      LOCAL_ORIGINS.includes(origin) ||
      origin.startsWith('http://localhost') ||
      origin.startsWith('http://127.0.0.1')
    ) {
      return callback(null, true);
    }
    console.warn('[CORS] Origin blocked:', origin, '— Allowed:', ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS.join(', ') : '(none set)');
    return callback(new Error('CORS: origin not allowed — ' + origin));
  },
  // v14 — 'GET' added for /api/embed-info (every other route in this file is
  // POST-only). Widening the shared allow-list rather than forking a second
  // CORS config object for one route — this only affects what the BROWSER's
  // own preflight is told is allowed, not an authorization boundary
  // (requireAuthStrict + the RA RPCs' own checks are that boundary).
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Auth-Token'],
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));

// Explicit OPTIONS preflight handler — guarantees CORS headers are set before
// rate limiter or auth middleware can intercept the preflight request.
// app.use(cors()) handles preflight globally, but this makes /api/anthropic
// deterministic regardless of future middleware order changes.
app.options('/api/anthropic', cors(corsOptions));
app.options('/api/check-company-name', cors(corsOptions));

// ── Rate limiting ─────────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MIN * 60 * 1000,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(200).json({
      error: {
        type: 'rate_limit_error',
        message: `Too many requests — limit is ${RATE_LIMIT_MAX} per ${RATE_LIMIT_WINDOW_MIN === 1 ? 'minute' : RATE_LIMIT_WINDOW_MIN + ' minutes'}. Please wait and try again.`
      }
    });
  }
});
app.use('/api/anthropic', limiter);

// Separate limiter instance for check-company-name — same config, applied to
// its own route so the two don't share a counter. This endpoint is
// unauthenticated by design (called before signup exists), so rate limiting
// is the only real abuse guard on it.
const companyNameLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MIN * 60 * 1000,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(200).json({
      error: {
        type: 'rate_limit_error',
        message: `Too many requests — limit is ${RATE_LIMIT_MAX} per ${RATE_LIMIT_WINDOW_MIN === 1 ? 'minute' : RATE_LIMIT_WINDOW_MIN + ' minutes'}. Please wait and try again.`
      }
    });
  }
});
app.use('/api/check-company-name', companyNameLimiter);

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'product-diagnostics-proxy', version: '2.2.0' });
});

// ── Strict JWT auth ────────────────────────────────────────────────────────
// v8.113: /api/anthropic now uses this too, replacing the old requireAuth
// (deleted — no other caller remained once this switched). requireAuth's
// local-dev bypass set no req.user at all, which was harmless when nothing
// downstream read it, but /api/anthropic now needs req.user.id for its new
// company-membership check, same reason Team Management needed this variant.
// Local-dev testing of AI generation now goes through the hosted dev proxy,
// same as Team Management already required.
//
// v8.113: added explicit issuer/audience checks — a real gap in the original
// implementation, not just new-code hygiene. Signature-only verification
// doesn't confirm the token came from THIS Supabase project specifically,
// or that it's a normal user session token rather than some other token
// type carrying a validly-signed but semantically wrong payload.
const SUPABASE_ISSUER = SUPABASE_URL ? (SUPABASE_URL + '/auth/v1') : '';
function requireAuthStrict(req, res, next) {
  if (req.method === 'OPTIONS') return next();

  const token = req.headers['x-auth-token'] || '';
  if (!token) {
    return res.status(200).json({ error: { type: 'auth_error', message: 'Not authenticated. Please sign in and try again.' } });
  }
  if (!jwksClient) {
    console.error('[AUTH] JWKS client not initialised — SUPABASE_URL missing');
    return res.status(200).json({ error: { type: 'auth_error', message: 'Auth not configured on proxy. Contact your administrator.' } });
  }
  jwt.verify(token, getSigningKey, {
    algorithms: ['ES256', 'RS256'],
    issuer: SUPABASE_ISSUER || undefined,
    audience: 'authenticated'
  }, function(err, decoded) {
    if (err) {
      console.warn('[AUTH] JWT verification failed (strict):', err.message);
      return res.status(200).json({ error: { type: 'auth_error', message: 'Session expired or invalid. Please sign in again.' } });
    }
    req.user = { id: decoded.sub, email: decoded.email };
    next();
  });
}

app.use('/api/anthropic', requireAuthStrict);

// ── Team Management — CORS preflight, rate limit, body parser ────────────────
app.options('/api/team/*', cors(corsOptions));

const teamLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MIN * 60 * 1000,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(200).json({
      error: {
        type: 'rate_limit_error',
        message: `Too many requests — limit is ${RATE_LIMIT_MAX} per ${RATE_LIMIT_WINDOW_MIN === 1 ? 'minute' : RATE_LIMIT_WINDOW_MIN + ' minutes'}. Please wait and try again.`
      }
    });
  }
});
app.use('/api/team', teamLimiter);
app.use('/api/team', express.json({ limit: '10kb' }));
app.use('/api/team', requireAuthStrict);

// requireCompanyAdmin — the single authorization boundary for every team route.
// These routes use the service-role client and bypass RLS entirely by design,
// so this check IS the security boundary, not a UX nicety. Every route reads
// req.companyId after this, never req.body.company_id again — closes the
// two-sources-of-truth risk of a handler accidentally re-reading the raw body.
async function requireCompanyAdmin(req, res, next) {
  const companyId = req.body && req.body.company_id;
  if (!companyId) {
    return res.status(200).json({ error: { type: 'invalid_request', message: 'company_id is required.' } });
  }
  try {
    const { data, error } = await supabaseAdmin
      .from('mt_users_companies')
      .select('role')
      .eq('user_id', req.user.id)
      .eq('company_id', companyId)
      .eq('is_active', true)
      .eq('role', 'admin')
      .maybeSingle();
    if (error || !data) {
      console.warn('[TEAM] authorization denied:', req.user.email, '->', companyId);
      return res.status(200).json({ error: { type: 'auth_error', message: "You don't have admin access to this company." } });
    }
    req.companyId = companyId;
    delete req.body.company_id;
    next();
  } catch (err) {
    console.error('[TEAM] authorization check exception:', err.message);
    return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not verify admin access. Please try again.' } });
  }
}
app.use('/api/team', requireCompanyAdmin);

// ── Body parser — scoped to /api/anthropic only, after auth ──────────────────
// 10mb limit accommodates base64-encoded screenshot payloads (max 1.5MB file = ~2MB base64).
// Scoped: health check and 404 routes do not inherit large body parsing.
// Order: limiter → requireAuthStrict → body parser → requireActiveCompanyMember → handler.
// Unauthenticated requests are rejected before body is parsed.
app.use('/api/anthropic', express.json({ limit: '10mb' }));

// ── Company-membership check (v8.113) ─────────────────────────────────────────
// requireAuthStrict proves WHO is calling; this proves they're currently an
// active member of the company they claim to be generating for — previously
// missing entirely on this endpoint, the highest-frequency one in the app.
// Calls the same is_active_company_member() RPC the Netlify function's
// equivalent check also calls, so the two implementations can't drift apart
// on what "active member" actually means.
async function requireActiveCompanyMember(req, res, next) {
  if (req.method === 'OPTIONS') return next();
  const companyId = req.body && req.body.company_id;
  if (!companyId) {
    return res.status(200).json({ error: { type: 'invalid_request', message: 'company_id is required.' } });
  }
  try {
    const { data: isMember, error } = await supabaseAdmin.rpc('is_active_company_member', {
      p_user_id: req.user.id, p_company_id: companyId
    });
    if (error) {
      console.error('[AI] membership check failed:', error.message);
      return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not verify company access. Please try again.' } });
    }
    if (!isMember) {
      console.warn('[AI] membership denied:', req.user.email, '->', companyId);
      return res.status(200).json({ error: { type: 'forbidden_error', message: "You don't have active access to this company." } });
    }
    // v9.13: preserved on req (not just deleted from body) so the AI usage-
    // tracking insert further down the handler has a trusted, server-verified
    // company_id to record against — mirrors requireCompanyAdmin's existing
    // req.companyId pattern below, previously only used by /api/team/*.
    req.companyId = companyId;
    delete req.body.company_id; // single source of truth from here on, same pattern as requireCompanyAdmin

    // v9.14: server-authoritative provider resolution. The proxy does NOT
    // trust body.provider for dispatch/billing/usage-attribution — a
    // manipulated provider field could route a request (and its cost) to a
    // different platform-owned org key than the company's actual configured
    // choice, a materially different risk than anything in the app before
    // this feature. Read directly from mt_company_settings, the same store
    // the client itself reads/writes (settings-page.js's
    // _spSaveCompanySettings()) — alongside the membership check already
    // just performed above. A missing/unreadable row defaults to
    // 'anthropic', matching appSettings.provider's own client-side default
    // for a company that predates this feature (never existed in a row yet).
    try {
      const { data: settingsRow, error: settingsErr } = await supabaseAdmin
        .from('mt_company_settings')
        .select('settings')
        .eq('company_id', companyId)
        .maybeSingle();
      if (settingsErr) {
        console.warn('[AI] provider resolution: mt_company_settings query failed, defaulting to anthropic:', settingsErr.message);
        req.resolvedProvider = 'anthropic';
      } else {
        req.resolvedProvider = (settingsRow && settingsRow.settings && settingsRow.settings.provider) || 'anthropic';
      }
    } catch (e) {
      console.warn('[AI] provider resolution exception, defaulting to anthropic:', e.message);
      req.resolvedProvider = 'anthropic';
    }

    next();
  } catch (err) {
    console.error('[AI] membership check exception:', err.message);
    return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not verify company access. Please try again.' } });
  }
}
app.use('/api/anthropic', requireActiveCompanyMember);

// ── Generic provider HTTP call (v9.14) ──────────────────────────────────────
// Replaces the old Anthropic-only inline https.request() block. Same
// Promise/timeout/error shape as before, just parameterized by the adapter's
// buildUpstreamRequest() output instead of a hardcoded hostname/path.
function _callUpstream(upstreamReq, timeoutMs, onTimeoutLog) {
  const https = require('https');
  const url = new URL(upstreamReq.url);
  const postBody = JSON.stringify(upstreamReq.body);
  const bodyBytes = Buffer.byteLength(postBody, 'utf8');

  return new Promise((resolve, reject) => {
    let upstreamTimedOut = false;
    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname + url.search,
      method: upstreamReq.method || 'POST',
      headers: Object.assign({ 'Content-Length': bodyBytes }, upstreamReq.headers)
    };

    const proxyReq = https.request(options, (upstreamRes) => {
      let raw = '';
      upstreamRes.on('data', chunk => { raw += chunk; });
      upstreamRes.on('end', () => {
        clearTimeout(upstreamTimer);
        const _responseBytes = Buffer.byteLength(raw, 'utf8');
        try {
          const parsed = JSON.parse(raw);
          resolve({ data: parsed, responseBytes: _responseBytes, httpStatus: upstreamRes.statusCode, requestBytes: bodyBytes });
        } catch (e) {
          reject(new Error('Failed to parse upstream response: ' + e.message));
        }
      });
    });

    const upstreamTimer = setTimeout(() => {
      upstreamTimedOut = true;
      if (onTimeoutLog) onTimeoutLog();
      proxyReq.destroy(new Error('Upstream timeout after ' + timeoutMs + 'ms'));
    }, timeoutMs);

    proxyReq.on('error', (e) => {
      clearTimeout(upstreamTimer);
      reject(e);
    });

    proxyReq.write(postBody);
    proxyReq.end();
  });
}

// ── Streaming upstream call (v-next, Requirement Agent only, opt-in via
// body.stream — see scripts/requirement-agent.js's _raStreamingEnabled()) ──
// Mirrors _callUpstream()'s connection/timeout/retry-eligible-error shape
// EXACTLY up through "did upstream return a 2xx" — this is what keeps the
// existing retry-once-on-transient-error logic meaningful for streaming
// calls too: retry decisions are still made before a single byte reaches the
// client. Only once upstream confirms 2xx does this diverge from
// _callUpstream() — instead of buffering the full body, it forwards each
// provider SSE event, translated by adapter.parseSSEEvent() into a
// normalized {delta, usage} shape, to the client as this proxy's OWN (much
// simpler) SSE contract: `data: {"delta":"..."}` per chunk, ending with
// `data: {"done":true}` (or `data: {"error":true,"message":"..."}` if the
// upstream connection drops mid-stream — no retry is possible at that point,
// same limitation any streaming client has).
// Shared "no usage data" shape for _streamUpstreamOnce's two return sites
// (initial accumulator, mid-stream-error fallback) — kept as one factory so
// a future field addition/removal only needs one edit, not two in lockstep.
function _emptyStreamUsage() {
  return { inputTokens: null, outputTokens: null, totalTokens: null, cacheReadTokens: null, providerUsageRaw: null, resolvedModel: null };
}

// Anthropic's cache-creation buckets (5m/1h ephemeral writes) have no
// equivalent on OpenAI/Gemini's raw usage shape (confirmed in
// proxy/providerAdapters.js's adapter comments), so they're read directly
// off the raw usage object here rather than normalized into the adapter's
// shared `usage` shape the way cacheReadTokens is. Shared between the
// streaming and non-streaming success paths below, which otherwise had to
// duplicate this same guard+field-access pattern.
function _extractAnthropicCacheCreation(provider, rawUsage, field) {
  if (provider !== 'anthropic' || !rawUsage || !rawUsage.cache_creation) return null;
  var v = rawUsage.cache_creation[field];
  return v != null ? v : null;
}

function _streamUpstreamOnce(upstreamReq, timeoutMs, adapter, res, onTimeoutLog) {
  const https = require('https');
  const { StringDecoder } = require('string_decoder');
  const url = new URL(upstreamReq.url);
  const postBody = JSON.stringify(upstreamReq.body);
  const bodyBytes = Buffer.byteLength(postBody, 'utf8');

  return new Promise((resolve, reject) => {
    let upstreamTimedOut = false;
    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname + url.search,
      method: upstreamReq.method || 'POST',
      headers: Object.assign({ 'Content-Length': bodyBytes }, upstreamReq.headers)
    };

    const proxyReq = https.request(options, (upstreamRes) => {
      clearTimeout(upstreamTimer);

      if (upstreamRes.statusCode < 200 || upstreamRes.statusCode >= 300) {
        // Never stream an error payload — buffer it exactly like _callUpstream
        // so the existing retry-once logic can inspect it as usual.
        let raw = '';
        upstreamRes.on('data', chunk => { raw += chunk; });
        upstreamRes.on('end', () => {
          let parsed = null;
          try { parsed = JSON.parse(raw); } catch (e) { /* leave null — adapter.normalizeHttpError tolerates this */ }
          resolve({ streamed: false, data: parsed, httpStatus: upstreamRes.statusCode, requestBytes: bodyBytes, responseBytes: Buffer.byteLength(raw, 'utf8') });
        });
        return;
      }

      // Upstream confirmed 2xx — begin forwarding to the client as a stream.
      // No more retry possible past this point, matching the plan's
      // documented tradeoff.
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
      let sseBuffer = '';
      let responseBytes = 0;
      const usage = _emptyStreamUsage();
      // StringDecoder (Node core), not Buffer#toString('utf8') per chunk —
      // a multi-byte UTF-8 character split across two TCP chunks would
      // otherwise decode independently in each chunk and come out as a
      // replacement character (U+FFFD) instead of being reassembled.
      // StringDecoder carries incomplete trailing bytes over to the next
      // .write() call, same guarantee scripts/api.js's client-side
      // TextDecoder(..., {stream:true}) already provides.
      const decoder = new StringDecoder('utf8');

      upstreamRes.on('data', (chunk) => {
        responseBytes += chunk.length;
        sseBuffer += decoder.write(chunk);
        const events = sseBuffer.split('\n\n');
        sseBuffer = events.pop(); // last entry may be a partial event — keep buffering it
        events.forEach((evt) => {
          if (!evt.trim()) return;
          let parsedEvt;
          try { parsedEvt = adapter.parseSSEEvent(evt); } catch (e) { parsedEvt = { delta: null, usage: null, done: false }; }
          if (parsedEvt.delta) {
            try { res.write('data: ' + JSON.stringify({ delta: parsedEvt.delta }) + '\n\n'); } catch (e) {}
          }
          if (parsedEvt.usage) {
            if (parsedEvt.usage.inputTokens != null) usage.inputTokens = parsedEvt.usage.inputTokens;
            if (parsedEvt.usage.outputTokens != null) usage.outputTokens = parsedEvt.usage.outputTokens;
            if (parsedEvt.usage.totalTokens != null) usage.totalTokens = parsedEvt.usage.totalTokens;
            if (parsedEvt.usage.cacheReadTokens != null) usage.cacheReadTokens = parsedEvt.usage.cacheReadTokens;
            // Shallow merge, not overwrite: Anthropic's message_start event carries
            // cache_creation/cache_read_input_tokens, message_delta carries only
            // output_tokens — a wholesale overwrite here silently dropped
            // message_start's cache fields once message_delta arrived (spec
            // Section 11 item 11). Confirmed this never affected output_tokens
            // itself, which is guarded per-field above, independent of this object.
            if (parsedEvt.usage.providerUsageRaw != null) usage.providerUsageRaw = Object.assign({}, usage.providerUsageRaw, parsedEvt.usage.providerUsageRaw);
          }
          if (parsedEvt.resolvedModel != null) usage.resolvedModel = parsedEvt.resolvedModel;
        });
      });

      upstreamRes.on('end', () => {
        try { res.write('data: ' + JSON.stringify({ done: true }) + '\n\n'); res.end(); } catch (e) {}
        resolve({ streamed: true, usage, requestBytes: bodyBytes, responseBytes });
      });
    });

    const upstreamTimer = setTimeout(() => {
      upstreamTimedOut = true;
      if (onTimeoutLog) onTimeoutLog();
      proxyReq.destroy(new Error('Upstream timeout after ' + timeoutMs + 'ms'));
    }, timeoutMs);

    proxyReq.on('error', (err) => {
      clearTimeout(upstreamTimer);
      if (res.headersSent) {
        // Streaming had already begun to the client — end it with an error
        // marker. No retry possible at this point (mirrors the non-streaming
        // path's own rule: a request that may have already reached the
        // provider is not safely retryable).
        try {
          res.write('data: ' + JSON.stringify({ error: true, message: upstreamTimedOut ? 'Upstream timed out mid-stream.' : ('Stream interrupted: ' + (err.message || 'unknown error')) }) + '\n\n');
          res.end();
        } catch (e) {}
        resolve({ streamed: true, usage: _emptyStreamUsage(), requestBytes: bodyBytes, responseBytes: 0, midStreamError: true });
      } else {
        // No response ever received (headers never sent) — a genuine
        // transport-level failure, same as _callUpstream()'s own
        // reject(e) above. Rejecting (not resolving) is what makes
        // _handleStreamingRequest's `catch (transportErr) { throw
        // transportErr; }` actually reachable, so this falls through to
        // the outer handler's proper timeout/network error path instead
        // of being misread as an HTTP error with undefined status.
        reject(err);
      }
    });

    proxyReq.write(postBody);
    proxyReq.end();
  });
}

// Full request lifecycle for a streaming call — same retry-once-on-transient-
// error semantics and same mt_ai_usage_events logging as the non-streaming
// path below, just restructured around _streamUpstreamOnce()'s
// {streamed, ...} result shape. Only reached when body.stream is true (opt-in,
// currently only ever sent by Requirement Agent when its localStorage
// streaming flag is on — see scripts/requirement-agent.js).
async function _handleStreamingRequest(req, res, ctx) {
  const { provider, adapter, upstreamReq, _caller, body, _requestStartedAt, _clientCallId, _sessionId, _sessionType, _productId, _userRoleAtCall, _settingsMode, _settingsModel, _selectionRule, _promptVersion, UPSTREAM_TIMEOUT_MS } = ctx;
  upstreamReq.body.stream = true;

  let _attempt = 0;
  const MAX_ATTEMPTS = 2;
  while (true) {
    _attempt++;
    let outcome;
    try {
      outcome = await _streamUpstreamOnce(upstreamReq, UPSTREAM_TIMEOUT_MS, adapter, res, function () {
        console.error('[AI TIMEOUT]', { provider, caller: _caller, timeoutMs: UPSTREAM_TIMEOUT_MS, model: body.model, attempt: _attempt, streaming: true });
      });
    } catch (transportErr) {
      throw transportErr; // no response ever received — outer catch handles usage-tracking + client response
    }

    if (outcome.streamed) {
      const _durationMs = Date.now() - _requestStartedAt.getTime();
      await _insertAiUsageEvent({
        client_call_id: _clientCallId, provider, company_id: req.companyId, product_id: _productId,
        session_id: _sessionId, session_type: _sessionType, user_id: req.user.id, user_role_at_call: _userRoleAtCall,
        caller: _caller, prompt_version: _promptVersion, requested_model: body.model, response_model: outcome.usage.resolvedModel,
        settings_mode: _settingsMode, settings_model: _settingsModel, selection_rule: _selectionRule,
        input_tokens: outcome.usage.inputTokens, output_tokens: outcome.usage.outputTokens,
        // Anthropic-specific cache-write buckets, same as the non-streaming path
        // below — only meaningful once the merge-bug fix above lets
        // providerUsageRaw actually retain message_start's cache_creation object.
        cache_creation_5m_tokens: _extractAnthropicCacheCreation(provider, outcome.usage.providerUsageRaw, 'ephemeral_5m_input_tokens'),
        cache_creation_1h_tokens: _extractAnthropicCacheCreation(provider, outcome.usage.providerUsageRaw, 'ephemeral_1h_input_tokens'),
        cache_read_tokens: outcome.usage.cacheReadTokens,
        provider_usage_raw: outcome.usage.providerUsageRaw,
        status: outcome.midStreamError ? 'error' : 'success',
        provider_http_status: 200,
        error_type: outcome.midStreamError ? 'stream_interrupted' : null,
        failure_phase: outcome.midStreamError ? 'outbound_call' : null,
        request_started_at: _requestStartedAt.toISOString(), duration_ms: _durationMs,
        request_bytes: outcome.requestBytes, response_bytes: outcome.responseBytes
      });
      return; // res already ended inside _streamUpstreamOnce
    }

    // Not streamed: either a pre-stream buffered HTTP error, or (thrown above)
    // a transport failure. Reaching here means a buffered error response.
    const _errVerdict = adapter.normalizeHttpError(outcome.data, outcome.httpStatus);
    if (_errVerdict.retryable && _attempt < MAX_ATTEMPTS) {
      console.warn('[AI RETRY]', { provider, caller: _caller, httpStatus: outcome.httpStatus, normalizedErrorCode: _errVerdict.normalizedErrorCode, attempt: _attempt, streaming: true });
      await new Promise(function (r) { setTimeout(r, 1000); });
      continue;
    }

    const _durationMs = Date.now() - _requestStartedAt.getTime();
    await _insertAiUsageEvent({
      client_call_id: _clientCallId, provider, company_id: req.companyId, product_id: _productId,
      session_id: _sessionId, session_type: _sessionType, user_id: req.user.id, user_role_at_call: _userRoleAtCall,
      caller: _caller, prompt_version: _promptVersion, requested_model: body.model, response_model: null,
      settings_mode: _settingsMode, settings_model: _settingsModel, selection_rule: _selectionRule,
      input_tokens: null, output_tokens: null, cache_creation_5m_tokens: null, cache_creation_1h_tokens: null, cache_read_tokens: null,
      provider_usage_raw: null, status: 'error', provider_http_status: outcome.httpStatus,
      error_type: _errVerdict.normalizedErrorCode, failure_phase: 'outbound_call',
      request_started_at: _requestStartedAt.toISOString(), duration_ms: _durationMs,
      request_bytes: outcome.requestBytes, response_bytes: outcome.responseBytes
    });
    return res.status(200).json({ error: { type: _errVerdict._rawType || _errVerdict.normalizedErrorCode, message: _errVerdict.safeErrorMessage } });
  }
}

// ── Main proxy endpoint ───────────────────────────────────────────────────────
app.post('/api/anthropic', async (req, res) => {
  try {
    // v9.14: provider is resolved server-side by requireActiveCompanyMember
    // above (req.resolvedProvider) — NEVER taken from body.provider, which
    // the client may send for diagnostics only (see scripts/api.js's
    // callAPI()). This is the single source of truth for which adapter runs,
    // which env var/BYOK-header key gets used, and what gets logged to
    // mt_ai_usage_events.provider.
    const provider = req.resolvedProvider || 'anthropic';
    const adapter = getAdapter(provider);
    if (!adapter) {
      console.error('[AI] no adapter for resolved provider:', provider);
      return res.status(200).json({ error: { type: 'invalid_request', message: 'This company\'s configured AI provider is not currently supported.' } });
    }

    // ── API key resolution ──
    // Priority 1: BYOK key from Authorization: Bearer header (user-supplied)
    // Priority 2: shared org key from the resolved provider's env var (Render dashboard)
    // If user supplies a BYOK key, it is always used — org key is never a silent fallback
    // for an invalid BYOK. Invalid BYOK → provider returns auth error → surfaces to user.
    const authHeader = req.headers['authorization'] || '';
    const byokKey = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    let apiKey = byokKey || ORG_API_KEY_BY_PROVIDER[provider] || '';

    if (!apiKey) {
      return res.status(200).json({
        error: {
          type: 'auth_error',
          message: 'No API key available. Add a personal API key in Settings or contact your admin.'
        }
      });
    }

    // Validate request body
    const body = req.body;
    if (!body || !body.model || !body.messages) {
      return res.status(200).json({
        error: {
          type: 'invalid_request',
          message: 'Malformed request body — model and messages are required.'
        }
      });
    }

    // ── Runtime model validation (Section 6.3's fail-fast requirement) ──
    // Reject an unrecognized model for the resolved provider BEFORE spending
    // an upstream call on it — a stale client cache or tampered request
    // sending a model string that was never actually offered for this
    // provider should surface a clear proxy-side error, not a confusing
    // upstream one.
    if (!isKnownModel(provider, body.model)) {
      console.warn('[AI] rejected unknown model for provider:', provider, body.model);
      return res.status(200).json({
        error: { type: 'invalid_request', message: 'Unsupported model for the configured AI provider.' }
      });
    }

    const _caller = body._caller || 'unknown';
    const upstreamReq = adapter.buildUpstreamRequest({
      model:      body.model,
      max_tokens: body.max_tokens,
      system:     body.system,
      messages:   body.messages
    }, apiKey);
    const bodyBytesPreview = Buffer.byteLength(JSON.stringify(upstreamReq.body), 'utf8');

    console.log('[AI OUT]', { provider, caller: _caller, model: body.model, max_tokens: body.max_tokens, bodyBytes: bodyBytesPreview });

    // ── AI usage-tracking (v9.13) ──
    // Fields read off the ORIGINAL request body (never anthropicBody above,
    // which is deliberately narrowed to only what Anthropic itself needs —
    // these fields must never be forwarded upstream). Marked started here,
    // before the outbound call begins, so duration_ms and the pricing-lookup
    // timestamp both reflect the actual Anthropic call, not proxy overhead
    // from auth/membership checks that already ran before this point.
    const _requestStartedAt = new Date();
    const _clientCallId = body.client_call_id || null;
    const _sessionId    = body.session_id || null;
    const _settingsMode  = body.settings_mode || null;
    const _settingsModel = body.settings_model || null;
    const _selectionRule = body.selection_rule || null;
    const _promptVersion = body.prompt_version || null;

    // v9.13.01: product_id is now derived server-side from session_id ->
    // mt_sessions.product_id, NOT trusted from the client's body.product_id
    // (activeProfileId on the frontend). Confirmed via real production data
    // that activeProfileId — a Home-tab-scoped UI variable — can be null at
    // generation time even mid-session with a genuine active product,
    // producing silent NULL product_id rows in mt_ai_usage_events. Since
    // mt_sessions.product_id is now NOT NULL (every session is launched
    // against exactly one product, enforced at both the UI and DB layer),
    // this lookup is authoritative whenever a session_id is present. The
    // client-sent body.product_id is kept ONLY as a fallback for the rare
    // caller with no session at all (e.g. doc-summary on a company-level
    // document) — never overriding a real session's own value.
    let _productId = body.product_id || null;
    // v9.15: session_type is set only by Guided Launch (session_type:'ChatCanvas'),
    // whose session_id points at mt_intake_sessions, not mt_sessions — the lookup
    // below would just miss and silently do nothing, but skipping it outright is
    // the correct behavior, not a fallback: body.product_id is already the real
    // value in that case (Guided Launch always knows its product directly, no
    // Discovery Map session exists yet to derive it from).
    const _sessionType = body.session_type || null;
    if (_sessionId && !_sessionType) {
      try {
        const { data: _sessRow } = await supabaseAdmin
          .from('mt_sessions')
          .select('product_id')
          .eq('id', _sessionId)
          .maybeSingle();
        if (_sessRow && _sessRow.product_id) _productId = _sessRow.product_id;
      } catch (e) {
        console.warn('[AI USAGE] session product_id lookup failed:', e.message);
      }
    }

    // Role snapshot at call time — deliberately a SEPARATE small query, not
    // squeezed out of requireActiveCompanyMember's is_active_company_member()
    // RPC above, which returns a plain boolean and has no role to give.
    // Modifying that RPC's return shape would be a security-definer-function
    // change shared with the (currently dormant) Netlify proxy path and
    // deserves its own scrutiny — out of scope for a telemetry addition.
    // Snapshotting here means later role changes never retroactively alter
    // what this historical row says the caller's role was at the time.
    let _userRoleAtCall = null;
    try {
      const { data: _roleRow } = await supabaseAdmin
        .from('mt_users_companies')
        .select('role')
        .eq('user_id', req.user.id)
        .eq('company_id', req.companyId)
        .maybeSingle();
      _userRoleAtCall = _roleRow ? _roleRow.role : null;
    } catch (e) {
      console.warn('[AI USAGE] role snapshot failed:', e.message);
    }

    // v8.98: per-caller timeout — raising PI's ceiling should not tie up the
    // proxy longer for every other (smaller, faster) caller if THEY hang.
    // v9.14: this remains the single total request deadline per Section 5.5
    // — a retry below (if any) happens WITHIN one overall attempt cycle, not
    // as an independent extra timeout window stacked on top.
    const TIMEOUT_BY_CALLER = { 'pi-generate': 150000, 'mi-docx-gen': 150000 };
    const UPSTREAM_TIMEOUT_MS = TIMEOUT_BY_CALLER[_caller] || 120000;

    // ── Streaming opt-in (v-next, Requirement Agent only) ──
    // body.stream is only ever sent true by Requirement Agent, and only when
    // its own localStorage flag is on (see scripts/requirement-agent.js's
    // _raStreamingEnabled()) — every other caller's request has no `stream`
    // field and falls straight through to the unchanged buffered path below.
    if (body.stream === true) {
      return await _handleStreamingRequest(req, res, {
        provider, adapter, upstreamReq, _caller, body, _requestStartedAt,
        _clientCallId, _sessionId, _sessionType, _productId, _userRoleAtCall,
        _settingsMode, _settingsModel, _selectionRule, _promptVersion, UPSTREAM_TIMEOUT_MS
      });
    }

    // ── Upstream call, with a single bounded retry on transient errors only
    // (Section 5.5) ──
    // Retried ONLY when a response was actually received and the adapter
    // classifies its error as transient (rate-limit/overload/5xx) — never on
    // invalid-key, permission, malformed-request, or content-safety errors,
    // and never on a transport-level failure/timeout, where the upstream
    // call may have already reached the provider and a retry risks a
    // double-billed duplicate. The client does not layer its own retry on
    // top of this (see scripts/api.js's callAPI() — single fetch, no retry).
    let _result;
    let _attempt = 0;
    const MAX_ATTEMPTS = 2;
    while (true) {
      _attempt++;
      try {
        _result = await _callUpstream(upstreamReq, UPSTREAM_TIMEOUT_MS, function(){
          console.error('[AI TIMEOUT]', { provider, caller: _caller, timeoutMs: UPSTREAM_TIMEOUT_MS, model: body.model, attempt: _attempt });
        });
      } catch (transportErr) {
        // Transport-level failure (network error or our own timeout-forced
        // destroy) — never retried, per Section 5.5's ambiguous-outcome rule.
        // Rethrown to the outer catch block, which handles the
        // no-response-at-all usage-tracking path.
        throw transportErr;
      }
      if (_result.httpStatus >= 200 && _result.httpStatus < 300) break; // success — no retry needed
      const _errVerdict = adapter.normalizeHttpError(_result.data, _result.httpStatus);
      if (_errVerdict.retryable && _attempt < MAX_ATTEMPTS) {
        console.warn('[AI RETRY]', { provider, caller: _caller, httpStatus: _result.httpStatus, normalizedErrorCode: _errVerdict.normalizedErrorCode, attempt: _attempt });
        await new Promise(function(r){ setTimeout(r, 1000); }); // fixed backoff — neither provider's retry-after field is confirmed yet (see spec Section 7)
        continue;
      }
      break; // not retryable, or out of attempts — fall through with the error response as-is
    }

    const { data, responseBytes, httpStatus, requestBytes } = _result;
    const bodyBytes = requestBytes;
    const _durationMs = Date.now() - _requestStartedAt.getTime();

    // ── AI usage-tracking insert — success/response-received path (v9.13,
    // provider-aware v9.14) ──
    // "Success" here means a response was actually received from the
    // provider, which may itself carry an error payload (e.g. an overloaded
    // response) — that still counts as status='error' with a real
    // duration/response size, distinct from the outer catch block below,
    // which only fires when NO response was ever received at all (network
    // failure, timeout).
    const _isErrorPayload = !(httpStatus >= 200 && httpStatus < 300);
    const _normalized = _isErrorPayload ? adapter.normalizeHttpError(data, httpStatus) : adapter.normalizeSuccess(data);
    if (!_isErrorPayload) _normalized.requestedModel = body.model;

    await _insertAiUsageEvent({
      client_call_id: _clientCallId,
      provider: provider, // server-resolved, never the client-echoed body.provider — see requireActiveCompanyMember above
      company_id: req.companyId,
      product_id: _productId,
      session_id: _sessionId,
      session_type: _sessionType,
      user_id: req.user.id,
      user_role_at_call: _userRoleAtCall,
      caller: _caller,
      prompt_version: _promptVersion,
      requested_model: body.model,
      response_model: _isErrorPayload ? null : _normalized.resolvedModel,
      settings_mode: _settingsMode,
      settings_model: _settingsModel,
      selection_rule: _selectionRule,
      input_tokens: _isErrorPayload ? null : _normalized.usage.inputTokens,
      output_tokens: _isErrorPayload ? null : _normalized.usage.outputTokens,
      // Anthropic-specific cache-write buckets — remain null for non-Anthropic
      // providers, whose usage detail (if any) belongs in provider_usage_raw
      // instead of being force-fit into these Anthropic-shaped columns.
      cache_creation_5m_tokens: !_isErrorPayload ? _extractAnthropicCacheCreation(provider, data.usage, 'ephemeral_5m_input_tokens') : null,
      cache_creation_1h_tokens: !_isErrorPayload ? _extractAnthropicCacheCreation(provider, data.usage, 'ephemeral_1h_input_tokens') : null,
      // Cache-read is a provider-neutral concept, unlike the two buckets above —
      // sourced through the adapter's normalized usage shape (Build B Part 1),
      // same as input_tokens/output_tokens two lines up, rather than reading
      // data.usage directly per provider.
      cache_read_tokens: (!_isErrorPayload && _normalized.usage) ? _normalized.usage.cacheReadTokens : null,
      provider_usage_raw: _isErrorPayload ? null : _normalized.providerUsageRaw,
      status: _isErrorPayload ? 'error' : 'success',
      provider_http_status: httpStatus,
      error_type: _isErrorPayload ? _normalized.normalizedErrorCode : null,
      failure_phase: _isErrorPayload ? 'outbound_call' : null,
      request_started_at: _requestStartedAt.toISOString(),
      duration_ms: _durationMs,
      request_bytes: bodyBytes,
      response_bytes: responseBytes
    });

    // v9.14: provider-neutral response envelope (Section 5.4) — the client's
    // callAPI() now reads data.text, not data.content[0].text. On an error
    // payload, keep the existing {error:{type,message}} shape the client's
    // _pgtAnthropicErrorMessage() already knows how to interpret; _rawType
    // preserves Anthropic's exact original error.type string so that
    // function's existing per-type prefixes don't regress for Anthropic.
    if (_isErrorPayload) {
      return res.status(200).json({
        error: {
          type: _normalized._rawType || _normalized.normalizedErrorCode,
          message: _normalized.safeErrorMessage
        }
      });
    }
    return res.status(200).json({ text: _normalized.text });

  } catch (err) {
    const isTimeout = /upstream timeout/i.test(err.message || '');
    const _errProvider = req.resolvedProvider || 'anthropic';
    console.error('[PROXY] Error:', err.message);

    // ── AI usage-tracking insert — error/timeout path (v9.13) ──
    // This branch fires when NO response was ever received from Anthropic at
    // all (network failure, timeout, or a thrown parse error) — distinct from
    // the success-path branch above, which handles a received-but-error-
    // payload response. token/model/response fields are genuinely unavailable
    // here, left null rather than defaulted to 0 (a real "we don't know," not
    // a false "this cost nothing"). Only fires if the earlier per-call setup
    // (timing, field extraction) completed — an error before that point
    // (e.g. malformed body caught earlier in this handler) never reaches
    // this catch block in the first place, so _requestStartedAt is safe to
    // reference here.
    if (typeof _requestStartedAt !== 'undefined') {
      const _durationMs = Date.now() - _requestStartedAt.getTime();
      await _insertAiUsageEvent({
        client_call_id: typeof _clientCallId !== 'undefined' ? _clientCallId : null,
        provider: _errProvider,
        company_id: req.companyId || null,
        product_id: typeof _productId !== 'undefined' ? _productId : null,
        session_id: typeof _sessionId !== 'undefined' ? _sessionId : null,
        session_type: typeof _sessionType !== 'undefined' ? _sessionType : null,
        user_id: req.user ? req.user.id : null,
        user_role_at_call: typeof _userRoleAtCall !== 'undefined' ? _userRoleAtCall : null,
        caller: typeof _caller !== 'undefined' ? _caller : 'unknown',
        prompt_version: typeof _promptVersion !== 'undefined' ? _promptVersion : null,
        requested_model: (body && body.model) || null,
        response_model: null,
        settings_mode: typeof _settingsMode !== 'undefined' ? _settingsMode : null,
        settings_model: typeof _settingsModel !== 'undefined' ? _settingsModel : null,
        selection_rule: typeof _selectionRule !== 'undefined' ? _selectionRule : null,
        input_tokens: null,
        output_tokens: null,
        cache_creation_5m_tokens: null,
        cache_creation_1h_tokens: null,
        cache_read_tokens: null,
        provider_usage_raw: null,
        status: isTimeout ? 'timeout' : 'error',
        provider_http_status: null,
        error_type: isTimeout ? 'timeout_error' : 'proxy_error',
        failure_phase: 'outbound_call',
        request_started_at: _requestStartedAt.toISOString(),
        duration_ms: _durationMs,
        request_bytes: typeof bodyBytes !== 'undefined' ? bodyBytes : null,
        response_bytes: null
      });
    }

    if (!res.headersSent) {
      return res.status(isTimeout ? 504 : 502).json({
        error: {
          type: isTimeout ? 'timeout_error' : 'proxy_error',
          message: isTimeout
            ? 'AI request timed out. The model took too long to respond — please try again.'
            : 'Proxy could not reach ' + _errProvider + '. Check your network or try again. Detail: ' + err.message
        }
      });
    }
    try { res.end(); } catch (_) {}
  }
});

// ── Check Company Name (Phase 1) ─────────────────────────────────────────────
// Unauthenticated by design — called before signup exists, so there's no JWT
// to verify yet. Uses the admin client to bypass RLS (mt_companies' SELECT
// policy requires active membership, which an unauthenticated caller never
// has). Rate-limited above; no JWT check on this route.
app.use('/api/check-company-name', express.json({ limit: '10kb' }));
app.post('/api/check-company-name', async (req, res) => {
  try {
    if (!supabaseAdmin) {
      console.error('[CHECK-COMPANY] supabaseAdmin not initialised — SUPABASE_SERVICE_ROLE_KEY missing');
      return res.status(200).json({ exists: false, error: 'Server not configured for this check.' });
    }
    const name = (req.body && req.body.name || '').trim();
    if (!name) {
      return res.status(200).json({ exists: false });
    }
    // Case-insensitive exact match, trimmed on both sides (input trimmed
    // above; ilike handles case, the stored name was trimmed at creation
    // time by create_company_with_admin()).
    const { data, error } = await supabaseAdmin
      .from('mt_companies')
      .select('id')
      .ilike('name', name)
      .limit(1);

    if (error) {
      console.warn('[CHECK-COMPANY] query failed:', error.message);
      return res.status(200).json({ exists: false, error: 'Check failed — proceeding as no match.' });
    }
    return res.status(200).json({ exists: !!(data && data.length > 0) });
  } catch (err) {
    console.error('[CHECK-COMPANY] exception:', err.message);
    return res.status(200).json({ exists: false, error: 'Check failed — proceeding as no match.' });
  }
});

// ── Embeddings — Requirement Agent persistent-document RAG (v14) ─────────────
// RA-Persistent-Doc-RAG-Spec-v14, D4/D6. Two routes: POST /api/embed (batch-
// embeds chunk texts) and GET /api/embed-info (reports the current schema
// version for the client's compatibility badge). Both registered before the
// 404 catch-all below, under this file's existing CORS allow-list (not just
// its auth middleware — the diagnostic route used during OI-6's smoke test
// skipped CORS registration specifically and was rejected from real app
// traffic for exactly that reason), same JWT auth (requireAuthStrict) as
// every other authenticated route, and this file's own rate-limit pattern.

app.options('/api/embed', cors(corsOptions));
app.options('/api/embed-info', cors(corsOptions));

const embedLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MIN * 60 * 1000,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(200).json({
      error: {
        type: 'rate_limit_error',
        message: `Too many requests — limit is ${RATE_LIMIT_MAX} per ${RATE_LIMIT_WINDOW_MIN === 1 ? 'minute' : RATE_LIMIT_WINDOW_MIN + ' minutes'}. Please wait and try again.`
      }
    });
  }
});
app.use('/api/embed', embedLimiter);
app.use('/api/embed-info', embedLimiter);
app.use('/api/embed', requireAuthStrict);
app.use('/api/embed-info', requireAuthStrict);
// Scoped to /api/embed only — /api/embed-info has no body. 2mb comfortably
// covers D4's own ~200,000-character aggregate cap (re-checked explicitly
// inside the handler below — this Express-level limit is just the outer
// safety net, not the real enforcement point).
app.use('/api/embed', express.json({ limit: '2mb' }));

// D6 — deliberately a hardcoded, maintained-by-hand constant, never derived
// from Azure deployment configuration or an env var (an earlier draft of
// this spec tried deriving it and found that unsafe — a deployment-side
// change wouldn't reliably bump it, silently mixing embeddings from two
// incompatible schema generations in the same table). Bump this string
// value by hand if the embedding model/deployment ever materially changes.
const EMBEDDING_SCHEMA_VERSION = 'azure-text-embedding-3-small-v1';
const EMBEDDING_DIMENSIONS = 1536;

// D4 per-request/aggregate caps — checked here, before ever calling Azure,
// not relied on Azure to reject (Azure's own limits — 2048 inputs/request,
// 8192 tokens/input, 300,000 tokens/request aggregate — are comfortably
// wider than these, so these are this app's own, tighter, deliberate caps).
const EMBED_MAX_TEXTS = 200;
const EMBED_MAX_CHARS_PER_TEXT = 4000;
const EMBED_MAX_AGGREGATE_CHARS = 200000;

// Calls Azure OpenAI's current (2026) v1 embeddings endpoint — confirmed
// against Microsoft's live REST reference during this build, not assumed
// from an older code sample: POST {endpoint}/openai/v1/embeddings, api-key
// header auth, the deployment name passed as the body's `model` field (not
// a URL path segment — that's the OLDER, now-superseded deployment-scoped
// pattern). Explicit timeout via AbortController (D8) — embeddings are
// normally fast, but a batch of up to 200 texts gets a generous margin.
async function _embedAzure(texts) {
  if (!AZURE_OPENAI_ENDPOINT || !AZURE_OPENAI_KEY || !AZURE_OPENAI_EMBED_DEPLOYMENT) {
    throw new Error('Azure OpenAI embedding is not configured on this proxy.');
  }
  const controller = new AbortController();
  const timeoutMs = 30000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const r = await fetch(AZURE_OPENAI_ENDPOINT + '/openai/v1/embeddings?api-version=v1', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'api-key': AZURE_OPENAI_KEY },
      body: JSON.stringify({ model: AZURE_OPENAI_EMBED_DEPLOYMENT, input: texts }),
      signal: controller.signal
    });
    const data = await r.json().catch(() => null);
    if (!r.ok || !data) {
      const msg = (data && data.error && data.error.message) || ('Azure OpenAI embedding request failed (HTTP ' + r.status + ').');
      throw new Error(msg);
    }
    if (!Array.isArray(data.data) || data.data.length !== texts.length) {
      throw new Error('Azure OpenAI returned an unexpected number of embeddings.');
    }
    // Sort by Azure's own `index` field rather than trusting array order —
    // the API does not explicitly document ordering as guaranteed, and this
    // is the one place a silent misalignment would corrupt every chunk's
    // embedding without any visible symptom.
    const ordered = data.data.slice().sort((a, b) => a.index - b.index);
    const embeddings = ordered.map(item => item.embedding);
    // D6 — explicit dimension validation: reject before this ever reaches
    // the database, rather than letting a malformed/mismatched response
    // surface as a confusing pgvector cast error three layers away.
    for (let i = 0; i < embeddings.length; i++) {
      if (!Array.isArray(embeddings[i]) || embeddings[i].length !== EMBEDDING_DIMENSIONS) {
        throw new Error('Azure OpenAI returned an embedding with an unexpected dimension count.');
      }
    }
    return embeddings;
  } finally {
    clearTimeout(timer);
  }
}

app.post('/api/embed', async (req, res) => {
  try {
    const texts = req.body && req.body.texts;
    if (!Array.isArray(texts) || texts.length === 0 || texts.length > EMBED_MAX_TEXTS) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'texts must be a non-empty array of at most ' + EMBED_MAX_TEXTS + ' strings.' } });
    }
    let aggregateChars = 0;
    for (let i = 0; i < texts.length; i++) {
      if (typeof texts[i] !== 'string' || !texts[i].trim()) {
        return res.status(200).json({ error: { type: 'invalid_request', message: 'Every entry in texts must be a non-empty string.' } });
      }
      if (texts[i].length > EMBED_MAX_CHARS_PER_TEXT) {
        return res.status(200).json({ error: { type: 'invalid_request', message: 'Each text must be at most ' + EMBED_MAX_CHARS_PER_TEXT + ' characters.' } });
      }
      aggregateChars += texts[i].length;
    }
    if (aggregateChars > EMBED_MAX_AGGREGATE_CHARS) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'Total text length across this request is too large.' } });
    }

    const embeddings = await _embedAzure(texts);
    return res.status(200).json({ embeddings, embedding_schema_version: EMBEDDING_SCHEMA_VERSION });
  } catch (err) {
    const isTimeout = err && err.name === 'AbortError';
    console.error('[EMBED] error:', err && err.message);
    return res.status(200).json({
      error: {
        type: isTimeout ? 'timeout_error' : 'proxy_error',
        message: isTimeout ? 'Embedding request timed out. Please try again.' : 'Could not generate embeddings. Please try again.'
      }
    });
  }
});

app.get('/api/embed-info', (req, res) => {
  return res.status(200).json({ embedding_schema_version: EMBEDDING_SCHEMA_VERSION });
});

// ── Team Management (Phase 4) ─────────────────────────────────────────────────
// All seven routes below run behind requireAuthStrict + requireCompanyAdmin
// (registered above). req.companyId is the verified, trusted company id —
// every query here scopes by BOTH company_id and the target user_id, never
// user_id alone, so a request can't act across companies even if a
// target_user_id from a different company were somehow supplied.

// Path B "already registered" detection is a text/status match against the
// GoTrue error — this needs live verification in dev against the actual
// error shape returned, not just assumed from SDK types.
function _isAlreadyRegisteredError(err) {
  if (!err) return false;
  if (err.status === 422) return true;
  const msg = (err.message || '').toLowerCase();
  return msg.includes('already') && (msg.includes('registered') || msg.includes('exists'));
}

// The atomic RPCs (team_set_role_safe/team_disable_safe/team_delete_member_safe) return
// a plain boolean, which can't distinguish "target isn't a member of THIS company at all"
// from "target is the last active admin." Calling them against a target with no row in
// req.companyId silently returns false, and the route would otherwise surface the
// misleading "last admin" message for what's actually a not-a-member case. Checking
// existence first, scoped by both company_id and user_id, closes that.
async function _membershipExistsInCompany(companyId, userId) {
  const { data, error } = await supabaseAdmin
    .from('mt_users_companies')
    .select('role')
    .eq('company_id', companyId)
    .eq('user_id', userId)
    .maybeSingle();
  if (error) return { exists: false, error };
  return { exists: !!data, error: null };
}

// ── List ──
app.post('/api/team/list', async (req, res) => {
  try {
    const { data: rows, error } = await supabaseAdmin
      .from('mt_users_companies')
      .select('user_id, role, is_active, joined_at')
      .eq('company_id', req.companyId);
    if (error) {
      console.error('[TEAM] list query failed:', error.message);
      return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not load team members.' } });
    }

    const members = await Promise.all((rows || []).map(async function(row) {
      try {
        const { data: userData, error: userErr } = await supabaseAdmin.auth.admin.getUserById(row.user_id);
        if (userErr || !userData || !userData.user) {
          console.warn('[TEAM] list: getUserById failed for', row.user_id, userErr && userErr.message);
          return null;
        }
        const u = userData.user;
        const displayName = (u.user_metadata && u.user_metadata.display_name) || '';
        const namePlaceholder = !displayName;
        const status = !row.is_active ? 'disabled' : (!u.last_sign_in_at ? 'invite_pending' : 'active');
        return {
          user_id: row.user_id,
          name: displayName || (u.email || '').split('@')[0],
          namePlaceholder,
          email: u.email || '',
          role: row.role,
          status,
          is_self: row.user_id === req.user.id
        };
      } catch (e) {
        console.warn('[TEAM] list: exception resolving', row.user_id, e.message);
        return null;
      }
    }));

    return res.status(200).json({ members: members.filter(Boolean) });
  } catch (err) {
    console.error('[TEAM] list exception:', err.message);
    return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not load team members.' } });
  }
});

// ── Invite ── Path A (new email) / Path B (already registered elsewhere)
app.post('/api/team/invite', async (req, res) => {
  try {
    const rawEmail = (req.body && req.body.email) || '';
    const email = rawEmail.trim().toLowerCase();
    const fullName = (req.body && req.body.full_name || '').trim();
    // v9.09 — explicit allowlist covering all 3 roles. Omitted/unrecognized
    // still defaults to 'member' (Power User) — an invite with no role
    // specified is normal, unlike set-role below where an invalid value on
    // an EXISTING member is treated as a hard error, not a silent default.
    const _validInviteRoles = ['admin', 'member', 'readonly'];
    const role = (req.body && _validInviteRoles.includes(req.body.role)) ? req.body.role : 'member';

    if (!email) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'Email is required.' } });
    }

    // Company name is looked up for invite metadata only — Supabase templates
    // can reference {{ .Data.company_name }} once template customization is
    // set up (needs a paid plan, deferred). Not sent for Path B, since no
    // invite email fires in that branch at all.
    let companyName = null;
    try {
      const { data: companyRow } = await supabaseAdmin
        .from('mt_companies')
        .select('name')
        .eq('id', req.companyId)
        .maybeSingle();
      companyName = companyRow && companyRow.name;
    } catch (e) {
      console.warn('[TEAM] invite: company name lookup failed, proceeding without it:', e.message);
    }

    const inviteMetadata = {};
    if (fullName) inviteMetadata.display_name = fullName;
    if (companyName) inviteMetadata.company_name = companyName;

    // redirectTo: reads the browser-enforced Origin header directly — never a
    // client-supplied field, which would just be a second value to spoof and
    // validate against the first. No match means no redirectTo at all,
    // falling back to Supabase's own configured Site URL default rather
    // than erroring the whole invite.
    const inviteOptions = { data: Object.keys(inviteMetadata).length ? inviteMetadata : undefined };
    const redirectTo = _resolveInviteRedirect(req);
    if (redirectTo) inviteOptions.redirectTo = redirectTo; // top-level — inviteUserByEmail's real shape

    const inviteResult = await supabaseAdmin.auth.admin.inviteUserByEmail(email, inviteOptions);

    let targetUserId = null;
    let path = null;

    if (!inviteResult.error && inviteResult.data && inviteResult.data.user) {
      targetUserId = inviteResult.data.user.id;
      path = 'A';
    } else if (_isAlreadyRegisteredError(inviteResult.error)) {
      const { data: existingId, error: rpcErr } = await supabaseAdmin.rpc('get_user_id_by_email', { p_email: email });
      if (rpcErr || !existingId) {
        console.warn('[TEAM] invite: Path B lookup failed for', email, rpcErr && rpcErr.message);
        return res.status(200).json({ error: { type: 'invalid_request', message: 'Could not find that account. Please check the email and try again.' } });
      }
      targetUserId = existingId;
      path = 'B';
    } else {
      console.warn('[TEAM] invite: inviteUserByEmail failed:', inviteResult.error && inviteResult.error.message);
      return res.status(200).json({ error: { type: 'invalid_request', message: 'Could not send invite. Please check the email and try again.' } });
    }

    const { error: insertErr } = await supabaseAdmin
      .from('mt_users_companies')
      .insert({ user_id: targetUserId, company_id: req.companyId, role, is_active: true });

    if (insertErr) {
      if (insertErr.code === '23505') {
        return res.status(200).json({ error: { type: 'invalid_request', message: 'Already a member of this company.' } });
      }
      console.error('[TEAM] invite: membership insert failed:', insertErr.message);
      return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not add member. Please try again.' } });
    }

    console.log('[TEAM] invite:', req.user.email, '->', email, 'path', path, 'company', req.companyId);
    return res.status(200).json({
      ok: true,
      path,
      message: path === 'A' ? ('Invite sent to ' + email) : ('Added ' + email + ' to the team')
    });
  } catch (err) {
    console.error('[TEAM] invite exception:', err.message);
    return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not send invite. Please try again.' } });
  }
});

// ── Set role ── Make Admin / Make Power User / Make Read Only
app.post('/api/team/set-role', async (req, res) => {
  try {
    const targetUserId = req.body && req.body.target_user_id;
    // v9.09 — HARD FAIL on invalid new_role, not a silent coerce-to-'member'.
    // This is deliberately different from /api/team/invite's behavior:
    // an invite with an omitted role defaulting is normal; a set-role
    // request naming an existing member with a garbled/unrecognized role
    // string is either a bug or an attack, and silently downgrading it to
    // 'member' would have granted MORE privilege than requested if the
    // caller actually meant 'readonly' — the exact landmine found during
    // adversarial review. Reject outright instead.
    const _validRoles = ['admin', 'member', 'readonly'];
    const newRole = req.body && req.body.new_role;
    if (typeof newRole !== 'string' || !_validRoles.includes(newRole)) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'Invalid role specified.' } });
    }
    if (!targetUserId) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'target_user_id is required.' } });
    }
    if (targetUserId === req.user.id) {
      return res.status(200).json({ error: { type: 'invalid_request', message: "You can't change your own role here." } });
    }
    const membership = await _membershipExistsInCompany(req.companyId, targetUserId);
    if (membership.error) {
      console.error('[TEAM] set-role: membership check failed:', membership.error.message);
      return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not change role. Please try again.' } });
    }
    if (!membership.exists) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'This person is not a member of this company.' } });
    }
    const { data: ok, error } = await supabaseAdmin.rpc('team_set_role_safe', {
      p_company_id: req.companyId, p_target_user: targetUserId, p_new_role: newRole
    });
    if (error) {
      console.error('[TEAM] set-role RPC failed:', error.message);
      return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not change role. Please try again.' } });
    }
    if (!ok) {
      return res.status(200).json({ error: { type: 'invalid_request', message: "Can't remove the last admin — promote someone else first." } });
    }
    console.log('[TEAM] set-role:', req.user.email, '->', targetUserId, 'to', newRole, 'company', req.companyId);
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('[TEAM] set-role exception:', err.message);
    return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not change role. Please try again.' } });
  }
});

// ── Disable ──
app.post('/api/team/disable', async (req, res) => {
  try {
    const targetUserId = req.body && req.body.target_user_id;
    if (!targetUserId) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'target_user_id is required.' } });
    }
    if (targetUserId === req.user.id) {
      return res.status(200).json({ error: { type: 'invalid_request', message: "You can't disable your own access." } });
    }
    const membership = await _membershipExistsInCompany(req.companyId, targetUserId);
    if (membership.error) {
      console.error('[TEAM] disable: membership check failed:', membership.error.message);
      return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not disable member. Please try again.' } });
    }
    if (!membership.exists) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'This person is not a member of this company.' } });
    }
    const { data: ok, error } = await supabaseAdmin.rpc('team_disable_safe', {
      p_company_id: req.companyId, p_target_user: targetUserId, p_disabled_by: req.user.id
    });
    if (error) {
      console.error('[TEAM] disable RPC failed:', error.message);
      return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not disable member. Please try again.' } });
    }
    if (!ok) {
      return res.status(200).json({ error: { type: 'invalid_request', message: "Can't remove the last admin — promote someone else first." } });
    }
    console.log('[TEAM] disable:', req.user.email, '->', targetUserId, 'company', req.companyId);
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('[TEAM] disable exception:', err.message);
    return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not disable member. Please try again.' } });
  }
});

// ── Enable ── no admin-count concern — re-enabling never reduces active admins
app.post('/api/team/enable', async (req, res) => {
  try {
    const targetUserId = req.body && req.body.target_user_id;
    if (!targetUserId) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'target_user_id is required.' } });
    }
    const { error } = await supabaseAdmin
      .from('mt_users_companies')
      .update({ is_active: true, disabled_at: null, disabled_by: null })
      .eq('user_id', targetUserId)
      .eq('company_id', req.companyId);
    if (error) {
      console.error('[TEAM] enable failed:', error.message);
      return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not re-enable member. Please try again.' } });
    }
    console.log('[TEAM] enable:', req.user.email, '->', targetUserId, 'company', req.companyId);
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('[TEAM] enable exception:', err.message);
    return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not re-enable member. Please try again.' } });
  }
});

// ── Delete ── two-step: (1) no resolution -> return shared-session count so the
// client can branch the confirm UI; (2) with resolution -> execute.
// Order matters: the membership delete (admin-count-safe) happens FIRST — if it's
// blocked (last admin), no session data is touched at all. Only on success do we
// clear locks and apply the chosen resolution to shared sessions. Private
// sessions are never touched, in any branch, per the accepted design decision.
app.post('/api/team/delete', async (req, res) => {
  try {
    const targetUserId = req.body && req.body.target_user_id;
    const resolution = req.body && req.body.resolution; // undefined | 'retain' | 'reassign' | 'delete_sessions'
    if (!targetUserId) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'target_user_id is required.' } });
    }
    if (targetUserId === req.user.id) {
      return res.status(200).json({ error: { type: 'invalid_request', message: "You can't remove your own access." } });
    }
    const membership = await _membershipExistsInCompany(req.companyId, targetUserId);
    if (membership.error) {
      console.error('[TEAM] delete: membership check failed:', membership.error.message);
      return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not remove member. Please try again.' } });
    }
    if (!membership.exists) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'This person is not a member of this company.' } });
    }

    if (!resolution) {
      // Step 1: report both shared and private session counts, no mutation yet.
      // Private count is disclosed here too (v8.114) — Delete now actually
      // deletes private sessions, not just orphans them, so the confirm UI
      // needs to tell the admin how many sessions are about to be permanently
      // lost, not just show a generic "can't be undone."
      const { count: sharedCount, error: sharedErr } = await supabaseAdmin
        .from('mt_sessions')
        .select('id', { count: 'exact', head: true })
        .eq('user_id', targetUserId)
        .eq('company_id', req.companyId)
        .eq('is_shared', true);
      if (sharedErr) {
        console.error('[TEAM] delete: shared-session count failed:', sharedErr.message);
        return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not check shared sessions. Please try again.' } });
      }
      const { count: privateCount, error: privateErr } = await supabaseAdmin
        .from('mt_sessions')
        .select('id', { count: 'exact', head: true })
        .eq('user_id', targetUserId)
        .eq('company_id', req.companyId)
        .eq('is_shared', false);
      if (privateErr) {
        console.error('[TEAM] delete: private-session count failed:', privateErr.message);
        return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not check sessions. Please try again.' } });
      }
      return res.status(200).json({ shared_session_count: sharedCount || 0, private_session_count: privateCount || 0 });
    }

    // Step 2: execute.
    const { data: deleted, error: delErr } = await supabaseAdmin.rpc('team_delete_member_safe', {
      p_company_id: req.companyId, p_target_user: targetUserId
    });
    if (delErr) {
      console.error('[TEAM] delete RPC failed:', delErr.message);
      return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not remove member. Please try again.' } });
    }
    if (!deleted) {
      return res.status(200).json({ error: { type: 'invalid_request', message: "Can't remove the last admin — promote someone else first." } });
    }

    // Clear generation-lock fields unconditionally on every shared session touched,
    // before applying the resolution — closes the "reassign/delete while someone
    // else's lock is still live" gap.
    await supabaseAdmin
      .from('mt_sessions')
      .update({ active_user_id: null, active_at: null })
      .eq('user_id', targetUserId)
      .eq('company_id', req.companyId)
      .eq('is_shared', true);

    // v9.12 — same cleanup for the separate occupancy lock (Session
    // Occupancy Lock / "Single User Editing" mode). Flagged during
    // adversarial review: without this, a removed member's still-
    // authenticated browser could keep refreshing occupant_at via
    // heartbeat_session_occupancy indefinitely, since that RPC only checks
    // occupant_user_id = current_app_user() and lease freshness — it has no
    // independent membership check of its own, by design (matching
    // acquire_generation_lock's own heartbeat, which relies on this exact
    // same admin-cleanup pattern rather than re-checking membership on
    // every 22-second tick).
    await supabaseAdmin
      .from('mt_sessions')
      .update({ occupant_user_id: null, occupant_at: null, occupant_user_name: null })
      .eq('user_id', targetUserId)
      .eq('company_id', req.companyId)
      .eq('is_shared', true);

    let affectedCount = 0;
    if (resolution === 'reassign') {
      // Phase 5: .select('id') added so the response can echo the REAL
      // affected count back to the client toast, rather than the client
      // re-displaying the step-1 count it fetched a few seconds earlier —
      // which could theoretically have drifted if something else changed
      // a session's is_shared/ownership in between the two calls.
      const { data: reassignedRows, error: reassignErr } = await supabaseAdmin
        .from('mt_sessions')
        .update({ user_id: req.user.id })
        .eq('user_id', targetUserId)
        .eq('company_id', req.companyId)
        .eq('is_shared', true)
        .select('id');
      if (reassignErr) console.warn('[TEAM] delete: reassign failed:', reassignErr.message);
      else affectedCount = (reassignedRows || []).length;
    } else if (resolution === 'delete_sessions') {
      const { data: deletedRows, error: sessDelErr } = await supabaseAdmin
        .from('mt_sessions')
        .delete()
        .eq('user_id', targetUserId)
        .eq('company_id', req.companyId)
        .eq('is_shared', true)
        .select('id');
      if (sessDelErr) console.warn('[TEAM] delete: session delete failed:', sessDelErr.message);
      else affectedCount = (deletedRows || []).length;
    }
    // Phase 5: any other resolution value (e.g. 'no_shared_sessions', the
    // client's own no-op marker for the zero-shared-sessions path) ->
    // no further mutation on shared sessions beyond the lock clear above,
    // affectedCount stays 0. Retain as a concept is fully removed — see
    // team-management.js's _tmShowSharedSessionChoice for why.

    // Private sessions are always deleted outright (v8.114) — reversed from the
    // original "leave untouched" design once cross-checked against Disable,
    // which already fully covers the "maybe they're coming back" reversible
    // case with less friction than delete+reinvite. Delete is free to be the
    // genuinely destructive option. No lock-clearing needed first — the row
    // is being removed entirely, not retained in a modified state.
    const { error: privateDelErr } = await supabaseAdmin
      .from('mt_sessions')
      .delete()
      .eq('user_id', targetUserId)
      .eq('company_id', req.companyId)
      .eq('is_shared', false);
    if (privateDelErr) console.warn('[TEAM] delete: private session delete failed:', privateDelErr.message);

    console.log('[TEAM] delete:', req.user.email, '-> removed', targetUserId, 'resolution', resolution, 'company', req.companyId);
    return res.status(200).json({ ok: true, affected_count: affectedCount });
  } catch (err) {
    console.error('[TEAM] delete exception:', err.message);
    return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not remove member. Please try again.' } });
  }
});

// ── Resend ── pending invites only. Generates a fresh link via generateLink() —
// does NOT delete/recreate the account (reversed from the original design once
// the adversarial review confirmed a single auth identity can span multiple
// companies; deleting it would have destroyed the person's OTHER memberships
// too). No SMTP infra exists, so this returns a link for the admin to share
// directly rather than claiming an email was re-sent.
app.post('/api/team/resend', async (req, res) => {
  try {
    const targetUserId = req.body && req.body.target_user_id;
    if (!targetUserId) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'target_user_id is required.' } });
    }
    const { data: membership, error: memErr } = await supabaseAdmin
      .from('mt_users_companies')
      .select('is_active')
      .eq('user_id', targetUserId)
      .eq('company_id', req.companyId)
      .maybeSingle();
    if (memErr || !membership || !membership.is_active) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'This person is not an active member of this company.' } });
    }
    const { data: userData, error: userErr } = await supabaseAdmin.auth.admin.getUserById(targetUserId);
    if (userErr || !userData || !userData.user) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'Could not find that account.' } });
    }
    if (userData.user.last_sign_in_at) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'This person has already signed in — nothing to resend.' } });
    }
    const linkParams = { type: 'invite', email: userData.user.email };
    const redirectTo = _resolveInviteRedirect(req);
    if (redirectTo) linkParams.options = { redirectTo }; // nested under options — generateLink's real shape, confirmed against the shipped @supabase/auth-js types (top-level redirectTo would be silently ignored)
    const { data: linkData, error: linkErr } = await supabaseAdmin.auth.admin.generateLink(linkParams);
    if (linkErr || !linkData) {
      console.error('[TEAM] resend: generateLink failed:', linkErr && linkErr.message);
      return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not generate a new invite link. Please try again.' } });
    }
    const link = linkData.properties && linkData.properties.action_link;
    console.log('[TEAM] resend:', req.user.email, '-> new link for', userData.user.email, 'company', req.companyId);
    return res.status(200).json({ ok: true, link: link || null });
  } catch (err) {
    console.error('[TEAM] resend exception:', err.message);
    return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not generate a new invite link. Please try again.' } });
  }
});

// ── Revoke ── pending invites only. Deletes the membership row ONLY — never
// the auth.users account (reversed from the original design; see resend
// comment above for why a hard account delete is unsafe in a multi-company
// identity model). Accepted trade-off: re-inviting the same email later may
// silently resolve via Path B if that person completed signup elsewhere in
// the meantime — narrow and non-destructive, matches §0.1's "never
// hard-delete the account" principle.
app.post('/api/team/revoke', async (req, res) => {
  try {
    const targetUserId = req.body && req.body.target_user_id;
    if (!targetUserId) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'target_user_id is required.' } });
    }
    const { data: userData, error: userErr } = await supabaseAdmin.auth.admin.getUserById(targetUserId);
    if (userErr || !userData || !userData.user) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'Could not find that account.' } });
    }
    if (userData.user.last_sign_in_at) {
      return res.status(200).json({ error: { type: 'invalid_request', message: 'This person has already signed in — use Disable or Delete instead.' } });
    }
    const { error: delErr } = await supabaseAdmin
      .from('mt_users_companies')
      .delete()
      .eq('user_id', targetUserId)
      .eq('company_id', req.companyId);
    if (delErr) {
      console.error('[TEAM] revoke failed:', delErr.message);
      return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not revoke invite. Please try again.' } });
    }
    console.log('[TEAM] revoke:', req.user.email, '-> revoked', targetUserId, 'company', req.companyId);
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('[TEAM] revoke exception:', err.message);
    return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not revoke invite. Please try again.' } });
  }
});

// ── 404 catch-all ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(200).json({
    error: {
      type: 'not_found',
      message: 'Route not found: ' + req.method + ' ' + req.path
    }
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('  ✓ Product Diagnostics Proxy running');
  console.log('  → Endpoint: http://localhost:' + PORT + '/api/anthropic');
  console.log('  → Auth:     JWT verification ' + (SUPABASE_URL ? 'ENABLED (JWKS / ECC P-256)' : 'DISABLED — set SUPABASE_URL'));
  console.log('  → API key:  anthropic=' + (ORG_API_KEY_BY_PROVIDER.anthropic ? 'org key set' : 'BYOK only') + ', openai=' + (ORG_API_KEY_BY_PROVIDER.openai ? 'org key set' : 'BYOK only') + ', gemini=' + (ORG_API_KEY_BY_PROVIDER.gemini ? 'org key set' : 'BYOK only'));
  console.log('');
});
