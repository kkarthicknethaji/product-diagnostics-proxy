// ─────────────────────────────────────────────────────────────────────────────
// AI PM Toolkit — Anthropic Proxy
// Render.com deployment — Phase 1 (Auth + BYOK + Org Key)
//
// Responsibilities:
//   - Receive POST /api/anthropic from browser (Netlify frontend)
//   - Verify Supabase JWT from X-Auth-Token header using JWKS (ES256 / ECC P-256)
//   - Forward to Anthropic server-side (no CORS restrictions, no timeout)
//   - API key priority: user BYOK key → ANTHROPIC_API_KEY env var (org key fallback)
//   - Returns structured JSON errors — never raw HTML
//   - Rate limit: RATE_LIMIT_MAX req/min per IP
//
// Required env vars (set in Render dashboard):
//   ALLOWED_ORIGIN        — single origin allowed e.g. https://productdiagnostics.netlify.app
//   SUPABASE_URL          — from Supabase project → Settings → API → Project URL
//                           JWKS endpoint derived automatically: SUPABASE_URL/auth/v1/.well-known/jwks.json
//   ANTHROPIC_API_KEY     — optional shared org key; if unset, requires user BYOK key
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
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '';
const SUPABASE_URL   = process.env.SUPABASE_URL   || '';

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
const ORG_API_KEY    = process.env.ANTHROPIC_API_KEY || ''; // optional shared key
// New for Phase 1 — required for /api/check-company-name (and Phase 4's admin
// routes later). This is the first time this proxy talks to the Supabase
// database directly rather than only verifying JWTs; @supabase/supabase-js
// is a new dependency as of this change, it wasn't needed before.
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

// Warn on startup if critical env vars are missing
if (!SUPABASE_URL)    console.warn('[WARN] SUPABASE_URL not set — JWT verification will fail');
if (!ALLOWED_ORIGIN)  console.warn('[WARN] ALLOWED_ORIGIN not set — all origins will be blocked');
if (!SUPABASE_SERVICE_ROLE_KEY) console.warn('[WARN] SUPABASE_SERVICE_ROLE_KEY not set — /api/check-company-name and admin routes will fail');
if (!INVITE_REDIRECT_ALLOWLIST.length) console.warn('[WARN] INVITE_REDIRECT_ALLOWLIST not set — invite links will use the Supabase project default Site URL only');

// Admin client — bypasses RLS by design, used only for the narrow set of
// server-side operations that need it (pre-auth company name checks here;
// invite/disable/delete in Phase 4). Never exposed to the browser.
const supabaseAdmin = (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
  : null;

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
      (ALLOWED_ORIGIN && origin === ALLOWED_ORIGIN) ||
      LOCAL_ORIGINS.includes(origin) ||
      origin.startsWith('http://localhost') ||
      origin.startsWith('http://127.0.0.1')
    ) {
      return callback(null, true);
    }
    console.warn('[CORS] Origin blocked:', origin, '— Allowed:', ALLOWED_ORIGIN || '(none set)');
    return callback(new Error('CORS: origin not allowed — ' + origin));
  },
  methods: ['POST', 'OPTIONS'],
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
    delete req.body.company_id; // single source of truth from here on, same pattern as requireCompanyAdmin
    next();
  } catch (err) {
    console.error('[AI] membership check exception:', err.message);
    return res.status(200).json({ error: { type: 'proxy_error', message: 'Could not verify company access. Please try again.' } });
  }
}
app.use('/api/anthropic', requireActiveCompanyMember);

// ── Main proxy endpoint ───────────────────────────────────────────────────────
app.post('/api/anthropic', async (req, res) => {
  try {
    // ── API key resolution ──
    // Priority 1: BYOK key from Authorization: Bearer header (user-supplied)
    // Priority 2: shared org key from ANTHROPIC_API_KEY env var (Render dashboard)
    // If user supplies a BYOK key, it is always used — org key is never a silent fallback
    // for an invalid BYOK. Invalid BYOK → Anthropic returns auth error → surfaces to user.
    const authHeader = req.headers['authorization'] || '';
    const byokKey = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    let apiKey = byokKey || ORG_API_KEY;

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

    // ── Forward to Anthropic ──
    const https = require('https');
    const _caller = body._caller || 'unknown';
    const anthropicBody = {
      model:      body.model,
      max_tokens: body.max_tokens,
      system:     body.system,
      messages:   body.messages
    };
    const postBody = JSON.stringify(anthropicBody);
    const bodyBytes = Buffer.byteLength(postBody, 'utf8');

    console.log('[AI OUT]', { caller: _caller, model: body.model, max_tokens: body.max_tokens, bodyBytes });

    // v8.98: per-caller timeout — raising PI's ceiling should not tie up the
    // proxy longer for every other (smaller, faster) caller if THEY hang.
    const TIMEOUT_BY_CALLER = { 'pi-generate': 150000, 'mi-docx-gen': 150000 };
    const UPSTREAM_TIMEOUT_MS = TIMEOUT_BY_CALLER[_caller] || 120000;

    const data = await new Promise((resolve, reject) => {
      let upstreamTimedOut = false;

      const options = {
        hostname: 'api.anthropic.com',
        port: 443,
        path: '/v1/messages',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': bodyBytes,
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        }
      };

      const proxyReq = https.request(options, (anthropicRes) => {
        let raw = '';
        console.log('[AI RESPONSE START]', { statusCode: anthropicRes.statusCode });
        anthropicRes.on('data', chunk => { raw += chunk; });
        anthropicRes.on('end', () => {
          clearTimeout(upstreamTimer);
          console.log('[AI RESPONSE END]', {
            statusCode: anthropicRes.statusCode,
            responseBytes: Buffer.byteLength(raw, 'utf8')
          });
          try {
            const parsed = JSON.parse(raw);
            if (anthropicRes.statusCode === 403) {
              resolve({
                error: {
                  type: 'permission_error',
                  message: 'Your API key is blocked from server-side access. Check your Anthropic org policy settings, or use a personal API key.'
                }
              });
            } else {
              resolve(parsed);
            }
          } catch (e) {
            reject(new Error('Failed to parse Anthropic response: ' + e.message));
          }
        });
      });

      const upstreamTimer = setTimeout(() => {
        upstreamTimedOut = true;
        console.error('[AI TIMEOUT]', { caller: _caller, timeoutMs: UPSTREAM_TIMEOUT_MS, model: body.model, max_tokens: body.max_tokens });
        proxyReq.destroy(new Error('Anthropic upstream timeout after ' + UPSTREAM_TIMEOUT_MS + 'ms'));
      }, UPSTREAM_TIMEOUT_MS);

      proxyReq.on('error', (e) => {
        clearTimeout(upstreamTimer);
        console.error('[AI ERROR]', { caller: _caller, message: e.message, timeout: upstreamTimedOut });
        reject(e);
      });

      proxyReq.write(postBody);
      proxyReq.end();
    });

    return res.status(200).json(data);

  } catch (err) {
    const isTimeout = err.message && err.message.includes('upstream timeout');
    console.error('[PROXY] Error:', err.message);
    if (!res.headersSent) {
      return res.status(isTimeout ? 504 : 502).json({
        error: {
          type: isTimeout ? 'timeout_error' : 'proxy_error',
          message: isTimeout
            ? 'AI request timed out. The model took too long to respond — please try again.'
            : 'Proxy could not reach Anthropic. Check your network or try again. Detail: ' + err.message
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
  console.log('  → API key:  ' + (ORG_API_KEY ? 'Shared org key (env var)' : 'BYOK only'));
  console.log('');
});
