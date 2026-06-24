// ─────────────────────────────────────────────────────────────────────────────
// Product Growth Toolkit — Anthropic Proxy
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
const ORG_API_KEY    = process.env.ANTHROPIC_API_KEY || ''; // optional shared key

// Warn on startup if critical env vars are missing
if (!SUPABASE_URL)    console.warn('[WARN] SUPABASE_URL not set — JWT verification will fail');
if (!ALLOWED_ORIGIN)  console.warn('[WARN] ALLOWED_ORIGIN not set — all origins will be blocked');

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

// ── Body parser ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));

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

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'product-diagnostics-proxy', version: '2.2.0' });
});

// ── JWT auth middleware ───────────────────────────────────────────────────────
// Verifies Supabase JWT (ES256 / ECC P-256) from X-Auth-Token header via JWKS.
// Local dev (localhost / file://) bypasses JWT check — dev convenience only.
// All hosted requests must carry a valid token.
function requireAuth(req, res, next) {
  // OPTIONS preflight must never require JWT — CORS middleware handles it.
  // This guard makes auth robust if middleware order ever changes.
  if (req.method === 'OPTIONS') {
    return next();
  }

  const origin = req.headers['origin'] || '';
  // Local dev bypass: explicit localhost/127.0.0.1/file:// origins only.
  // No-Origin requests on a hosted Render service are NOT local dev —
  // removing !origin closes the JWT bypass security gap.
  const isLocal =
    origin.startsWith('http://localhost') ||
    origin.startsWith('http://127.0.0.1') ||
    origin === 'null';

  // Bypass JWT for local dev only
  if (isLocal) {
    console.log('[AUTH] Local dev — JWT check bypassed for origin:', origin || '(none)');
    return next();
  }

  const token = req.headers['x-auth-token'] || '';
  if (!token) {
    return res.status(200).json({
      error: {
        type: 'auth_error',
        message: 'Not authenticated. Please sign in and try again.'
      }
    });
  }

  if (!jwksClient) {
    console.error('[AUTH] JWKS client not initialised — SUPABASE_URL missing');
    return res.status(200).json({
      error: {
        type: 'auth_error',
        message: 'Auth not configured on proxy. Contact your administrator.'
      }
    });
  }

  // Async callback-based verify — required for JWKS key retrieval
  jwt.verify(token, getSigningKey, { algorithms: ['ES256', 'RS256'] }, function(err, decoded) {
    if (err) {
      console.warn('[AUTH] JWT verification failed:', err.message);
      return res.status(200).json({
        error: {
          type: 'auth_error',
          message: 'Session expired or invalid. Please sign in again.'
        }
      });
    }
    req.user = { id: decoded.sub, email: decoded.email };
    console.log('[AUTH] JWT verified for:', req.user.email);
    return next();
  });
}

app.use('/api/anthropic', requireAuth);

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
    const postBody = JSON.stringify(body);

    const data = await new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.anthropic.com',
        port: 443,
        path: '/v1/messages',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postBody),
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        }
      };

      const proxyReq = https.request(options, (anthropicRes) => {
        let raw = '';
        anthropicRes.on('data', chunk => { raw += chunk; });
        anthropicRes.on('end', () => {
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

      proxyReq.on('error', (e) => reject(e));
      proxyReq.write(postBody);
      proxyReq.end();
    });

    return res.status(200).json(data);

  } catch (err) {
    console.error('[PROXY] Error:', err.message);
    return res.status(200).json({
      error: {
        type: 'proxy_error',
        message: 'Proxy could not reach Anthropic. Check your network or try again. Detail: ' + err.message
      }
    });
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
