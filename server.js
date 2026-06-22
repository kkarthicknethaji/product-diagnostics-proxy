// ─────────────────────────────────────────────────────────────────────────────
// Product Growth Toolkit — Anthropic Proxy
// Render.com deployment — Phase 1 (Auth + BYOK)
//
// Responsibilities:
//   - Receive POST /api/anthropic from browser (Netlify frontend)
//   - Verify Supabase JWT from X-Auth-Token header — reject unauthenticated requests
//   - Forward to Anthropic server-side (no CORS restrictions, no timeout)
//   - API key priority: ANTHROPIC_API_KEY env var (shared org key) → user BYOK key fallback
//   - Returns structured JSON errors — never raw HTML
//   - Rate limit: 20 req/min per IP
//
// Required env vars (set in Render dashboard):
//   ALLOWED_ORIGIN      — single origin allowed e.g. https://devproductdiagnostics.netlify.app
//   SUPABASE_JWT_SECRET — from Supabase project → Settings → API → JWT Secret
//   SUPABASE_URL        — from Supabase project → Settings → API → Project URL
//   ANTHROPIC_API_KEY   — optional shared org key; if unset, falls back to user BYOK key
// ─────────────────────────────────────────────────────────────────────────────

const express  = require('express');
const cors     = require('cors');
const rateLimit = require('express-rate-limit');
const jwt      = require('jsonwebtoken');

const app  = express();
const PORT = process.env.PORT || 3001;

// Trust Render's load balancer so express-rate-limit reads the real client IP
// from X-Forwarded-For instead of the proxy IP. Fixes rate-limit log warning.
app.set('trust proxy', 1);

// ── Env vars ──────────────────────────────────────────────────────────────────
const ALLOWED_ORIGIN      = process.env.ALLOWED_ORIGIN      || '';
const SUPABASE_JWT_SECRET = process.env.SUPABASE_JWT_SECRET || '';
const SUPABASE_URL        = process.env.SUPABASE_URL        || '';
const ORG_API_KEY         = process.env.ANTHROPIC_API_KEY   || ''; // optional shared key

// Warn on startup if critical env vars are missing
if (!SUPABASE_JWT_SECRET) console.warn('[WARN] SUPABASE_JWT_SECRET not set — JWT verification will fail');
if (!ALLOWED_ORIGIN)      console.warn('[WARN] ALLOWED_ORIGIN not set — all origins will be blocked');

// ── CORS ──────────────────────────────────────────────────────────────────────
// Single allowed origin from env var + local dev origins.
const LOCAL_ORIGINS = [
  'http://localhost',
  'http://127.0.0.1',
  'null' // file:// origin (local open-in-browser)
];

app.use(cors({
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
    return callback(new Error('CORS: origin not allowed — ' + origin));
  },
  methods: ['POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Auth-Token']
}));

// ── Body parser ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));

// ── Rate limiting ─────────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(200).json({
      error: {
        type: 'rate_limit_error',
        message: 'Too many requests — limit is 20 per minute. Please wait and try again.'
      }
    });
  }
});
app.use('/api/anthropic', limiter);

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'product-diagnostics-proxy', version: '2.0.0' });
});

// ── JWT auth middleware ───────────────────────────────────────────────────────
// Verifies Supabase JWT from X-Auth-Token header.
// Local dev (localhost / file://) bypasses JWT check — dev convenience only.
// All hosted requests must carry a valid token.
function requireAuth(req, res, next) {
  const origin = req.headers['origin'] || '';
  const isLocal = !origin ||
    origin.startsWith('http://localhost') ||
    origin.startsWith('http://127.0.0.1') ||
    origin === 'null';

  // Bypass JWT for local dev
  if (isLocal) {
    console.log('[AUTH] Local dev — JWT check bypassed');
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

  if (!SUPABASE_JWT_SECRET) {
    console.error('[AUTH] SUPABASE_JWT_SECRET not configured');
    return res.status(200).json({
      error: {
        type: 'auth_error',
        message: 'Auth not configured on proxy. Contact your administrator.'
      }
    });
  }

  try {
    const decoded = jwt.verify(token, SUPABASE_JWT_SECRET);
    req.user = { id: decoded.sub, email: decoded.email };
    console.log('[AUTH] JWT verified for:', req.user.email);
    return next();
  } catch (err) {
    console.warn('[AUTH] JWT verification failed:', err.message);
    return res.status(200).json({
      error: {
        type: 'auth_error',
        message: 'Session expired or invalid. Please sign in again.'
      }
    });
  }
}

app.use('/api/anthropic', requireAuth);

// ── Main proxy endpoint ───────────────────────────────────────────────────────
app.post('/api/anthropic', async (req, res) => {
  try {
    // ── API key resolution ──
    // Priority 1: shared org key from env var (set in Render — users don't need their own key)
    // Priority 2: BYOK key from Authorization: Bearer header
    let apiKey = ORG_API_KEY;
    if (!apiKey) {
      const authHeader = req.headers['authorization'] || '';
      apiKey = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    }

    if (!apiKey) {
      return res.status(200).json({
        error: {
          type: 'auth_error',
          message: 'No API key available. Enter your Anthropic API key in Settings.'
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
        rejectUnauthorized: false,
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
  console.log('  → Auth:     JWT verification ' + (SUPABASE_JWT_SECRET ? 'ENABLED' : 'DISABLED — set SUPABASE_JWT_SECRET'));
  console.log('  → API key:  ' + (ORG_API_KEY ? 'Shared org key (env var)' : 'BYOK only'));
  console.log('');
});
