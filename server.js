// ─────────────────────────────────────────────────────────────────────────────
// HCLTech Product Growth Diagnostic Suite — Anthropic Proxy
// Render.com deployment — Phase 2 (BYOK)
//
// Responsibilities:
//   - Receive POST /api/anthropic from browser (Netlify frontend)
//   - Forward to Anthropic server-side (no CORS restrictions, no timeout)
//   - BYOK: user key arrives in Authorization: Bearer header, forwarded as x-api-key
//   - Works for personal keys AND org keys
//   - Returns structured JSON errors — never raw HTML
//   - Rate limit: 20 req/min per IP
//
// Phase 3 additions (not built yet — structure is ready):
//   - Auth middleware (JWT or session-based)
//   - Per-user request logging
//   - Database connection (usage tracking, feature flags)
// ─────────────────────────────────────────────────────────────────────────────

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// ── CORS ──────────────────────────────────────────────────────────────────────
// Allow requests from the Netlify frontend and local development only.
// Phase 3: tighten to authenticated origins only.
const ALLOWED_ORIGINS = [
  'https://productdiagnostics.netlify.app',
  'https://devproductdiagnostics.netlify.app',
  'http://localhost',
  'http://127.0.0.1',
  'null' // file:// origin (local open-in-browser)
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (curl, Postman, server-to-server)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin) || origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1')) {
      return callback(null, true);
    }
    return callback(new Error('CORS: origin not allowed — ' + origin));
  },
  methods: ['POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ── Body parser ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));

// ── Rate limiting ─────────────────────────────────────────────────────────────
// 20 requests per minute per IP.
// Phase 3: swap windowMs/max with per-user DB-backed counters.
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
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
  res.json({ status: 'ok', service: 'product-diagnostics-proxy', version: '1.0.0' });
});

// ── Phase 3 auth middleware placeholder ──────────────────────────────────────
// Uncomment and implement when adding user sessions:
// app.use('/api/anthropic', requireAuth);

// ── Main proxy endpoint ───────────────────────────────────────────────────────
app.post('/api/anthropic', async (req, res) => {
  try {
    // Extract API key from Authorization: Bearer <key>
    const authHeader = req.headers['authorization'] || '';
    const apiKey = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

    if (!apiKey) {
      return res.status(200).json({
        error: {
          type: 'auth_error',
          message: 'No API key provided. Enter your Anthropic API key in Settings.'
        }
      });
    }

    // Forward the request body as-is to Anthropic
    const body = req.body;
    if (!body || !body.model || !body.messages) {
      return res.status(200).json({
        error: {
          type: 'invalid_request',
          message: 'Malformed request body — model and messages are required.'
        }
      });
    }

    // ── Forward to Anthropic ──────────────────────────────────────────────────
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
        // Note: anthropic-dangerous-direct-browser-access header NOT needed server-side
      },
      body: JSON.stringify(body)
    });

    const data = await anthropicRes.json();

    // Anthropic org policy block (403) — surface a clear message
    if (anthropicRes.status === 403) {
      return res.status(200).json({
        error: {
          type: 'permission_error',
          message: 'Your API key is blocked from server-side access. Check your Anthropic org policy settings, or use a personal API key.'
        }
      });
    }

    // Pass through all other Anthropic responses (200, 400, 429, 500, etc.)
    // Always return HTTP 200 to browser — errors are in the JSON body
    return res.status(200).json(data);

  } catch (err) {
    // Network error, Anthropic unreachable, or unexpected exception
    console.error('Proxy error:', err.message);
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
  console.log('Product Diagnostics Proxy running on port ' + PORT);
});
