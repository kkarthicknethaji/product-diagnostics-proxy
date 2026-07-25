# AI PM Toolkit — Anthropic Proxy

Express.js server for handling authenticated API requests from the AI PM Toolkit frontend.

## Deployment

This is a **separate deployable** from the frontend. Deploy to Render.com:

1. Create new Web Service on Render
2. Connect GitHub repo: `kkarthicknethaji/product-diagnostics-proxy`
3. Set environment variables:
   - `ALLOWED_ORIGIN` — Frontend URL (e.g., `https://productdiagnostics.netlify.app`)
   - `SUPABASE_URL` — Supabase project URL
   - `ANTHROPIC_API_KEY` — Shared org API key (optional; uses user BYOK if unset)

4. Deploy from `main` branch

## Local Development

```bash
npm install
ALLOWED_ORIGIN=http://localhost:3000 \
SUPABASE_URL=https://your-supabase-url.supabase.co \
ANTHROPIC_API_KEY=your-key \
node server.js
```

## Features

- JWT validation via Supabase JWKS
- Rate limiting per IP
- User BYOK key support
- Org fallback key support
- Comprehensive error logging

See `server.js` for full implementation details.
