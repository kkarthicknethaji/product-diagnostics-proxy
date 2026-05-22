# Product Diagnostics Proxy — Render Deployment Guide

This is the backend proxy for the HCLTech Product Growth Diagnostic Suite.
It sits between the browser app (Netlify) and the Anthropic API, enabling org API keys to work without CORS restrictions.

---

## What this does

```
Browser (productdiagnostics.netlify.app)
    ↓  POST /api/anthropic  (Authorization: Bearer <your-key>)
Render proxy (this service)
    ↓  forwards to Anthropic server-side
Anthropic API
    ↓  response
Browser
```

---

## Deploy to Render — Step by Step

### Step 1 — Sign up / log in
Go to https://render.com and sign in with your Gmail account.

### Step 2 — Create a new Web Service
- Click **+ New** in the top navigation
- Select **Web Service**

### Step 3 — Connect your GitHub repo
- Select **Git Provider** tab
- Connect to GitHub and authorise Render
- Find and select the repo: `kkarthicknethaji/product-diagnostics-proxy`

### Step 4 — Configure the service
Fill in these fields exactly:

| Field | Value |
|---|---|
| **Name** | `product-diagnostics-proxy` |
| **Region** | Singapore (closest to India) or any |
| **Branch** | `main` |
| **Runtime** | Node |
| **Build Command** | `npm install` |
| **Start Command** | `node server.js` |
| **Instance Type** | Free |

Leave all other fields as default.

### Step 5 — Deploy
- Click **Create Web Service**
- Render will install dependencies and start the server
- Wait for the status to show **Live** (takes 2–4 minutes first time)

### Step 6 — Note your URL
Your proxy URL will be:
```
https://product-diagnostics-proxy.onrender.com
```
This is already configured in the app's `api.js`. No further action needed.

### Step 7 — Verify it's working
Open this URL in your browser:
```
https://product-diagnostics-proxy.onrender.com
```
You should see:
```json
{ "status": "ok", "service": "product-diagnostics-proxy", "version": "1.0.0" }
```
If you see that, the proxy is live and ready.

---

## Important — Free tier sleep behaviour

Render's free tier spins down the service after 15 minutes of inactivity.
The **first API call** after inactivity will take 30–60 seconds to respond (cold start).
Subsequent calls are fast. This is normal on the free tier.

For demos: open the health check URL (`/`) in a browser tab 1–2 minutes before you start — this wakes the service.

---

## Updating the proxy

If you need to update `server.js`:
1. Edit the file on GitHub (web UI)
2. Commit the change
3. Render auto-deploys within 1–2 minutes

---

## Environment variables

Phase 2 (current): None required. The user's API key is passed from the browser on every request.

Phase 3 (future): Auth secrets and database URL will be added here via Render's Environment tab.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| First call times out | Cold start (free tier sleep) | Wait 60s, retry |
| CORS error in browser | Request from unknown origin | Check ALLOWED_ORIGINS in server.js |
| "No API key" error | Key not entered in app Settings | Enter key in app → Settings |
| 403 from Anthropic | Org policy blocks the key | Use a personal Anthropic key |
