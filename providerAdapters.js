// ─────────────────────────────────────────────────────────────────────────────
// providerAdapters.js — shared provider translation layer (v9.14)
//
// Canonical, single copy — imported (not manually mirrored) by BOTH proxy
// runtimes (proxy/server.js on Render, netlify/functions/anthropic-proxy.js
// on Netlify). Per AI_EDITING_RULES.md's no-duplicate-file rule and
// PROJECT_MAP.md's existing warning about these two runtimes drifting apart
// on shared logic (previously about auth; the same risk applies here).
//
// NOTE ON PACKAGING: this file lives outside netlify/functions/. Netlify's
// default JS function bundler (esbuild) traces `require()` calls by
// filesystem path, not by "functions" folder boundary, so a relative
// require from netlify/functions/anthropic-proxy.js up into proxy/ is
// expected to bundle correctly at deploy time — but this has NOT been
// directly confirmed against a live Netlify deploy. Verify on first deploy
// after this ships; if it doesn't bundle, the fallback is a build step that
// copies this file into netlify/functions/ at zip-time (matching the
// no-duplicate-file rule's own suggested resolution), not a hand-maintained
// second copy.
//
// One adapter per provider. Each exposes:
//   buildUpstreamRequest(normalizedBody) -> { url, method, headers, body }
//   normalizeSuccess(rawParsedBody) -> { text, provider, requestedModel,
//     resolvedModel, finishReason, truncated, refused, usage, providerUsageRaw,
//     providerRequestId }
//   normalizeHttpError(rawParsedBody, httpStatus) -> { normalizedErrorCode,
//     retryable, retryAfterMs, safeErrorMessage }
//   normalizeTransportError(err) -> { normalizedErrorCode, retryable, safeErrorMessage }
//
// v9.14.03: Gemini adapter added. The earlier "GA-vs-Beta documentation
// contradiction" that deferred it (Section 8 of multi-llm-provider-spec-
// DRAFT.md) turned out to be a mis-read on direct re-examination of the
// exact quoted passages — not a real inconsistency (one describes product
// maturity, the other describes URL versioning scheme). This module's shape
// did not need to change to add it, as anticipated.
// ─────────────────────────────────────────────────────────────────────────────

// ── Runtime model validation catalog (Section 6.3's fail-fast requirement) ──
// Mirrors scripts/config.js's _spModelsByProvider / scripts/api.js's
// TIER_MODEL_BY_PROVIDER — kept here too since this file runs server-side in
// a Node context that doesn't load the browser scripts. If these ever drift,
// the proxy will fail closed (reject an unrecognized model) rather than
// silently forwarding something the client-side catalog wouldn't have
// offered — a caught drift is safer than an unnoticed one.
const MODEL_CATALOG_BY_PROVIDER = {
  anthropic: new Set(['claude-haiku-4-5', 'claude-sonnet-4-6', 'claude-opus-4-8']),
  // OpenAI model IDs confirmed 2026-07-25 via direct human screenshot of
  // developers.openai.com/api/docs/models — not a search/fetch-tool result;
  // this project caught tool-mediated fabrication on this exact question
  // twice before, so these required a direct human read before shipping.
  //
  // RESIDUAL UNCERTAINTY — this is the fail-fast gate that will actually
  // reject a call if this turns out to be wrong, so it matters most here:
  // the GPT-5.6 family (Sol/Terra/Luna) is independently reported by press
  // as limited-preview to ~20 organizations, not confirmed GA. The docs page
  // shows no access-restriction badge, but "documented" is not the same as
  // "confirmed callable by this org's account" — we have NOT been able to
  // confirm via a successful live API call, blocked on this org's $0 billing
  // balance. If real calls start failing with a permission/model_unavailable
  // error from OpenAI (not from isKnownModel() itself — that only checks the
  // string matches this Set, not real access), this residual uncertainty is
  // the first thing to check, before assuming the model ID string is wrong.
  openai: new Set(['gpt-5.6-luna', 'gpt-5.6-terra', 'gpt-5.6-sol']),
  // Gemini model IDs confirmed via Nethaji's direct raw-documentation paste
  // (ai.google.dev/gemini-api/docs/interactions-overview and
  // /api/interactions-api "Supported models & agents" table) — a stronger
  // source than the search-tool passes used for OpenAI's literals. No
  // premium tier: gemini-3.1-pro-preview is the only Pro-class model and
  // carries "preview" directly in its model ID string.
  gemini: new Set(['gemini-3.5-flash-lite', 'gemini-3.6-flash'])
};

function isKnownModel(provider, model) {
  const set = MODEL_CATALOG_BY_PROVIDER[provider];
  return !!(set && set.has(model));
}

// ── Anthropic adapter (Messages API — unchanged wire format from today) ──
const anthropicAdapter = {
  buildUpstreamRequest(normalizedBody, apiKey) {
    return {
      url: 'https://api.anthropic.com/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: {
        model:      normalizedBody.model,
        max_tokens: normalizedBody.max_tokens,
        system:     normalizedBody.system,
        messages:   normalizedBody.messages
      }
    };
  },

  normalizeSuccess(data) {
    const contentBlock = (data.content && data.content[0]) ? data.content[0] : null;
    const text = contentBlock ? (contentBlock.text || '') : '';
    const stopReason = data.stop_reason || 'unknown';
    const finishReasonMap = { end_turn: 'stop', max_tokens: 'max_tokens', tool_use: 'tool_use', stop_sequence: 'stop' };
    return {
      text,
      provider: 'anthropic',
      requestedModel: null, // filled in by the caller, which knows what was requested
      resolvedModel: data.model || null, // kept separate from requestedModel — dated-alias drift is a known, existing concept for Anthropic
      finishReason: finishReasonMap[stopReason] || 'unknown',
      truncated: stopReason === 'max_tokens',
      refused: false, // Anthropic surfaces refusals as ordinary text content, not a distinct flag
      usage: data.usage ? {
        inputTokens: data.usage.input_tokens != null ? data.usage.input_tokens : null,
        outputTokens: data.usage.output_tokens != null ? data.usage.output_tokens : null,
        totalTokens: (data.usage.input_tokens != null && data.usage.output_tokens != null) ? (data.usage.input_tokens + data.usage.output_tokens) : null,
        cacheReadTokens: data.usage.cache_read_input_tokens != null ? data.usage.cache_read_input_tokens : null
      } : { inputTokens: null, outputTokens: null, totalTokens: null, cacheReadTokens: null },
      providerUsageRaw: data.usage || null,
      providerRequestId: data.id || null
    };
  },

  // httpStatus 403 keeps its existing special-cased message (server.js
  // already handled this distinctly before the adapter layer existed).
  normalizeHttpError(data, httpStatus) {
    if (httpStatus === 403) {
      return {
        normalizedErrorCode: 'permission',
        retryable: false,
        retryAfterMs: null,
        safeErrorMessage: 'Your API key is blocked from server-side access. Check your Anthropic org policy settings, or use a personal API key.'
      };
    }
    const etype = (data && data.error && data.error.type) || '';
    const emsg = (data && data.error && data.error.message) || 'Unknown error';
    const codeMap = {
      authentication_error: 'authentication',
      permission_error: 'permission',
      invalid_request_error: 'invalid_request',
      not_found_error: 'invalid_request',
      rate_limit_error: 'rate_limited',
      overloaded_error: 'overloaded',
      api_error: 'upstream_error'
    };
    const normalizedErrorCode = codeMap[etype] || 'upstream_error';
    const retryable = normalizedErrorCode === 'rate_limited' || normalizedErrorCode === 'overloaded' || httpStatus >= 500;
    return {
      normalizedErrorCode,
      retryable,
      retryAfterMs: null, // Anthropic does not currently document a retry-after body field this proxy parses
      safeErrorMessage: emsg,
      // preserved for existing client-side _pgtAnthropicErrorMessage() prefix
      // logic, which keys off the raw Anthropic error `type` string — not
      // part of the adapter contract's normalized vocabulary, but needed so
      // that function's existing behavior doesn't regress for Anthropic.
      _rawType: etype
    };
  },

  normalizeTransportError(err) {
    const isTimeout = !!(err && err.message && err.message.includes('timeout'));
    return {
      normalizedErrorCode: isTimeout ? 'timeout' : 'network_error',
      retryable: false, // a request that may have already reached Anthropic is not safely retryable — see spec Section 5.5
      safeErrorMessage: isTimeout
        ? 'AI request timed out. The model took too long to respond — please try again.'
        : 'Proxy could not reach Anthropic. Check your network or try again.'
    };
  },

  // v-next (Requirement Agent streaming, opt-in via body.stream — see
  // server.js's _handleStreamingRequest). Anthropic's Messages API SSE
  // format is well-documented and stable: named `event:`/`data:` pairs
  // separated by a blank line. Confidence: HIGH — standard, long-stable
  // wire format, unlike OpenAI/Gemini's adapters below.
  // Takes one raw SSE event block (everything between two blank lines) and
  // returns {delta, usage, done, resolvedModel} — never throws, a malformed/
  // unrecognized event just yields all-null/false so the caller keeps
  // streaming. usage.providerUsageRaw carries the exact upstream usage
  // object (cache tokens etc.) through untouched, same as the non-streaming
  // normalizeSuccess() already does for the buffered path.
  parseSSEEvent(eventBlock) {
    let dataLine = null;
    eventBlock.split('\n').forEach(function(l) {
      if (l.indexOf('data:') === 0) dataLine = l.slice(5).trim();
    });
    if (!dataLine) return { delta: null, usage: null, done: false };
    let data;
    try { data = JSON.parse(dataLine); } catch (e) { return { delta: null, usage: null, done: false }; }
    if (data.type === 'content_block_delta' && data.delta && data.delta.type === 'text_delta') {
      return { delta: data.delta.text || '', usage: null, done: false };
    }
    if (data.type === 'message_start' && data.message) {
      return {
        delta: null,
        usage: data.message.usage ? { inputTokens: data.message.usage.input_tokens != null ? data.message.usage.input_tokens : null, outputTokens: null, totalTokens: null, cacheReadTokens: data.message.usage.cache_read_input_tokens != null ? data.message.usage.cache_read_input_tokens : null, providerUsageRaw: data.message.usage } : null,
        done: false,
        resolvedModel: data.message.model || null
      };
    }
    if (data.type === 'message_delta' && data.usage) {
      return { delta: null, usage: { inputTokens: null, outputTokens: data.usage.output_tokens != null ? data.usage.output_tokens : null, totalTokens: null, cacheReadTokens: data.usage.cache_read_input_tokens != null ? data.usage.cache_read_input_tokens : null, providerUsageRaw: data.usage }, done: false };
    }
    if (data.type === 'message_stop') {
      return { delta: null, usage: null, done: true };
    }
    return { delta: null, usage: null, done: false };
  }
};

// ── OpenAI adapter (Responses API) ──
// Per spec Section 5.3 — [VERIFY — reported via search, not yet directly
// eyeballed] confidence tier. Structured defensively (typed-array filtering,
// never a fixed index) so a wrong field name surfaces as a clear parsing
// error rather than silent misbehavior, per the spec's own requirement.
const openaiAdapter = {
  buildUpstreamRequest(normalizedBody, apiKey) {
    return {
      url: 'https://api.openai.com/v1/responses',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + apiKey
      },
      body: {
        model: normalizedBody.model,
        instructions: normalizedBody.system,
        // CONFIRMED (2026-07-24, developers.openai.com/api/docs/quickstart —
        // quoted official example): input accepts an array of {role, content}
        // items where `content` is a plain string for text-only messages;
        // typed content-part arrays ({type:'input_text', text:'...'}) are
        // only required when mixing modalities (e.g. attaching an image),
        // which this app never does. normalizedBody.messages already matches
        // this shape exactly — no reformatting needed.
        input: normalizedBody.messages,
        max_output_tokens: normalizedBody.max_tokens,
        store: false // this app's calls are stateless single-turn — never rely on account retention default
      }
    };
  },

  normalizeSuccess(data) {
    const outputArr = Array.isArray(data.output) ? data.output : [];
    const messageItem = outputArr.find(function(item) { return item && item.type === 'message'; });
    const textParts = messageItem && Array.isArray(messageItem.content)
      ? messageItem.content.filter(function(c) { return c && c.type === 'output_text'; }).map(function(c) { return c.text || ''; })
      : [];
    const text = textParts.join('');
    const hasReasoningOnly = outputArr.length > 0 && !messageItem;
    return {
      text,
      provider: 'openai',
      requestedModel: null,
      resolvedModel: data.model || null,
      finishReason: data.incomplete_details ? 'max_tokens' : (hasReasoningOnly ? 'unknown' : 'stop'),
      truncated: !!data.incomplete_details,
      refused: !messageItem && !hasReasoningOnly, // no message item and no reasoning-only item either — treat as a refusal-shaped response, not a silent empty string
      usage: data.usage ? {
        inputTokens: data.usage.input_tokens != null ? data.usage.input_tokens : null,
        outputTokens: data.usage.output_tokens != null ? data.usage.output_tokens : null,
        totalTokens: data.usage.total_tokens != null ? data.usage.total_tokens : null,
        cacheReadTokens: (data.usage.input_tokens_details && data.usage.input_tokens_details.cached_tokens != null) ? data.usage.input_tokens_details.cached_tokens : null
      } : { inputTokens: null, outputTokens: null, totalTokens: null, cacheReadTokens: null },
      providerUsageRaw: data.usage || null,
      providerRequestId: data.id || null
    };
  },

  normalizeHttpError(data, httpStatus) {
    const etype = (data && data.error && data.error.type) || '';
    const emsg = (data && data.error && data.error.message) || 'Unknown error';
    let normalizedErrorCode = 'upstream_error';
    if (httpStatus === 401) normalizedErrorCode = 'authentication';
    else if (httpStatus === 403) normalizedErrorCode = 'permission';
    else if (httpStatus === 400 || httpStatus === 404) normalizedErrorCode = 'invalid_request';
    else if (httpStatus === 429) normalizedErrorCode = (etype === 'insufficient_quota') ? 'quota_exhausted' : 'rate_limited';
    else if (httpStatus >= 500) normalizedErrorCode = 'overloaded';
    const retryable = normalizedErrorCode === 'rate_limited' || normalizedErrorCode === 'overloaded';
    return {
      normalizedErrorCode,
      retryable,
      retryAfterMs: null, // [VERIFY] — OpenAI's retry-after header/body field not yet confirmed against live docs
      safeErrorMessage: emsg,
      _rawType: etype
    };
  },

  normalizeTransportError(err) {
    const isTimeout = !!(err && err.message && err.message.includes('timeout'));
    return {
      normalizedErrorCode: isTimeout ? 'timeout' : 'network_error',
      retryable: false,
      safeErrorMessage: isTimeout
        ? 'AI request timed out. The model took too long to respond — please try again.'
        : 'Proxy could not reach OpenAI. Check your network or try again.'
    };
  },

  // v-next (Requirement Agent streaming). [VERIFY] — Responses API SSE event
  // names/shape (response.output_text.delta / response.completed) are based
  // on OpenAI's documented streaming pattern, not directly re-confirmed
  // against live docs the way this file's other OpenAI fields were (see the
  // confidence-tier note above buildUpstreamRequest). Same defensive shape
  // as the Anthropic adapter's parseSSEEvent — an unrecognized event yields
  // all-null/false rather than throwing, so a wrong assumption here degrades
  // to "no visible delta for that event" rather than breaking the stream.
  parseSSEEvent(eventBlock) {
    let dataLine = null;
    eventBlock.split('\n').forEach(function(l) {
      if (l.indexOf('data:') === 0) dataLine = l.slice(5).trim();
    });
    if (!dataLine || dataLine === '[DONE]') return { delta: null, usage: null, done: dataLine === '[DONE]' };
    let data;
    try { data = JSON.parse(dataLine); } catch (e) { return { delta: null, usage: null, done: false }; }
    if (data.type === 'response.output_text.delta' && typeof data.delta === 'string') {
      return { delta: data.delta, usage: null, done: false };
    }
    if (data.type === 'response.completed' && data.response && data.response.usage) {
      const u = data.response.usage;
      return {
        delta: null,
        usage: { inputTokens: u.input_tokens != null ? u.input_tokens : null, outputTokens: u.output_tokens != null ? u.output_tokens : null, totalTokens: u.total_tokens != null ? u.total_tokens : null, cacheReadTokens: (u.input_tokens_details && u.input_tokens_details.cached_tokens != null) ? u.input_tokens_details.cached_tokens : null, providerUsageRaw: u },
        done: true,
        resolvedModel: (data.response && data.response.model) || null
      };
    }
    return { delta: null, usage: null, done: false };
  }
};

// ── Gemini adapter (Interactions API) ──
// Endpoint, system_instruction field, input field, response steps[] shape,
// and usage field names all confirmed via Nethaji's direct raw-documentation
// paste (ai.google.dev/gemini-api/docs/interactions-overview and
// /api/interactions-api) — a stronger source than the search-tool passes
// used elsewhere in this file, per multi-llm-provider-spec-DRAFT.md Section
// 5.3. Auth header (x-goog-api-key) is one tier lower confidence — reached
// via a search/fetch-tool pass, not a direct human paste; the target
// endpoint in that fetch's own example matched the already-confirmed
// /v1beta/interactions path, which is a real consistency signal, but this
// specific field is worth a human glance at ai.google.dev/gemini-api/docs/api-key
// before treating it as fully closed.
//
// Known limitation, not blocking this app's use case (single-turn text
// generation, no multi-turn tool use): the Interactions API does not yet
// support custom safety settings or explicit caching, both available on the
// legacy generateContent API. Flagging here so a future request for custom
// safety thresholds isn't a surprise.
const geminiAdapter = {
  buildUpstreamRequest(normalizedBody, apiKey) {
    return {
      url: 'https://generativelanguage.googleapis.com/v1beta/interactions',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': apiKey
      },
      body: {
        model: normalizedBody.model,
        system_instruction: normalizedBody.system,
        input: normalizedBody.messages, // confirmed polymorphic — accepts Content/array/Step/Turn/string; our {role,content} array shape is valid
        generation_config: { max_output_tokens: normalizedBody.max_tokens },
        store: false // this app's calls are stateless single-turn — never rely on account retention default (55 days paid / 1 day free tier otherwise)
      }
    };
  },

  normalizeSuccess(data) {
    const stepsArr = Array.isArray(data.steps) ? data.steps : [];
    const modelOutputStep = stepsArr.find(function(step) { return step && step.type === 'model_output'; });
    const textParts = modelOutputStep && Array.isArray(modelOutputStep.content)
      ? modelOutputStep.content.filter(function(c) { return c && c.type === 'text'; }).map(function(c) { return c.text || ''; })
      : [];
    const text = textParts.join('');
    const usage = data.usage || null;
    return {
      text,
      provider: 'gemini',
      requestedModel: null,
      resolvedModel: data.model || null, // kept separate from requestedModel — dated-alias drift is a known concept, same as the other two adapters
      finishReason: modelOutputStep ? 'stop' : (stepsArr.length > 0 ? 'unknown' : 'unknown'),
      truncated: false, // [VERIFY] — Gemini's truncation signal field wasn't part of this pass's confirmed content; do not assume a specific field name until checked
      refused: !modelOutputStep && stepsArr.length > 0, // steps exist but none is a model_output step — treat as refusal-shaped, not a silent empty string
      usage: usage ? {
        inputTokens: usage.total_input_tokens != null ? usage.total_input_tokens : null,
        outputTokens: usage.total_output_tokens != null ? usage.total_output_tokens : null,
        totalTokens: usage.total_tokens != null ? usage.total_tokens : null,
        cacheReadTokens: usage.total_cached_tokens != null ? usage.total_cached_tokens : null
      } : { inputTokens: null, outputTokens: null, totalTokens: null, cacheReadTokens: null },
      // Gemini breaks usage down further than the other two providers even
      // for a text-only call (total_cached_tokens, total_thought_tokens,
      // total_tool_use_tokens, and input_tokens_by_modality — an array, not
      // a flat count) — preserved here rather than force-fit into the
      // normalized usage shape above.
      providerUsageRaw: usage,
      providerRequestId: data.id || null
    };
  },

  normalizeHttpError(data, httpStatus) {
    const etype = (data && data.error && data.error.status) || (data && data.error && data.error.type) || '';
    const emsg = (data && data.error && data.error.message) || 'Unknown error';
    let normalizedErrorCode = 'upstream_error';
    if (httpStatus === 401 || httpStatus === 403) normalizedErrorCode = 'permission';
    else if (httpStatus === 400 || httpStatus === 404) normalizedErrorCode = 'invalid_request';
    else if (httpStatus === 429) normalizedErrorCode = 'rate_limited';
    else if (httpStatus >= 500) normalizedErrorCode = 'overloaded';
    const retryable = normalizedErrorCode === 'rate_limited' || normalizedErrorCode === 'overloaded';
    return {
      normalizedErrorCode,
      retryable,
      retryAfterMs: null, // [VERIFY] — Gemini's retry-after field not part of this pass's confirmed content
      safeErrorMessage: emsg,
      _rawType: etype
    };
  },

  normalizeTransportError(err) {
    const isTimeout = !!(err && err.message && err.message.includes('timeout'));
    return {
      normalizedErrorCode: isTimeout ? 'timeout' : 'network_error',
      retryable: false,
      safeErrorMessage: isTimeout
        ? 'AI request timed out. The model took too long to respond — please try again.'
        : 'Proxy could not reach Gemini. Check your network or try again.'
    };
  },

  // v-next (Requirement Agent streaming). [VERIFY] — LOWEST confidence of
  // the three: the Interactions API's streaming event shape was not part of
  // any confirmed-via-direct-paste source used elsewhere in this file (see
  // the non-streaming normalizeSuccess() comment above). Best-effort mirror
  // of the non-streaming steps[]/model_output shape, assuming each SSE event
  // carries one incremental steps[] entry. If this assumption is wrong in
  // practice, the effect is limited and safe: Gemini-provider Requirement
  // Agent turns simply show no incremental deltas (falls back to appearing
  // all at once when the stream ends), never a broken/wrong response —
  // worth a live check against a real Gemini-provider company before
  // treating this as confirmed.
  parseSSEEvent(eventBlock) {
    let dataLine = null;
    eventBlock.split('\n').forEach(function(l) {
      if (l.indexOf('data:') === 0) dataLine = l.slice(5).trim();
    });
    if (!dataLine) return { delta: null, usage: null, done: false };
    let data;
    try { data = JSON.parse(dataLine); } catch (e) { return { delta: null, usage: null, done: false }; }
    const stepsArr = Array.isArray(data.steps) ? data.steps : [];
    const modelOutputStep = stepsArr.find(function(s) { return s && s.type === 'model_output'; });
    const textParts = modelOutputStep && Array.isArray(modelOutputStep.content)
      ? modelOutputStep.content.filter(function(c) { return c && c.type === 'text'; }).map(function(c) { return c.text || ''; })
      : [];
    const delta = textParts.length ? textParts.join('') : null;
    const usage = data.usage ? {
      inputTokens: data.usage.total_input_tokens != null ? data.usage.total_input_tokens : null,
      outputTokens: data.usage.total_output_tokens != null ? data.usage.total_output_tokens : null,
      totalTokens: data.usage.total_tokens != null ? data.usage.total_tokens : null,
      cacheReadTokens: data.usage.total_cached_tokens != null ? data.usage.total_cached_tokens : null,
      providerUsageRaw: data.usage
    } : null;
    return { delta: delta, usage: usage, done: !!data.done, resolvedModel: data.model || null };
  }
};

const adapters = {
  anthropic: anthropicAdapter,
  openai: openaiAdapter,
  gemini: geminiAdapter
};

function getAdapter(provider) {
  return adapters[provider] || null;
}

module.exports = { adapters, getAdapter, isKnownModel, MODEL_CATALOG_BY_PROVIDER };
