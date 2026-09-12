// AI Cost Control Tower: OpenAPI Ingestion Layer — /v1/usage-events
// Spec: ai-cost-tower-openapi-ingestion-spec.md v0.11, Sections 5, 6.
//
// Exported as a factory(supabaseAdmin) — see middleware/apiKeyAuth.js's
// header comment for why (no supabaseAdmin export from server.js to avoid
// a require() cycle).

const express = require('express');
const { updateUnitsGenerated } = require('../../lib/costTower/unitsGenerated');
const { buildUsageEventRpcParams } = require('../../lib/costTower/usageEventRpcParams');

const STATUS_VALUES = ['success', 'error', 'timeout'];
const REQUIRED_FIELDS = ['client_call_id', 'user_role_at_call', 'caller', 'requested_model', 'status', 'request_started_at'];
const BATCH_CAP = 500;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// AI Trace Layer — Payload Capture Infrastructure (D.7 bypass invariant).
// Spec: ai-trace-layer-payload-infra-followup-spec-v0.7.md, §4.1a.
//
// provider_usage_raw exists to carry a provider's raw token/cache-usage
// response, persisted opaquely (no downstream key ever unpacked from it —
// see usageEventRpcParams.js / the SQL RPC). Without this allowlist, an
// external caller of this route could put arbitrary content — including
// full prompt/response text — inside this JSONB blob and it would persist
// exactly as submitted, bypassing the invariant that model-visible content
// only ever enters through the payload-gated /v1/trace-payloads route
// (built v9.33.02, tracePayloads.js). Scope note (code-review fix): this only
// instruments this external route's own caller-controlled input — it does
// NOT validate proxy/server.js's internal _insertAiUsageEvent() path, which
// writes provider_usage_raw from this proxy's own trusted provider-adapter
// responses (never a caller's JSON body), so was never the bypass this
// allowlist closes.
//
// Each provider's table is traced to that provider's own adapter in
// proxy/providerAdapters.js, not to provider documentation — see the spec
// for the exact citation per key. cache_creation_input_tokens/service_tier
// (Anthropic) are real, documented Anthropic fields included proactively,
// not currently read by this codebase. Gemini's input_tokens_by_modality
// is the one field in this table without a bounded element-type check —
// its shape isn't confirmed anywhere in live code — accepted as any array,
// controlled only by the total-size backstop below (an explicit, one-off
// exception, not a precedent for future uncertain fields).
const PROVIDER_USAGE_RAW_MAX_BYTES = 2048;
const PROVIDER_USAGE_RAW_ALLOWLISTS = {
  anthropic: {
    input_tokens: { type: 'integer' },
    output_tokens: { type: 'integer' },
    cache_read_input_tokens: { type: 'integer' },
    cache_creation_input_tokens: { type: 'integer' },
    service_tier: { type: 'string', maxLength: 32, pattern: /^[a-z_]+$/ },
    cache_creation: {
      type: 'object',
      nestedKeys: {
        ephemeral_5m_input_tokens: { type: 'integer' },
        ephemeral_1h_input_tokens: { type: 'integer' }
      }
    }
  },
  openai: {
    input_tokens: { type: 'integer' },
    output_tokens: { type: 'integer' },
    total_tokens: { type: 'integer' },
    input_tokens_details: { type: 'object', nestedKeys: { cached_tokens: { type: 'integer' } } }
  },
  gemini: {
    total_input_tokens: { type: 'integer' },
    total_output_tokens: { type: 'integer' },
    total_tokens: { type: 'integer' },
    total_cached_tokens: { type: 'integer' },
    total_thought_tokens: { type: 'integer' },
    total_tool_use_tokens: { type: 'integer' },
    // [VERIFY] element shape not confirmed against live Gemini docs/traffic —
    // accept any array, per Nethaji's explicit decision (spec §0.0c).
    input_tokens_by_modality: { type: 'array' }
  }
};

// Code-review fix: a plain `obj[key]` lookup on a caller-controlled string
// resolves inherited Object.prototype members (e.g. key === 'constructor' or
// '__proto__') instead of undefined for any key this codebase never defined
// on that object — which silently defeats every `if (!rule)`
// unrecognized-key rejection below and, once resolved to a function like
// `Object.prototype.constructor`, crashes the process when its own
// (nonexistent) `.nestedKeys` is indexed into further down. Confirmed live:
// `provider_usage_raw: {"constructor": {"prompt": "..."}}` threw an
// uncaught TypeError all the way out of this async route handler, and
// `{"constructor": {}}` (empty) was silently accepted despite not being an
// allowed key. `_ownGet` restores the intended "only a key this table
// actually defines" semantics.
function _ownGet(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
}

function _validateProviderUsageRawValue(value, rule, path) {
  if (rule.type === 'integer') {
    return Number.isInteger(value) ? null : path + ' must be an integer.';
  }
  if (rule.type === 'string') {
    if (typeof value !== 'string') return path + ' must be a string.';
    if (rule.maxLength != null && value.length > rule.maxLength) return path + ' exceeds the maximum length of ' + rule.maxLength + '.';
    if (rule.pattern && !rule.pattern.test(value)) return path + ' has an invalid format.';
    return null;
  }
  if (rule.type === 'array') {
    return Array.isArray(value) ? null : path + ' must be an array.';
  }
  // rule.type === 'object' — the only remaining case in the tables above.
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return path + ' must be an object.';
  }
  for (const nestedKey of Object.keys(value)) {
    const nestedRule = _ownGet(rule.nestedKeys, nestedKey);
    if (!nestedRule) return path + ' contains an unrecognized key: ' + nestedKey;
    const nestedError = _validateProviderUsageRawValue(value[nestedKey], nestedRule, path + '.' + nestedKey);
    if (nestedError) return nestedError;
  }
  return null;
}

// Reject, not strip — an item with any key outside its provider's table,
// any wrong-typed value, any oversized string, any excess nesting, or an
// oversized total payload fails the whole item with a clear message,
// exactly like a missing required field already does. Unrecognized/omitted
// provider falls back to Anthropic's table (today's existing default is
// `item.provider || 'anthropic'`, unchanged by this fix).
function _validateProviderUsageRaw(providerUsageRaw, provider) {
  if (providerUsageRaw == null) return null;
  if (typeof providerUsageRaw !== 'object' || Array.isArray(providerUsageRaw)) {
    return 'provider_usage_raw must be an object.';
  }

  let serialized;
  try { serialized = JSON.stringify(providerUsageRaw); } catch (e) { return 'provider_usage_raw could not be serialized.'; }
  if (Buffer.byteLength(serialized, 'utf8') > PROVIDER_USAGE_RAW_MAX_BYTES) {
    return 'provider_usage_raw exceeds the maximum size of ' + PROVIDER_USAGE_RAW_MAX_BYTES + ' bytes.';
  }

  // Normalized (lowercased/trimmed) for table selection only — matches this
  // codebase's own established convention (providerAdapters.js's `adapters`
  // map keys are always lowercase 'anthropic'/'openai'/'gemini'); the raw
  // `provider` value is still what's stored/sent to the RPC, unchanged.
  const normalizedProvider = typeof provider === 'string' ? provider.trim().toLowerCase() : provider;
  const allowlist = _ownGet(PROVIDER_USAGE_RAW_ALLOWLISTS, normalizedProvider) || PROVIDER_USAGE_RAW_ALLOWLISTS.anthropic;
  for (const key of Object.keys(providerUsageRaw)) {
    const rule = _ownGet(allowlist, key);
    if (!rule) {
      return 'provider_usage_raw contains an unrecognized key for provider \'' + provider + '\': ' + key;
    }
    const error = _validateProviderUsageRawValue(providerUsageRaw[key], rule, 'provider_usage_raw.' + key);
    if (error) return error;
  }
  return null;
}

function _validateItem(item) {
  if (!item || typeof item !== 'object' || Array.isArray(item)) {
    return 'Item must be an object.';
  }
  for (const field of REQUIRED_FIELDS) {
    if (item[field] === undefined || item[field] === null || item[field] === '') {
      return 'Missing required field: ' + field;
    }
  }
  if (STATUS_VALUES.indexOf(item.status) === -1) {
    return 'status must be one of: ' + STATUS_VALUES.join(', ');
  }
  if (Number.isNaN(Date.parse(item.request_started_at))) {
    return 'request_started_at must be a valid ISO 8601 timestamp.';
  }
  // Validated here, not left for the DB to reject, because the batch
  // ownership pre-fetch (_fetchOwnedOutcomeIds) runs ONE .in() query across
  // every item's outcome_id — a single malformed value would fail that
  // whole query (invalid input syntax for type uuid), incorrectly marking
  // every OTHER item's legitimate outcome_id as unowned too. Catching the
  // bad shape per-item before it ever reaches that shared query keeps one
  // caller mistake from collaterally rejecting the rest of the batch.
  if (item.outcome_id != null && !UUID_RE.test(String(item.outcome_id))) {
    return 'outcome_id must be a valid UUID.';
  }
  // AI Trace Layer — client_trace_id is the only trace-continuation key
  // (spec Invariant 2); agent_name is required whenever it's present, same
  // rule the RPC itself enforces (mt_ai_record_usage_event_with_span raises
  // ERRCODE 22023 otherwise) — checked here too so a caller gets a clean 400
  // instead of a database-level error surfacing as a 500.
  if (item.client_trace_id != null && (item.agent_name == null || item.agent_name === '')) {
    return 'agent_name is required when client_trace_id is present.';
  }
  const providerUsageRawError = _validateProviderUsageRaw(item.provider_usage_raw, item.provider || 'anthropic');
  if (providerUsageRawError) return providerUsageRawError;
  return null;
}

// last_activity_at auto-bump (Section 5) — ownership already verified by
// the caller before this runs (see _fetchOwnedOutcomeIds), so this is a
// plain scoped update, not a re-check. Fire-and-forget, never awaited by
// the request path — same discipline as apiKeyAuth.js's
// _touchCredentialLastUsedOpportunistic for the identical "just a
// timestamp, best-effort" shape of write. A mismatched outcome_id was
// already rejected earlier in the request, so silent failure here only
// ever means a genuine best-effort miss, never a masked ownership gap.
function _bumpOutcomeActivity(supabaseAdmin, companyId, appId, outcomeId) {
  supabaseAdmin
    .from('mt_outcomes')
    .update({ last_activity_at: new Date().toISOString() })
    .eq('outcome_id', outcomeId)
    .eq('company_id', companyId)
    .eq('app_id', appId)
    .then(function (result) {
      if (result && result.error) console.error('[V1 USAGE-EVENTS] last_activity_at bump failed:', result.error.message);
    }, function (e) {
      console.error('[V1 USAGE-EVENTS] last_activity_at bump exception:', e.message);
    });
}

// Bounded-concurrency map — a batch of up to BATCH_CAP items each doing
// independent DB round trips (findings: code review, batch efficiency)
// must not run fully sequentially (up to 500x latency for no correctness
// reason, per this file's own "independent records, not a transaction"
// comment below) nor fully unbounded (500 simultaneous connections would
// overwhelm Supabase's pooler). limit caps how many items are ever
// in-flight at once; order of the returned array always matches input order
// regardless of which item resolves first.
async function _mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  }
  const workers = [];
  for (let w = 0; w < Math.min(limit, items.length); w++) workers.push(worker());
  await Promise.all(workers);
  return results;
}

// One query for every distinct outcome_id referenced anywhere in the
// batch, instead of one ownership-check query per item — a batch where
// many items share a single outcome_id (a realistic pattern: many usage
// events tied to one tracked outcome) previously re-ran the identical
// SELECT once per item instead of once per distinct id.
async function _fetchOwnedOutcomeIds(supabaseAdmin, companyId, appId, outcomeIds) {
  if (outcomeIds.length === 0) return new Set();
  const { data, error } = await supabaseAdmin
    .from('mt_outcomes')
    .select('outcome_id')
    .eq('company_id', companyId)
    .eq('app_id', appId)
    .in('outcome_id', outcomeIds);
  if (error) {
    console.error('[V1 USAGE-EVENTS] outcome ownership check failed:', error.message);
    return new Set(); // fail closed — every outcome_id in this batch is treated as unowned
  }
  return new Set((data || []).map(function (r) { return r.outcome_id; }));
}

// ownedOutcomeIds is pre-fetched once per batch (see _fetchOwnedOutcomeIds)
// rather than re-checked per item — without this check at all, a
// caller-supplied outcome_id from a DIFFERENT (company_id, app_id) would
// still satisfy the plain FK on mt_ai_usage_events.outcome_id (existence
// only, not ownership) and persist a permanent cross-tenant reference.
// Mirrors the same ownership guarantee PATCH /v1/outcomes/{id} enforces.
//
// AI Trace Layer — this now calls mt_ai_record_usage_event_with_span()
// instead of a direct table insert, so this route and Product Studio's own
// /api/anthropic path share exactly one place a usage event (and its
// optional span/trace) is ever written. session_type/prompt_version/
// settings_model have no equivalent concept for an external caller — this
// route never accepted them before either, so they're passed as null,
// same as they were simply absent from _buildRow()'s old row shape.
async function _processItem(supabaseAdmin, item, companyId, appId, ownedOutcomeIds) {
  const validationError = _validateItem(item);
  if (validationError) {
    return { error: { type: 'invalid_request', message: validationError } };
  }

  if (item.outcome_id != null && !ownedOutcomeIds.has(item.outcome_id)) {
    return { error: { type: 'invalid_request', message: 'outcome_id does not exist or does not belong to this credential.' } };
  }

  // Normalize this item's own field names/defaults into the shared shape
  // buildUsageEventRpcParams() expects, then let it own the field->p_*
  // mapping — code-review fix, closing the drift risk between this and
  // server.js's independent copy of the same ~34-key mapping (this RPC's
  // parameter list already went out of sync with calling code once, see
  // ai-cost-tower-trace-layer-migration.sql's Step 4 reconciliation note).
  const { data, error } = await supabaseAdmin.rpc('mt_ai_record_usage_event_with_span', buildUsageEventRpcParams({
    company_id: companyId,
    app_id: appId,
    client_call_id: item.client_call_id,
    provider: item.provider || 'anthropic',
    product_id: item.product_id != null ? item.product_id : null,
    session_id: item.session_id != null ? item.session_id : null,
    session_type: null,
    user_id: item.user_id != null ? item.user_id : null,
    user_role_at_call: item.user_role_at_call,
    caller: item.caller,
    prompt_version: null,
    requested_model: item.requested_model,
    response_model: item.response_model != null ? item.response_model : null,
    // settings_mode/selection_rule default to 'external' when omitted — this
    // route is the consumer-tier ingestion surface, never Product Studio's
    // own /api/anthropic path, so defaulting unconditionally (rather than
    // conditioning on appId !== 'product-studio') matches every real caller
    // this endpoint will ever see.
    settings_mode: item.settings_mode || 'external',
    settings_model: null,
    selection_rule: item.selection_rule || 'external',
    input_tokens: item.input_tokens != null ? item.input_tokens : null,
    output_tokens: item.output_tokens != null ? item.output_tokens : null,
    cache_creation_5m_tokens: item.cache_creation_5m_tokens != null ? item.cache_creation_5m_tokens : null,
    cache_creation_1h_tokens: item.cache_creation_1h_tokens != null ? item.cache_creation_1h_tokens : null,
    cache_read_tokens: item.cache_read_tokens != null ? item.cache_read_tokens : null,
    provider_usage_raw: item.provider_usage_raw != null ? item.provider_usage_raw : null,
    status: item.status,
    provider_http_status: item.provider_http_status != null ? item.provider_http_status : null,
    error_type: item.error_type != null ? item.error_type : null,
    failure_phase: item.failure_phase != null ? item.failure_phase : null,
    request_started_at: item.request_started_at,
    duration_ms: item.duration_ms != null ? item.duration_ms : null,
    request_bytes: item.request_bytes != null ? item.request_bytes : null,
    response_bytes: item.response_bytes != null ? item.response_bytes : null,
    outcome_id: item.outcome_id != null ? item.outcome_id : null,
    units_generated: item.units_generated != null ? item.units_generated : null,
    client_trace_id: item.client_trace_id != null ? item.client_trace_id : null,
    agent_name: item.agent_name != null ? item.agent_name : null
  }));

  if (error) {
    // 23514 = check_violation, raised by the RPC itself for a replayed
    // client_call_id/client_trace_id with different identity fields — a
    // genuine integration bug on the caller's side, mapped to 409 per spec
    // Part D.4 (distinct from Product Studio's own internal wrapper, which
    // must swallow this same exception rather than surface it to an end user).
    if (error.code === '23514') {
      return { error: { type: 'conflict', message: error.message } };
    }
    // 23503 = foreign_key_violation — same translation outcomes.js already
    // does for its own FK (e.g. a bad outcome_type_id); without this, a
    // permanent client input error (a stale/bad reference) surfaced as an
    // undifferentiated 500 instead of a 400.
    if (error.code === '23503') {
      return { error: { type: 'invalid_request', message: 'One of the referenced ids (e.g. outcome_id) does not exist.' } };
    }
    console.error('[V1 USAGE-EVENTS] rpc failed:', error.message);
    return { error: { type: 'server_error', message: 'Could not record usage event.' } };
  }

  const row = data[0];
  return { id: row.usage_event_id, deduplicated: row.was_duplicate, outcomeId: item.outcome_id != null ? item.outcome_id : null };
}

module.exports = function usageEventsRouterFactory(supabaseAdmin) {
  const router = express.Router();

  // POST /v1/usage-events — single object or array (Section 6).
  router.post('/usage-events', async function (req, res) {
    const body = req.body;

    if (body === undefined || body === null || (typeof body !== 'object')) {
      return res.status(400).json({ error: { type: 'invalid_request', message: 'Request body must be a JSON object or array.' } });
    }

    const isBatch = Array.isArray(body);
    const items = isBatch ? body : [body];

    if (isBatch && items.length > BATCH_CAP) {
      return res.status(400).json({ error: { type: 'invalid_request', message: 'Batch exceeds the maximum of ' + BATCH_CAP + ' items.' } });
    }
    if (isBatch && items.length === 0) {
      return res.status(400).json({ error: { type: 'invalid_request', message: 'Batch must contain at least one item.' } });
    }

    // One ownership check for every distinct outcome_id in the whole batch,
    // not one per item — a batch where many items share a single outcome_id
    // (a realistic pattern) previously re-ran the identical query per item.
    // Only syntactically-valid UUIDs are collected here (matches
    // _validateItem's own check) — a malformed value is rejected per-item
    // before it ever reaches this shared query, which would otherwise fail
    // as a whole and mark every other item's legitimate outcome_id unowned.
    const distinctOutcomeIds = Array.from(new Set(
      items.filter(function (it) { return it && it.outcome_id != null && UUID_RE.test(String(it.outcome_id)); }).map(function (it) { return it.outcome_id; })
    ));
    const ownedOutcomeIds = await _fetchOwnedOutcomeIds(supabaseAdmin, req.companyId, req.appId, distinctOutcomeIds);

    // A single malformed item never discards the rest of the batch — these
    // are independent cost/telemetry records, not a transaction (Section 6
    // batch semantics), so there is no correctness reason to process them
    // one at a time: bounded concurrency turns up to BATCH_CAP sequential
    // round-trip chains into a small, fixed number of concurrent ones.
    // `index` (not resolution order) is what maps a result back to its
    // request position, so out-of-order completion is never observable.
    const outcomes = await _mapWithConcurrency(items, 20, function (item) {
      return _processItem(supabaseAdmin, item, req.companyId, req.appId, ownedOutcomeIds);
    });
    const results = outcomes.map(function (outcome, i) {
      return outcome.error ? { index: i, error: outcome.error } : { index: i, id: outcome.id, deduplicated: outcome.deduplicated };
    });

    // Bump once per distinct outcome_id actually written, not once per
    // item — fires on both a fresh insert and a deduplicated replay (a
    // retried call carrying outcome_id shouldn't lose the bump just
    // because it was a duplicate delivery), fire-and-forget so it never
    // adds to this response's latency.
    const outcomeIdsToBump = new Set(outcomes.filter(function (o) { return !o.error && o.outcomeId; }).map(function (o) { return o.outcomeId; }));
    outcomeIdsToBump.forEach(function (outcomeId) {
      _bumpOutcomeActivity(supabaseAdmin, req.companyId, req.appId, outcomeId);
    });

    if (!isBatch) {
      const only = results[0];
      if (only.error) {
        // AI Trace Layer — 'conflict' is a new error type _processItem() can
        // now return (a replayed client_call_id/client_trace_id with
        // different identity fields); map it to 409, per spec Part D.4,
        // rather than the flat 400 every error type got before this existed.
        const _statusByType = { invalid_request: 400, conflict: 409, server_error: 500 };
        return res.status(_statusByType[only.error.type] || 400).json({ error: only.error });
      }
      return res.status(200).json({ id: only.id, deduplicated: only.deduplicated });
    }

    return res.status(200).json({ results: results });
  });

  // PATCH /v1/usage-events/{client_call_id}/units-generated — idempotent,
  // scoped to (company_id, app_id, client_call_id).
  router.patch('/usage-events/:client_call_id/units-generated', async function (req, res) {
    const unitsGenerated = req.body ? req.body.units_generated : undefined;
    if (typeof unitsGenerated !== 'number' || !Number.isInteger(unitsGenerated) || unitsGenerated < 0) {
      return res.status(400).json({ error: { type: 'invalid_request', message: 'units_generated must be an integer >= 0.' } });
    }

    const { data, error } = await updateUnitsGenerated(supabaseAdmin, {
      companyId: req.companyId,
      appId: req.appId,
      clientCallId: req.params.client_call_id,
      unitsGenerated: unitsGenerated
    });

    if (error) {
      console.error('[V1 USAGE-EVENTS] units-generated update failed:', error.message);
      return res.status(500).json({ error: { type: 'server_error', message: 'Could not update units_generated.' } });
    }
    if (!data) {
      return res.status(404).json({ error: { type: 'not_found', message: 'No usage event found for this client_call_id.' } });
    }

    return res.status(200).json({ id: data.id, units_generated: unitsGenerated });
  });

  // GET /v1/usage-events — reconciliation read-back, not a dashboard
  // replacement. Direct query, never mt_ai_cost_events_list (finding #5 —
  // that RPC's auth check assumes a human Supabase Auth session).
  router.get('/usage-events', async function (req, res) {
    const start = req.query.start;
    const end = req.query.end;
    if (!start || Number.isNaN(Date.parse(start)) || !end || Number.isNaN(Date.parse(end))) {
      return res.status(400).json({ error: { type: 'invalid_request', message: 'start and end are required, valid ISO 8601 timestamps.' } });
    }

    let limit = parseInt(req.query.limit, 10);
    if (Number.isNaN(limit)) limit = 200;
    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;

    // cursor: opaque to the caller, a base64-encoded JSON [request_started_at, id]
    // tuple of the last row in the prior page — keyset pagination, not offset,
    // so it stays stable and performant as new events are written concurrently.
    let cursorTimestamp = null;
    let cursorId = null;
    if (req.query.cursor) {
      try {
        const decoded = JSON.parse(Buffer.from(String(req.query.cursor), 'base64').toString('utf8'));
        if (!Array.isArray(decoded) || decoded.length !== 2 || Number.isNaN(Date.parse(decoded[0]))) throw new Error('shape');
        // Re-serialize through Date rather than trusting the decoded string
        // verbatim, and restrict cursorId to a safe charset — both values
        // get spliced into a raw PostgREST filter string below, and neither
        // was previously validated for filter metacharacters (comma/parens),
        // which Date.parse's own lenient formats (e.g. its own toString())
        // can contain.
        if (!/^[a-zA-Z0-9-]+$/.test(String(decoded[1]))) throw new Error('id');
        cursorTimestamp = new Date(decoded[0]).toISOString();
        cursorId = decoded[1];
      } catch (e) {
        return res.status(400).json({ error: { type: 'invalid_request', message: 'Malformed cursor.' } });
      }
    }

    let query = supabaseAdmin
      .from('mt_ai_usage_events')
      .select('id, request_started_at, provider, requested_model, response_model, caller, session_id, user_id, user_role_at_call, status, error_type, failure_phase, duration_ms, request_bytes, response_bytes, input_tokens, output_tokens, cache_creation_5m_tokens, cache_creation_1h_tokens, cache_read_tokens, outcome_id, units_generated, trace_id')
      .eq('company_id', req.companyId)
      .eq('app_id', req.appId)
      .gte('request_started_at', start)
      .lt('request_started_at', end)
      .order('request_started_at', { ascending: false })
      .order('id', { ascending: false })
      .limit(limit);

    if (cursorTimestamp) {
      query = query.or('request_started_at.lt.' + cursorTimestamp + ',and(request_started_at.eq.' + cursorTimestamp + ',id.lt.' + cursorId + ')');
    }

    const { data: events, error } = await query;
    if (error) {
      console.error('[V1 USAGE-EVENTS] read failed:', error.message);
      return res.status(500).json({ error: { type: 'server_error', message: 'Could not read usage events.' } });
    }

    // calculated_cost is application-computed here, not via the RPC's own
    // formula call site — same pricing-table shape and range-match logic
    // as mt_ai_cost_events_list (sql/ai-cost-tower-outcomes-v2-migration.sql),
    // deliberately not reused directly since that RPC's own auth check is
    // the human-session dependency this endpoint exists to avoid.
    const pairs = Array.from(new Set(events.map(function (e) { return e.provider + ' ' + (e.response_model || e.requested_model); })));
    let pricingRows = [];
    if (pairs.length > 0) {
      const providers = Array.from(new Set(events.map(function (e) { return e.provider; })));
      const { data: pricing, error: pricingError } = await supabaseAdmin
        .from('mt_model_pricing')
        .select('provider, model_name, effective_from, effective_to, tier, input_price_per_mtok, output_price_per_mtok, cache_write_5m_price_per_mtok, cache_write_1h_price_per_mtok, cache_read_price_per_mtok')
        .in('provider', providers);
      if (pricingError) {
        console.error('[V1 USAGE-EVENTS] pricing lookup failed:', pricingError.message);
      } else {
        pricingRows = pricing || [];
      }
    }

    function _findPricing(event) {
      const modelName = event.response_model || event.requested_model;
      const at = new Date(event.request_started_at).getTime();
      return pricingRows.find(function (p) {
        if (p.provider !== event.provider || p.model_name !== modelName) return false;
        const from = new Date(p.effective_from).getTime();
        const to = p.effective_to ? new Date(p.effective_to).getTime() : null;
        return at >= from && (to === null || at < to);
      }) || null;
    }

    const enriched = events.map(function (e) {
      const pricing = _findPricing(e);
      let calculatedCost = null;
      if (pricing) {
        calculatedCost =
          ((e.input_tokens || 0) / 1000000) * pricing.input_price_per_mtok +
          ((e.output_tokens || 0) / 1000000) * pricing.output_price_per_mtok +
          ((e.cache_creation_5m_tokens || 0) / 1000000) * pricing.cache_write_5m_price_per_mtok +
          ((e.cache_creation_1h_tokens || 0) / 1000000) * pricing.cache_write_1h_price_per_mtok +
          ((e.cache_read_tokens || 0) / 1000000) * pricing.cache_read_price_per_mtok;
      }
      return Object.assign({}, e, { calculated_cost: calculatedCost });
    });

    let nextCursor = null;
    if (events.length === limit) {
      const last = events[events.length - 1];
      nextCursor = Buffer.from(JSON.stringify([last.request_started_at, last.id])).toString('base64');
    }

    return res.status(200).json({ events: enriched, next_cursor: nextCursor });
  });

  return router;
};
