// AI Cost Control Tower: AI Trace Layer — /v1/traces
// Spec: ai-trace-layer-spec-v0.11-final.md, Parts D.1, D.2, D.3.
//
// POST /v1/traces exists for an external app that wants to create a trace
// explicitly, ahead of its first usage-event submission — it is not the
// only way a trace comes into existence; POST /v1/usage-events creates one
// implicitly via mt_ai_record_usage_event_with_span() whenever a caller
// supplies client_trace_id without having called this endpoint first.

const express = require('express');
const { insertIdempotentStrict } = require('../../lib/costTower/idempotencyStrict');

const REQUIRED_FIELDS = ['agent_name', 'client_trace_id']; // session_id intentionally not required —
                                                             // an external app with no session concept
                                                             // should not be forced to invent one

module.exports = function tracesRouterFactory(supabaseAdmin) {
  const router = express.Router();

  // POST /v1/traces
  router.post('/traces', async function (req, res) {
    const body = req.body || {};
    for (const field of REQUIRED_FIELDS) {
      if (body[field] === undefined || body[field] === null || body[field] === '') {
        return res.status(400).json({ error: { type: 'invalid_request', message: 'Missing required field: ' + field } });
      }
    }

    // outcome_id ownership check — mt_ai_traces.outcome_id is only a plain
    // existence FK (not tenant-scoped), so without this a caller could
    // attach another company/app's outcome_id and persist a permanent
    // cross-tenant reference. Mirrors usageEvents.js's _fetchOwnedOutcomeIds.
    if (body.outcome_id != null) {
      const { data: owned, error: ownedError } = await supabaseAdmin
        .from('mt_outcomes')
        .select('outcome_id')
        .eq('outcome_id', body.outcome_id)
        .eq('company_id', req.companyId)
        .eq('app_id', req.appId)
        .maybeSingle();
      if (ownedError) {
        console.error('[V1 TRACES] outcome ownership check failed:', ownedError.message);
        return res.status(500).json({ error: { type: 'server_error', message: 'Could not create trace.' } });
      }
      if (!owned) {
        return res.status(400).json({ error: { type: 'invalid_request', message: 'outcome_id does not exist or does not belong to this credential.' } });
      }
    }

    const row = {
      company_id: req.companyId, app_id: req.appId,
      agent_name: body.agent_name, client_trace_id: body.client_trace_id,
      session_id: body.session_id != null ? body.session_id : null,
      product_id: body.product_id != null ? body.product_id : null,
      outcome_id: body.outcome_id != null ? body.outcome_id : null
    };

    const result = await insertIdempotentStrict(supabaseAdmin, {
      table: 'mt_ai_traces',
      conflictColumns: ['company_id', 'app_id', 'client_trace_id'],
      row: row, idColumn: 'trace_id',
      compareColumns: ['agent_name', 'session_id']
    });

    if (result.error) {
      if (result.error.code === 'IDEMPOTENCY_CONFLICT') {
        return res.status(409).json({ error: { type: 'conflict', message: result.error.message } });
      }
      // 23503 = foreign_key_violation — e.g. a bad outcome_id — same
      // translation the sibling outcomes.js/usageEvents.js routes already do.
      if (result.error.code === '23503') {
        return res.status(400).json({ error: { type: 'invalid_request', message: 'One of the referenced ids (e.g. outcome_id) does not exist.' } });
      }
      console.error('[V1 TRACES] insert failed:', result.error.message);
      return res.status(500).json({ error: { type: 'server_error', message: 'Could not create trace.' } });
    }

    return res.status(200).json({ trace_id: result.id, deduplicated: result.deduplicated });
  });

  // PATCH /v1/traces/{id} — sets completed_at only. No execution_result
  // field exists in this version's schema at all (spec Part B.1). Ownership-
  // scoped by (company_id, app_id), same discipline as PATCH /v1/outcomes/{id}.
  router.patch('/traces/:id', async function (req, res) {
    const completedAt = new Date().toISOString();
    const { data, error } = await supabaseAdmin
      .from('mt_ai_traces')
      .update({ completed_at: completedAt })
      .eq('trace_id', req.params.id)
      .eq('company_id', req.companyId)
      .eq('app_id', req.appId)
      .select('trace_id')
      .maybeSingle();

    if (error) {
      console.error('[V1 TRACES] completion failed:', error.message);
      return res.status(500).json({ error: { type: 'server_error', message: 'Could not update trace.' } });
    }
    if (!data) {
      return res.status(404).json({ error: { type: 'not_found', message: 'Trace not found.' } });
    }

    return res.status(200).json({ trace_id: data.trace_id, completed_at: completedAt });
  });

  // GET /v1/traces/{id} — ownership-scoped by (company_id, app_id).
  router.get('/traces/:id', async function (req, res) {
    const { data, error } = await supabaseAdmin
      .from('mt_ai_traces')
      .select('trace_id, agent_name, session_id, product_id, outcome_id, started_at, completed_at')
      .eq('trace_id', req.params.id)
      .eq('company_id', req.companyId)
      .eq('app_id', req.appId)
      .maybeSingle();

    if (error) {
      console.error('[V1 TRACES] read failed:', error.message);
      return res.status(500).json({ error: { type: 'server_error', message: 'Could not read trace.' } });
    }
    if (!data) {
      return res.status(404).json({ error: { type: 'not_found', message: 'Trace not found.' } });
    }

    return res.status(200).json(data);
  });

  // GET /v1/traces/{id}/spans — every span in sequence_order, embedding its
  // mt_ai_usage_events row (PostgREST foreign-table embed via the real FK on
  // usage_event_id) for cost/token/model/duration fields — null for a
  // tool_call span, which has no usage event. Ownership checked against the
  // trace itself FIRST, so a trace this credential doesn't own returns a
  // plain 404 rather than leaking whether it exists via its spans.
  router.get('/traces/:id/spans', async function (req, res) {
    const { data: trace, error: traceError } = await supabaseAdmin
      .from('mt_ai_traces')
      .select('trace_id')
      .eq('trace_id', req.params.id)
      .eq('company_id', req.companyId)
      .eq('app_id', req.appId)
      .maybeSingle();

    if (traceError) {
      console.error('[V1 TRACES] spans ownership check failed:', traceError.message);
      return res.status(500).json({ error: { type: 'server_error', message: 'Could not read trace spans.' } });
    }
    if (!trace) {
      return res.status(404).json({ error: { type: 'not_found', message: 'Trace not found.' } });
    }

    const { data: spans, error } = await supabaseAdmin
      .from('mt_ai_spans')
      .select('span_id, parent_span_id, span_type, tool_name, sequence_order, attempt_number, status, started_at, completed_at, duration_ms, mt_ai_usage_events(requested_model, response_model, provider, input_tokens, output_tokens, duration_ms)')
      .eq('trace_id', req.params.id)
      .order('sequence_order', { ascending: true });

    if (error) {
      console.error('[V1 TRACES] spans read failed:', error.message);
      return res.status(500).json({ error: { type: 'server_error', message: 'Could not read trace spans.' } });
    }

    return res.status(200).json({ spans: spans || [] });
  });

  return router;
};
