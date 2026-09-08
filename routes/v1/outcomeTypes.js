// AI Cost Control Tower: OpenAPI Ingestion Layer — /v1/outcome-types
// Spec: ai-cost-tower-openapi-ingestion-spec.md v0.11, Section 6.

const express = require('express');

const REQUIRED_FIELDS = ['outcome_type_id', 'name', 'description', 'canvas', 'costing_method', 'unit_label'];
const COSTING_METHODS = ['session_sum', 'yield_ratio'];

module.exports = function outcomeTypesRouterFactory(supabaseAdmin) {
  const router = express.Router();

  // POST /v1/outcome-types — idempotent upsert. "Idempotent" only means
  // safe to resubmit IDENTICAL values (Section 6): a re-registration of an
  // existing outcome_type_id with a different costing_method or unit_label
  // is rejected with 409, not silently applied — changing either after
  // outcomes already exist under the old semantics would corrupt historical
  // cost interpretation with no warning (finding #26).
  router.post('/outcome-types', async function (req, res) {
    const body = req.body || {};
    for (const field of REQUIRED_FIELDS) {
      if (body[field] === undefined || body[field] === null || body[field] === '') {
        return res.status(400).json({ error: { type: 'invalid_request', message: 'Missing required field: ' + field } });
      }
    }
    if (COSTING_METHODS.indexOf(body.costing_method) === -1) {
      return res.status(400).json({ error: { type: 'invalid_request', message: 'costing_method must be one of: ' + COSTING_METHODS.join(', ') } });
    }

    // company_id has no bearing on the underlying (app_id, outcome_type_id)
    // primary key (see the fix migration's own comment for why that can't
    // safely change), so a row with this app_id/outcome_type_id could
    // belong to a different company entirely if the same app_id was ever
    // granted to more than one company. Checked explicitly below so that
    // case gets an honest "taken by someone else" conflict instead of
    // either a false 409 against your own prior registration or, worse,
    // silently reading/matching against another company's row.
    const { data: existing, error: selectError } = await supabaseAdmin
      .from('mt_outcome_types')
      .select('company_id, costing_method, unit_label')
      .eq('app_id', req.appId)
      .eq('outcome_type_id', body.outcome_type_id)
      .maybeSingle();

    if (selectError) {
      console.error('[V1 OUTCOME-TYPES] lookup failed:', selectError.message);
      return res.status(500).json({ error: { type: 'server_error', message: 'Could not register outcome type.' } });
    }

    if (existing) {
      if (existing.company_id !== req.companyId) {
        return res.status(409).json({
          error: {
            type: 'conflict',
            message: 'outcome_type_id already registered under this app_id by a different company. Register a new outcome_type_id.'
          }
        });
      }
      if (existing.costing_method !== body.costing_method || existing.unit_label !== body.unit_label) {
        return res.status(409).json({
          error: {
            type: 'conflict',
            message: 'outcome_type_id already registered with a different costing_method or unit_label. Register a new outcome_type_id if your taxonomy genuinely changed.'
          }
        });
      }
      // costing_method/unit_label match (the only fields that would corrupt
      // historical cost interpretation if changed, finding #26) — but
      // name/description/canvas/abandonment_window_hrs are safe to update
      // on every resubmission, so a caller fixing a typo in one of those
      // isn't silently ignored just because the load-bearing fields matched.
      const { error: updateError } = await supabaseAdmin
        .from('mt_outcome_types')
        .update({
          name: body.name,
          description: body.description,
          canvas: body.canvas,
          abandonment_window_hrs: body.abandonment_window_hrs != null ? body.abandonment_window_hrs : null
        })
        .eq('app_id', req.appId)
        .eq('company_id', req.companyId)
        .eq('outcome_type_id', body.outcome_type_id);
      if (updateError) {
        console.error('[V1 OUTCOME-TYPES] update failed:', updateError.message);
        return res.status(500).json({ error: { type: 'server_error', message: 'Could not register outcome type.' } });
      }
      return res.status(200).json({ outcome_type_id: body.outcome_type_id, status: 'unchanged' });
    }

    const { error: insertError } = await supabaseAdmin
      .from('mt_outcome_types')
      .insert({
        company_id: req.companyId,
        app_id: req.appId,
        outcome_type_id: body.outcome_type_id,
        name: body.name,
        description: body.description,
        canvas: body.canvas,
        costing_method: body.costing_method,
        unit_label: body.unit_label,
        abandonment_window_hrs: body.abandonment_window_hrs != null ? body.abandonment_window_hrs : null
      });

    if (insertError) {
      console.error('[V1 OUTCOME-TYPES] insert failed:', insertError.message);
      return res.status(500).json({ error: { type: 'server_error', message: 'Could not register outcome type.' } });
    }

    return res.status(200).json({ outcome_type_id: body.outcome_type_id, status: 'created' });
  });

  // GET /v1/outcome-types — self-check on the caller's own registered
  // taxonomy. Scoped by company_id as well as app_id so a caller never sees
  // another company's registrations, even if they share an app_id.
  router.get('/outcome-types', async function (req, res) {
    const { data, error } = await supabaseAdmin
      .from('mt_outcome_types')
      .select('outcome_type_id, name, description, canvas, costing_method, unit_label, abandonment_window_hrs')
      .eq('app_id', req.appId)
      .eq('company_id', req.companyId);

    if (error) {
      console.error('[V1 OUTCOME-TYPES] read failed:', error.message);
      return res.status(500).json({ error: { type: 'server_error', message: 'Could not read outcome types.' } });
    }

    return res.status(200).json({ outcome_types: data || [] });
  });

  return router;
};
