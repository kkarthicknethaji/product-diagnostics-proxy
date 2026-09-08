// AI Cost Control Tower: OpenAPI Ingestion Layer — units-generated report-back
// Spec: ai-cost-tower-openapi-ingestion-spec.md v0.11, Section 6,
// PATCH /v1/usage-events/{client_call_id}/units-generated.
//
// Scoped by (company_id, app_id, client_call_id) — not client_call_id alone
// (Section 13, item 2: the generalized report-back must filter on app_id as
// well as company_id, matching the actual uniqueness scope of the
// idempotency constraint added in Phase 1).

async function updateUnitsGenerated(supabaseAdmin, { companyId, appId, clientCallId, unitsGenerated }) {
  const { data, error } = await supabaseAdmin
    .from('mt_ai_usage_events')
    .update({ units_generated: unitsGenerated })
    .eq('company_id', companyId)
    .eq('app_id', appId)
    .eq('client_call_id', clientCallId)
    .select('id')
    .maybeSingle();

  return { data, error };
}

module.exports = { updateUnitsGenerated };
