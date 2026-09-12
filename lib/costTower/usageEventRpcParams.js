// AI Trace Layer — code-review fix: the mt_ai_record_usage_event_with_span
// RPC's ~34-key parameter object was independently hand-built in both
// proxy/server.js's _insertAiUsageEvent() and
// proxy/routes/v1/usageEvents.js's _processItem(), with no shared mapping
// between them. This RPC's parameter list already drifted out of sync with
// calling code once (see ai-cost-tower-trace-layer-migration.sql's Step 4
// reconciliation note — 12 parameters were missing on first deployment,
// found only via live testing), so a single source of truth for this
// mapping is worth having: a future parameter change now only needs to
// happen here, not independently in both call sites.
//
// Callers normalize their own field names/defaults into this common shape
// first (e.g. usageEvents.js hardcodes session_type/prompt_version/
// settings_model to null, since an external caller has no equivalent
// concept) — this function only does the final field-name -> p_* mapping.

function buildUsageEventRpcParams(f) {
  return {
    p_company_id: f.company_id,
    p_app_id: f.app_id,
    p_client_call_id: f.client_call_id,
    p_provider: f.provider,
    p_product_id: f.product_id,
    p_session_id: f.session_id,
    p_session_type: f.session_type,
    p_user_id: f.user_id,
    p_user_role_at_call: f.user_role_at_call,
    p_caller: f.caller,
    p_prompt_version: f.prompt_version,
    p_requested_model: f.requested_model,
    p_response_model: f.response_model,
    p_settings_mode: f.settings_mode,
    p_settings_model: f.settings_model,
    p_selection_rule: f.selection_rule,
    p_input_tokens: f.input_tokens,
    p_output_tokens: f.output_tokens,
    p_cache_creation_5m_tokens: f.cache_creation_5m_tokens,
    p_cache_creation_1h_tokens: f.cache_creation_1h_tokens,
    p_cache_read_tokens: f.cache_read_tokens,
    p_provider_usage_raw: f.provider_usage_raw,
    p_status: f.status,
    p_provider_http_status: f.provider_http_status,
    p_error_type: f.error_type,
    p_failure_phase: f.failure_phase,
    p_request_started_at: f.request_started_at,
    p_duration_ms: f.duration_ms,
    p_request_bytes: f.request_bytes,
    p_response_bytes: f.response_bytes,
    p_outcome_id: f.outcome_id,
    p_units_generated: f.units_generated,
    p_client_trace_id: f.client_trace_id != null ? f.client_trace_id : null,
    p_agent_name: f.agent_name != null ? f.agent_name : null,
    // Universal Payload Capture — both nullable, RPC-side gating decides
    // whether a non-NULL value actually persists. Callers that never set
    // these (e.g. usageEvents.js's _processItem(), which has no payload
    // concept) leave them undefined here, which JSON-serializes away
    // before the RPC call, same as an explicit null.
    p_request_payload: f.request_payload,
    p_response_payload: f.response_payload
  };
}

module.exports = { buildUsageEventRpcParams };
