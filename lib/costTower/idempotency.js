// AI Cost Control Tower: OpenAPI Ingestion Layer — shared idempotency helper
// Spec: ai-cost-tower-openapi-ingestion-spec.md v0.11, Sections 4.3/4.5/5/6.
//
// Both ingestion writes (POST /v1/usage-events' client_call_id and
// POST /v1/outcomes' client_outcome_id) use the identical pattern: insert
// with ON CONFLICT (company_id, app_id, <idempotency column>) DO NOTHING,
// then a follow-up SELECT on an empty result (findings #3 and #27 — an
// empty result on conflict is a successful dedup, not an error).
//
// supabase-js has no raw "INSERT ... ON CONFLICT DO NOTHING" call. The
// PostgREST-native equivalent is .upsert(row, { onConflict, ignoreDuplicates:
// true }) — sends Prefer: resolution=ignore-duplicates, and correctly
// returns an empty result set (not an error) on conflict, same as the raw
// SQL would.

async function insertIdempotent(supabaseAdmin, { table, conflictColumns, row, idColumn }) {
  const { data: inserted, error: insertError } = await supabaseAdmin
    .from(table)
    .upsert(row, { onConflict: conflictColumns.join(','), ignoreDuplicates: true })
    .select(idColumn);

  if (insertError) return { error: insertError };

  if (inserted && inserted.length > 0) {
    return { id: inserted[0][idColumn], deduplicated: false };
  }

  // Empty result = conflict = this exact (company_id, app_id, <idempotency
  // column>) tuple already exists. Follow-up SELECT to hand back the
  // existing row's id rather than surfacing this as an error.
  const matchFilter = {};
  conflictColumns.forEach(function(col) { matchFilter[col] = row[col]; });

  const { data: existing, error: selectError } = await supabaseAdmin
    .from(table)
    .select(idColumn)
    .match(matchFilter)
    .maybeSingle();

  if (selectError) return { error: selectError };
  if (!existing) {
    // Should not happen — a conflict implies a matching row exists — but
    // treated as a genuine error rather than silently returning nothing,
    // since the caller needs an id to respond with.
    return { error: new Error('Idempotent insert conflicted but the follow-up SELECT found no matching row.') };
  }

  return { id: existing[idColumn], deduplicated: true };
}

module.exports = { insertIdempotent };
