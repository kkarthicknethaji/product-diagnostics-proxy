// AI Trace Layer — strict-comparison idempotency helper
// Spec: ai-trace-layer-spec-v0.11-final.md, Part D.0.
//
// insertIdempotent() (./idempotency.js) treats any conflict as a successful
// dedup, handing back the existing row's id with no regard for whether the
// caller's OTHER fields match. That's correct for a plain re-send of an
// identical event, but wrong wherever the idempotency key alone isn't
// enough — e.g. POST /v1/traces replaying client_trace_id with a DIFFERENT
// agent_name/session_id is a genuine caller error, not a safe no-op.
//
// v9.33.02 rewrite (code-review fix, AI Trace Layer: Payload Capture): this
// no longer delegates to insertIdempotent() internally. That delegation cost
// an extra round trip on every conflict — insertIdempotent()'s own internal
// follow-up SELECT (idColumn only), then a second, separate follow-up SELECT
// here (compareColumns only) — found while building POST /v1/trace-payloads
// (proxy/routes/v1/tracePayloads.js), which needs this same strict-compare
// shape but couldn't afford two round trips to read one row. Now does one
// upsert, and on conflict, exactly one follow-up SELECT for idColumn +
// compareColumns together. insertIdempotent() itself is untouched and still
// used as-is by every caller that doesn't need a strict compare.
//
// Also adds:
// - `compareFn` (optional, defaults to `_valuesEqual` below): lets a caller
//   supply its own equality function instead of `_valuesEqual`'s
//   string/UUID-only comparison — e.g. tracePayloads.js needs a structural,
//   key-order-independent compare for JSONB columns, where even
//   `JSON.stringify`-based equality is wrong (Postgres jsonb does not
//   preserve object key order on read-back).
// - `extraMatch` (optional): additional column/value filters applied to the
//   conflict follow-up SELECT only, alongside conflictColumns — for a caller
//   like tracePayloads.js whose conflictColumns (`usage_event_id` alone)
//   don't already include a tenant scope the way traces.js's
//   (`company_id`, `app_id`, `client_trace_id`) do.
// - A `!existing` guard on the follow-up SELECT — a real latent gap found
//   during this same rewrite: the pre-v9.33.02 version dereferenced
//   `existing[col]` with no check that a conflict's follow-up SELECT
//   actually found a row, the same unguarded-null-deref bug class just fixed
//   in tracePayloads.js's own first draft.

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Postgres always canonicalizes a uuid-typed column to lowercase on
// read-back, regardless of the case it was inserted with, but a caller's
// fresh request body keeps whatever case it happened to send. A plain !==
// would then spuriously flag a legitimate retry (identical value, different
// case) as a mismatch. Only normalizes values that are actually UUID-shaped
// — a non-UUID compareColumn (e.g. agent_name) stays case-sensitive, since
// that's real, meaningful text, not an opaque id.
function _valuesEqual(a, b) {
  if (typeof a === 'string' && typeof b === 'string' && UUID_RE.test(a) && UUID_RE.test(b)) {
    return a.toLowerCase() === b.toLowerCase();
  }
  return a === b;
}

async function insertIdempotentStrict(supabaseAdmin, { table, conflictColumns, row, idColumn, compareColumns, compareFn, extraMatch }) {
  const equalsFn = compareFn || _valuesEqual;
  const selectColumns = [idColumn].concat(compareColumns).join(',');

  const { data: inserted, error: insertError } = await supabaseAdmin
    .from(table)
    .upsert(row, { onConflict: conflictColumns.join(','), ignoreDuplicates: true })
    .select(selectColumns);

  if (insertError) return { error: insertError };

  if (inserted && inserted.length > 0) {
    return { id: inserted[0][idColumn], deduplicated: false };
  }

  // Empty result = conflict = this exact (conflictColumns) tuple already
  // exists. Follow-up SELECT to hand back the existing row's id and content,
  // in one query.
  const matchFilter = {};
  conflictColumns.forEach(function(col) { matchFilter[col] = row[col]; });
  if (extraMatch) Object.assign(matchFilter, extraMatch);

  const { data: existing, error: selectError } = await supabaseAdmin
    .from(table)
    .select(selectColumns)
    .match(matchFilter)
    .maybeSingle();

  if (selectError) return { error: selectError };
  if (!existing) {
    // Should not happen — a conflict implies a matching row exists — but
    // treated as a genuine error rather than dereferencing a null below.
    return { error: new Error('Idempotent insert conflicted but the follow-up SELECT found no matching row.') };
  }

  const mismatch = compareColumns.some(function(col) { return !equalsFn(existing[col], row[col]); });
  if (mismatch) {
    return { error: { code: 'IDEMPOTENCY_CONFLICT', message: 'Replay with the same idempotency key but different ' + compareColumns.join('/') + '.' } };
  }

  return { id: existing[idColumn], deduplicated: true };
}

module.exports = { insertIdempotentStrict };
