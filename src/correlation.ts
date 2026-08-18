// Headers that identify a REQUEST, not a person.
//
// `x-ebay-c-correlation-session` is a per-page correlation id: it ties a page's
// calls together in eBay's own logs and carries no authority whatsoever. It was
// treated as a credential because its name ends in "session", and the fallout
// was worse than noise — nothing local holds such a value, so egress could not
// resolve it, the call was blocked, and the agent told a signed-in user to sign
// in. The actual eBay session is a cookie the browser attaches by itself.
//
// A correlation header is safe to omit. The server mints its own when it is
// missing, which is exactly what happens on a request the site makes itself.

/** Names that mark a header as request-scoped tracing rather than a credential. */
const CORRELATION_RE = /correlation|traceparent|tracestate|\btrace\b|request[-_]?id|\breq[-_]?id\b|\bspan\b|\bray\b|\bb3\b/i;

/**
 * Names that are unambiguously credentials, whatever else they contain.
 *
 * Checked first so a hypothetical `x-csrf-correlation` stays a secret. Weak
 * words like "session", "token" and "id" are deliberately NOT here: those are
 * the ones correlation headers routinely contain, and treating them as decisive
 * is the mistake being fixed.
 */
const CREDENTIAL_RE = /authorization|bearer|csrf|xsrf|api[-_]?key|apikey|secret|password/i;

/** Whether a header names request tracing that can be dropped rather than resolved. */
export function isCorrelationHeader(name: string): boolean {
  if (CREDENTIAL_RE.test(name)) return false;
  return CORRELATION_RE.test(name);
}
