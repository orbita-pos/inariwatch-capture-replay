/**
 * Pure helpers for safely capturing fetch request / response bodies in the
 * replay stream. Designed so 100% of the masking logic is unit-testable
 * with no DOM / no network — `replay.ts` only orchestrates timing and
 * fetch interception.
 *
 * Threat model:
 *   - Auth tokens, passwords, credit cards, SSNs, secret API keys end up in
 *     real-world bodies all the time. Default policy is "capture nothing"
 *     (project must opt-in) AND "even when on, redact aggressively".
 *   - We never trust customer-shipped denylist patterns to be exhaustive;
 *     the BUILT-IN denylists below always apply on top.
 */

/** Hard ceiling regardless of project setting — defends storage + R2 cost. */
export const ABSOLUTE_MAX_BODY_BYTES = 500_000;

/** URL substring patterns that ALWAYS skip body capture, even when the
 *  project's customer denylist is empty. Endpoints handling secrets.
 *  Expanded after a security review flagged how easy it is for legit-but-
 *  not-named-/login auth endpoints to slip through. */
const BUILTIN_URL_DENY = [
  // Auth flow names
  "/auth", "/login", "/logout", "/signin", "/sign-in", "/sign_in",
  "/signup", "/sign-up", "/sign_up", "/register",
  "/authenticate", "/authn", "/authz",
  "/credential", "/credentials", "/verify", "/verification",
  "/oauth", "/sso", "/saml", "/2fa", "/mfa", "/totp", "/webauthn",
  "/password", "/reset-password", "/reset_password", "/forgot",
  "/whoami", "/me",
  // Payments / financial
  "/payment", "/payments", "/checkout/pay", "/cards", "/wallet",
  "/billing", "/invoice", "/charge", "/refund",
  // Common API conventions on top of the above
  "/api/auth", "/api/login", "/api/session", "/api/sessions",
  "/api/token", "/api/tokens", "/api/key", "/api/keys",
  "/api/v1/auth", "/api/v2/auth", "/api/v3/auth",
  "/api/user/auth", "/api/users/auth", "/api/account/auth",
];

/** JSON keys (case-insensitive substring match) whose VALUES get masked
 *  when serialising a captured body. Belt + suspenders on top of the URL
 *  denylist — bodies with these fields shouldn't ship raw even if they
 *  came back from a non-auth endpoint. */
const SECRET_KEY_PATTERNS = [
  "password", "passwd", "pwd",
  "token", "id_token", "refresh", "refresh_token", "bearer", "jwt",
  "secret", "apikey", "api_key", "access_key", "client_secret",
  "authorization", "auth", "credential", "credentials", "passphrase",
  "cookie", "session", "session_id", "sessionid", "sid",
  "creditcard", "credit_card", "cardnumber", "card_number", "cvv", "cvc",
  "ssn", "socialsecurity", "national_id", "tax_id", "taxid",
  "pin", "otp", "mfa",
  "privatekey", "private_key", "secret_key",
  // Common cloud-provider key shapes — masked by name even before the
  // value-shape mask catches the literal AKIA/sk_ prefixes.
  "aws_access_key_id", "aws_secret_access_key", "aws_session_token",
];

/** Value-shape patterns that get masked regardless of the key name.
 *  Catches embedded credentials in fields like `{"data": "AKIA…"}` where
 *  the key isn't suspicious but the value clearly is. */
const SECRET_VALUE_PATTERNS: RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/,                                   // AWS access key id
  /\bASIA[0-9A-Z]{16}\b/,                                   // AWS temporary access key
  /\bsk_(?:live|test)_[0-9a-zA-Z]{20,}\b/,                  // Stripe secret keys
  /\brk_(?:live|test)_[0-9a-zA-Z]{20,}\b/,                  // Stripe restricted keys
  /\bxox[abprs]-[0-9a-zA-Z-]{10,}\b/,                       // Slack tokens
  /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/, // JWT
  /\bghp_[A-Za-z0-9]{36}\b/,                                // GitHub PAT (classic)
  /\bgho_[A-Za-z0-9]{36}\b/,                                // GitHub OAuth token
];

/** Content-Type prefixes we ALLOW to capture. Anything else (binary,
 *  multipart with files, etc.) gets dropped at the source. */
const CAPTURABLE_CONTENT_TYPES = [
  "application/json",
  "application/x-www-form-urlencoded",
  "application/xml",
  "text/",
];

/** Headers always removed from any captured request/response header set.
 *  Case-insensitive match on the header name. */
const REDACT_HEADER_NAMES = new Set([
  "authorization", "proxy-authorization",
  "cookie", "set-cookie",
  "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
  "x-access-token", "x-session-id", "x-jwt", "x-id-token",
  "x-amz-security-token", "x-google-authuser",
  "x-forwarded-authorization",
]);

/**
 * Returns true when the URL matches any built-in or customer-supplied
 * denylist pattern. Used by `captureBodyForUrl` AND surfaced separately
 * so the `_kind: "network"` event can record `bodyOmittedReason`.
 */
export function urlIsDenied(url: string, customerPatterns: string[] = []): boolean {
  if (!url) return true;
  const lower = url.toLowerCase();
  for (const p of BUILTIN_URL_DENY) {
    if (lower.includes(p)) return true;
  }
  for (const p of customerPatterns) {
    if (typeof p === "string" && p.length > 0 && lower.includes(p.toLowerCase())) {
      return true;
    }
  }
  return false;
}

/** True when the content type is in the allowlist (text-ish formats only). */
export function contentTypeIsCapturable(contentType: string | null | undefined): boolean {
  if (!contentType) return false;
  const lower = contentType.toLowerCase();
  return CAPTURABLE_CONTENT_TYPES.some((prefix) => lower.startsWith(prefix));
}

/**
 * Mask values whose key looks like a secret. Recurses into objects/arrays.
 * Strings replaced with `[REDACTED]`. Used on request + response bodies
 * after JSON parsing.
 *
 * Non-JSON bodies skip this step (we only mask structured data — text/xml
 * pass through unchanged once they pass the size + URL gates).
 */
export function maskSecretsInJson(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[depth-limit]";
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map((v) => maskSecretsInJson(v, depth + 1));
  // Strings at any depth: also screen for value-shape secrets (JWTs,
  // AWS keys, Stripe keys, etc.) so embedded credentials in non-suspect
  // keys don't slip through.
  if (typeof value === "string") {
    return SECRET_VALUE_PATTERNS.some((re) => re.test(value)) ? "[REDACTED]" : value;
  }
  if (typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    const lowerKey = key.toLowerCase();
    const isSecret = SECRET_KEY_PATTERNS.some((p) => lowerKey.includes(p));
    if (isSecret) {
      out[key] = typeof val === "string" || typeof val === "number" ? "[REDACTED]" : val;
    } else {
      out[key] = maskSecretsInJson(val, depth + 1);
    }
  }
  return out;
}

/**
 * Filter out auth-related headers, return the rest as a flat record.
 * Header values themselves are not modified — the assumption is once the
 * NAME isn't sensitive, the value isn't either (cache-control, content-type).
 */
export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (REDACT_HEADER_NAMES.has(name.toLowerCase())) continue;
    out[name] = value;
  }
  return out;
}

/**
 * Process a captured raw body string into the final shape stored on the
 * `_kind: "network"` event. Returns null when the body should NOT be
 * captured (denied URL, wrong content type, oversized after truncation).
 *
 * Truncation strategy: if the raw body exceeds `maxBytes`, slice and
 * append a marker so the reviewer can tell. JSON bodies are pretty-printed
 * AFTER masking so the viewer is human-readable.
 */
export interface ProcessedBody {
  /** UTF-8 string ready to ship. May be valid JSON or any other text. */
  text: string;
  /** True when the original body was longer than maxBytes. */
  truncated: boolean;
  /** Original size in bytes (pre-truncation) — useful in the UI. */
  originalBytes: number;
}

export function processBody(opts: {
  raw: string;
  contentType: string | null;
  maxBytes: number;
}): ProcessedBody | null {
  const { raw, contentType, maxBytes } = opts;
  if (!raw) return null;
  if (!contentTypeIsCapturable(contentType)) return null;

  const cap = Math.min(Math.max(1, maxBytes), ABSOLUTE_MAX_BODY_BYTES);
  const originalBytes = raw.length; // ≈ bytes for ASCII; close enough for metadata
  let text = raw;
  let truncated = false;
  if (text.length > cap) {
    text = text.slice(0, cap);
    truncated = true;
  }

  // Try to parse + mask JSON bodies. If parse fails (invalid JSON despite
  // the content-type), fall back to the raw text — masking can't help and
  // the reviewer needs SOMETHING to look at.
  if (contentType && contentType.toLowerCase().startsWith("application/json")) {
    try {
      const parsed = JSON.parse(text);
      const masked = maskSecretsInJson(parsed);
      text = JSON.stringify(masked, null, 2);
    } catch {
      // Truncated bodies often fail to parse (chopped mid-string). That's
      // OK — show the raw slice.
    }
  }

  return { text, truncated, originalBytes };
}
