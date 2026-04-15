/**
 * PII classifier for browser input fields.
 *
 * Two tiers:
 *   1. Heuristics — synchronous, runs on every input. 90%+ recall on obvious
 *      cases (password, credit card, email, phone, SSN, DOB, address).
 *   2. AI (optional) — batched server call for fields the heuristic marked
 *      as "uncertain". Enabled via ReplayConfig.piiClassifier = "ai".
 *
 * Outputs a `PiiCategory` plus a confidence score. Callers apply the
 * `iw-mask` class to DOM nodes that scored at or above a threshold —
 * rrweb then masks their captured values automatically.
 *
 * Pure functions — zero DOM dependencies so they're unit-testable.
 */

export type PiiCategory =
  | "password"
  | "credit_card"
  | "card_cvv"
  | "ssn"
  | "email"
  | "phone"
  | "date_of_birth"
  | "full_name"
  | "street_address"
  | "postal_code"
  | "government_id"
  | "api_secret"
  | "not_pii"
  | "uncertain";

export interface FieldFeatures {
  /** Normalized tag name, e.g. "input", "textarea". */
  tagName: string;
  /** The HTML `type` attribute, e.g. "password", "email", "tel". */
  inputType?: string;
  /** The `name` attribute. */
  name?: string;
  /** The `id` attribute. */
  id?: string;
  /** Placeholder text. */
  placeholder?: string;
  /** `aria-label` if set. */
  ariaLabel?: string;
  /** Text content of the associated <label> element (or nearby label). */
  labelText?: string;
  /** The `autocomplete` attribute (HTML5 autofill hint — super high signal). */
  autocomplete?: string;
}

export interface Classification {
  category: PiiCategory;
  /** 0-100. ≥70 means we're confident enough to auto-mask. */
  confidence: number;
  /** Human-readable note for debugging ("matched: type=password"). */
  reason: string;
}

/** Confidence cutoff at or above which the caller should apply iw-mask. */
export const MASK_THRESHOLD = 70;
/** Below this, the heuristic sends the field to the AI classifier (if enabled). */
export const UNCERTAIN_THRESHOLD = 50;

// ── Rule set ─────────────────────────────────────────────────────────────────
// Order matters: the first rule that matches wins. Rules are tiered so
// strong signals (input type, autocomplete) fire before fuzzy name regexes.

interface Rule {
  category: PiiCategory;
  confidence: number;
  match: (f: NormalizedFeatures) => string | null; // returns the reason string on hit
}

interface NormalizedFeatures {
  tagName: string;
  inputType: string;
  name: string;
  id: string;
  placeholder: string;
  ariaLabel: string;
  labelText: string;
  autocomplete: string;
  /** Concatenated text of name + id + placeholder + ariaLabel + labelText, lowercased. */
  blob: string;
}

const RULES: Rule[] = [
  // ── Input type (strongest signal, native browser attribute) ─────────────
  {
    category: "password",
    confidence: 100,
    match: (f) => (f.inputType === "password" ? "type=password" : null),
  },
  {
    category: "email",
    confidence: 95,
    match: (f) => (f.inputType === "email" ? "type=email" : null),
  },
  {
    category: "phone",
    confidence: 90,
    match: (f) => (f.inputType === "tel" ? "type=tel" : null),
  },

  // ── Autocomplete attribute (HTML5 standard, explicit intent) ────────────
  {
    category: "credit_card",
    confidence: 100,
    match: (f) => (/\bcc-(number|name|exp(-month|-year)?)\b/.test(f.autocomplete) ? `autocomplete=${f.autocomplete}` : null),
  },
  {
    category: "card_cvv",
    confidence: 100,
    match: (f) => (f.autocomplete.includes("cc-csc") ? "autocomplete=cc-csc" : null),
  },
  {
    category: "password",
    confidence: 100,
    match: (f) => (/\b(current-password|new-password)\b/.test(f.autocomplete) ? `autocomplete=${f.autocomplete}` : null),
  },
  {
    category: "ssn",
    confidence: 100,
    match: (f) => (/\b(ssn|national-id)\b/.test(f.autocomplete) ? `autocomplete=${f.autocomplete}` : null),
  },
  {
    category: "street_address",
    confidence: 90,
    match: (f) => (/\b(street-address|address-line[12])\b/.test(f.autocomplete) ? `autocomplete=${f.autocomplete}` : null),
  },
  {
    category: "postal_code",
    confidence: 90,
    match: (f) => (f.autocomplete.includes("postal-code") ? "autocomplete=postal-code" : null),
  },
  {
    category: "date_of_birth",
    confidence: 90,
    match: (f) => (/\bbday(-day|-month|-year)?\b/.test(f.autocomplete) ? `autocomplete=${f.autocomplete}` : null),
  },
  {
    category: "full_name",
    confidence: 85,
    match: (f) => (/\b(name|given-name|family-name|honorific-(prefix|suffix))\b/.test(f.autocomplete) ? `autocomplete=${f.autocomplete}` : null),
  },

  // ── Name/label regex (fuzzy — medium confidence) ────────────────────────
  {
    category: "credit_card",
    confidence: 90,
    match: (f) => matchAny(f.blob, [/\bcard[\s_-]?number\b/, /\bcredit[\s_-]?card\b/, /\bcc[\s_-]?num\b/, /\bcardnum/]) ? "blob:card-number" : null,
  },
  {
    category: "card_cvv",
    confidence: 90,
    match: (f) => matchAny(f.blob, [/\bcvv\b/, /\bcvc\b/, /\bcsc\b/, /\bsecurity[\s_-]?code\b/]) ? "blob:cvv" : null,
  },
  {
    category: "ssn",
    confidence: 90,
    match: (f) => matchAny(f.blob, [/\bssn\b/, /\bsocial[\s_-]?security\b/, /\bsocial[\s_-]?security[\s_-]?number\b/]) ? "blob:ssn" : null,
  },
  {
    category: "government_id",
    confidence: 85,
    match: (f) => matchAny(f.blob, [/\bpassport\b/, /\bnational[\s_-]?id\b/, /\bdriver[\s_-]?licen[cs]e\b/, /\bid[\s_-]?number\b/, /\btax[\s_-]?id\b/]) ? "blob:gov-id" : null,
  },
  {
    category: "date_of_birth",
    confidence: 85,
    match: (f) => matchAny(f.blob, [/\bdob\b/, /\bbirth[\s_-]?date\b/, /\bdate[\s_-]?of[\s_-]?birth\b/, /\bbirthday\b/]) ? "blob:dob" : null,
  },
  {
    category: "email",
    confidence: 85,
    match: (f) => matchAny(f.blob, [/\be[\s_-]?mail\b/, /\bemail[\s_-]?address\b/]) ? "blob:email" : null,
  },
  {
    category: "phone",
    confidence: 80,
    match: (f) => matchAny(f.blob, [/\bphone\b/, /\bmobile\b/, /\btelephone\b/, /\bcell(phone)?\b/]) ? "blob:phone" : null,
  },
  {
    category: "postal_code",
    confidence: 80,
    match: (f) => matchAny(f.blob, [/\bzip[\s_-]?code\b/, /\bpostal[\s_-]?code\b/, /\bpostcode\b/]) ? "blob:zip" : null,
  },
  {
    category: "street_address",
    confidence: 75,
    match: (f) => matchAny(f.blob, [/\bstreet[\s_-]?address\b/, /\bhome[\s_-]?address\b/, /\baddress[\s_-]?line\b/, /\baddr[\s_-]?1\b/]) ? "blob:address" : null,
  },
  {
    category: "full_name",
    confidence: 70,
    match: (f) => matchAny(f.blob, [/\bfirst[\s_-]?name\b/, /\blast[\s_-]?name\b/, /\bfull[\s_-]?name\b/, /\bgiven[\s_-]?name\b/, /\bfamily[\s_-]?name\b/, /\bsurname\b/]) ? "blob:name" : null,
  },
  {
    category: "api_secret",
    confidence: 95,
    // Note: `\b` treats `_` as a word character in JS regex, so `\bbearer\b`
    // fails on `bearer_token`. Anchor only at the start and allow an
    // optional trailing separator+word.
    match: (f) => matchAny(f.blob, [
      /\bapi[\s_-]?key\b/,
      /\bsecret[\s_-]?key\b/,
      /\baccess[\s_-]?token\b/,
      /\bbearer(?:[\s_-]?token)?\b/,
      /\bauth[\s_-]?token\b/,
    ]) ? "blob:secret" : null,
  },

  // ── Non-PII markers (bump confidence that a field is OK to show) ───────
  {
    category: "not_pii",
    confidence: 80,
    match: (f) => matchAny(f.blob, [/\bsearch\b/, /\bquery\b/, /\bcomment\b/, /\bmessage\b/, /\bsubject\b/, /\btitle\b/, /\bdescription\b/, /\bnotes?\b/, /\bfeedback\b/]) ? "blob:non-pii" : null,
  },
  {
    category: "not_pii",
    confidence: 70,
    match: (f) => (f.inputType === "search" ? "type=search" : null),
  },
];

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Classify a field by features. Returns the best match, or `uncertain`
 * if no rule fires — callers may then forward it to the AI endpoint.
 */
export function classifyField(features: FieldFeatures): Classification {
  const n = normalize(features);

  for (const rule of RULES) {
    const reason = rule.match(n);
    if (reason) {
      return { category: rule.category, confidence: rule.confidence, reason };
    }
  }

  // Nothing matched — the caller decides whether to query the AI tier
  return { category: "uncertain", confidence: 0, reason: "no-rule-matched" };
}

/**
 * Should the caller apply `iw-mask` based on this classification?
 * Only true when we're confident the field holds PII.
 */
export function shouldMask(c: Classification): boolean {
  if (c.category === "not_pii" || c.category === "uncertain") return false;
  return c.confidence >= MASK_THRESHOLD;
}

/**
 * Is this classification too weak to trust on its own? When `true`,
 * the caller should escalate to the server-side AI tier (if enabled).
 */
export function isUncertain(c: Classification): boolean {
  return c.category === "uncertain" || (c.confidence < UNCERTAIN_THRESHOLD && c.category !== "not_pii");
}

/**
 * Stable hash of the features — used as a cache key for AI results so
 * identical fields across pages/sessions don't pay for re-classification.
 * djb2, truncated to 12 hex chars.
 */
export function hashFeatures(features: FieldFeatures): string {
  const n = normalize(features);
  const blob = [n.tagName, n.inputType, n.name, n.id, n.placeholder, n.ariaLabel, n.labelText, n.autocomplete].join("|");
  let hash = 5381;
  for (let i = 0; i < blob.length; i++) hash = ((hash << 5) + hash) ^ blob.charCodeAt(i);
  return Math.abs(hash).toString(36).slice(0, 12);
}

// ── Internals ────────────────────────────────────────────────────────────────

function normalize(f: FieldFeatures): NormalizedFeatures {
  const norm = {
    tagName: (f.tagName ?? "").toLowerCase(),
    inputType: (f.inputType ?? "").toLowerCase(),
    name: (f.name ?? "").toLowerCase(),
    id: (f.id ?? "").toLowerCase(),
    placeholder: (f.placeholder ?? "").toLowerCase(),
    ariaLabel: (f.ariaLabel ?? "").toLowerCase(),
    labelText: (f.labelText ?? "").toLowerCase(),
    autocomplete: (f.autocomplete ?? "").toLowerCase(),
  };
  const blob = [norm.name, norm.id, norm.placeholder, norm.ariaLabel, norm.labelText]
    .filter(Boolean)
    .join(" ");
  return { ...norm, blob };
}

function matchAny(str: string, patterns: RegExp[]): boolean {
  for (const p of patterns) {
    if (p.test(str)) return true;
  }
  return false;
}
