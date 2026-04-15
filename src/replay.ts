/**
 * Replay V2 — continuous DOM event streaming to InariWatch cloud.
 *
 * Captures full rrweb event stream (not just filtered subset like session.ts),
 * batches into 30-second blocks, and POSTs to /api/replay/ingest. Each block
 * is stored as a gzipped object in Cloudflare R2 and can be scrubbed frame-by-frame
 * in the dashboard player.
 *
 * Browser-only. rrweb is loaded dynamically (optional peer dep) so Node users
 * pay zero bundle cost.
 *
 * Correlation with backend: exposes window.__INARIWATCH_SESSION__ and patches
 * fetch() to propagate the session id as `x-inariwatch-session` header on
 * same-origin requests. The server attaches that id to any errors it captures.
 */

import type { CaptureConfig } from "@inariwatch/capture"
import { classifyField, shouldMask, isUncertain, hashFeatures, type FieldFeatures, type Classification, type PiiCategory } from "./pii-classifier.js"
import {
  urlIsDenied,
  contentTypeIsCapturable,
  redactHeaders,
  processBody,
  ABSOLUTE_MAX_BODY_BYTES,
  type ProcessedBody,
} from "./network-body.js"

/**
 * Replay recording options. Lives here (not in core capture) so users who
 * only need error tracking pay zero tokens for the type.
 */
export interface ReplayConfig {
  /** Flush interval in seconds (default: 30) */
  blockDurationSec?: number
  /** Max buffer bytes before forced flush (default: 262144 = 256 KB) */
  maxBufferBytes?: number
  /** Override the endpoint (default: parsed from DSN or https://app.inariwatch.com) */
  endpoint?: string
  /**
   * Mask all input values. Default behavior:
   *   - `true`  when `piiClassifier` is `false` — safer fallback.
   *   - `false` when `piiClassifier` is `"heuristic"` or `"ai"` — the classifier decides per field.
   * Explicitly setting this overrides both defaults.
   */
  maskAllInputs?: boolean
  /** CSS selectors whose text content should be redacted */
  redactSelectors?: string[]
  /**
   * PII classifier strategy:
   *   - `"ai"` (default) — heuristics first, server AI for ambiguous fields.
   *   - `"heuristic"` — client-side rules only, zero network cost.
   *   - `false` — disabled; falls back to `maskAllInputs: true` for safety.
   */
  piiClassifier?: "ai" | "heuristic" | false
  /**
   * Probability (0.0–1.0) that an uncaught error triggers a full session
   * flush. Default `1.0` — every error session is recorded.
   *
   * Sessions without errors stay 100% client-side (ring buffer only) and
   * never touch the network — matches Sentry's cost-efficient default.
   */
  errorSampleRate?: number
  /**
   * Probability (0.0–1.0) that a session starts recording from the first
   * event, regardless of whether an error occurs. Default `0.0` — zero
   * passive traffic. Raise to e.g. `0.01` to sample 1% of all sessions for
   * UX research on top of error-triggered capture.
   */
  sessionSampleRate?: number
  /**
   * Seconds of pre-error context to keep in the client-side ring buffer.
   * When an error fires, the full buffer flushes as the first block so
   * reviewers can see the steps that led to the crash. Default `60`.
   *
   * Also drives rrweb's `checkoutEveryNms` so a full DOM snapshot is
   * guaranteed within every buffer window — without this, trimming old
   * events would leave the replay unplayable.
   */
  bufferSeconds?: number
}

const DEFAULT_BLOCK_DURATION_SEC = 30
const DEFAULT_MAX_BUFFER_BYTES = 256 * 1024 // 256 KB
const DEFAULT_BUFFER_SECONDS = 60
const DEFAULT_ERROR_SAMPLE_RATE = 1.0
const DEFAULT_SESSION_SAMPLE_RATE = 0.0
const MAX_EVENTS_PER_BLOCK = 10_000 // server-side limit

let replayActive = false
let currentSessionId: string | null = null

/**
 * Session lifecycle state machine:
 *   - "buffer"    — events accumulate in memory, never sent. Trimmed to
 *                   `bufferMaxMs` on each tick. Zero network activity.
 *   - "streaming" — events flush to the server every `blockDurationSec` or
 *                   whenever the buffer cap is hit. Set by either a sampled
 *                   session (sessionSampleRate roll) or an error trigger.
 */
type ReplayMode = "buffer" | "streaming"

interface ReplayState {
  sessionId: string
  projectId: string
  endpoint: string
  blockIndex: number
  buffer: unknown[]
  bufferBytes: number
  blockStartMs: number
  sessionStartMs: number
  timer: ReturnType<typeof setInterval> | null
  debug: boolean
  mode: ReplayMode
  /** Milliseconds of pre-error context to keep in buffer mode. */
  bufferMaxMs: number
  /** Probability threshold for error-triggered flush (0-1). */
  errorSampleRate: number
  /** Timestamp of the first error that triggered streaming (for telemetry). */
  errorTriggeredAt: number | null
}

let state: ReplayState | null = null

function generateSessionId(): string {
  // crypto.randomUUID available in modern browsers (Chrome 92+, Safari 15.4+)
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return `s_${crypto.randomUUID()}`
  }
  // Fallback: 128 random bits encoded as hex
  const bytes = new Uint8Array(16)
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(bytes)
  } else {
    for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256)
  }
  return `s_${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`
}

/** Get current session id (null if replay not active). Exposed for tests. */
export function getSessionId(): string | null {
  return currentSessionId
}

function getEndpoint(config: CaptureConfig, replayConfig: ReplayConfig): string {
  if (replayConfig.endpoint) return replayConfig.endpoint.replace(/\/$/, "")
  if (config.dsn) {
    try {
      const u = new URL(config.dsn)
      return `${u.protocol}//${u.host}`
    } catch {
      // fall through
    }
  }
  return "https://app.inariwatch.com"
}

/** Clamp sample rates into [0, 1]; NaN / non-numbers fall back to default. */
function clampRate(value: number | undefined, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback
  if (value < 0) return 0
  if (value > 1) return 1
  return value
}

interface RemoteReplaySettings {
  enabled?: boolean
  errorSampleRate?: number
  sessionSampleRate?: number
  bufferSeconds?: number
  retentionDays?: number
  piiClassifier?: "ai" | "heuristic" | false
  // Phase I.d — body capture toggle + per-project denylist + size cap.
  // SDK applies all of these client-side BEFORE any data leaves the page.
  captureNetworkBodies?: boolean
  networkUrlDenylist?: string[]
  networkBodyMaxBytes?: number
  networkBodyMode?: "failed" | "all"
}

/**
 * Fetch dashboard-set config for this project. 2-second timeout so a slow
 * dashboard never blocks replay init. Errors → return null → fall back to
 * SDK-code defaults.
 *
 * The response is cacheable (server sends cache-control: public, max-age=60)
 * so subsequent fetches inside a minute use the HTTP cache.
 */
async function fetchRemoteConfig(
  endpoint: string,
  projectId: string,
  debug: boolean,
): Promise<RemoteReplaySettings | null> {
  if (typeof fetch === "undefined") return null
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 2000)
    const resp = await fetch(`${endpoint}/api/replay/config/${encodeURIComponent(projectId)}`, {
      method: "GET",
      signal: controller.signal,
    })
    clearTimeout(timer)
    if (!resp.ok) return null
    const data = (await resp.json()) as { settings?: RemoteReplaySettings }
    return data.settings ?? null
  } catch (err) {
    if (debug) {
      console.warn("[@inariwatch/capture-replay] config fetch failed, using code defaults:", err instanceof Error ? err.message : err)
    }
    return null
  }
}

/**
 * Drop events older than the ring-buffer window. Always keep the most
 * recent full DOM snapshot (rrweb type 2) + its preceding meta event
 * (type 4) regardless of age — without them the replay can't render
 * anything on playback (user sees a black viewport).
 *
 * rrweb's `checkoutEveryNms` (set equal to bufferMaxMs) emits fresh full
 * snapshots periodically, but there's a race window between the previous
 * snapshot expiring and the next one being created. Pinning the latest
 * snapshot closes that gap.
 */
function trimBuffer(): void {
  if (!state) return
  const cutoff = Date.now() - state.bufferMaxMs

  // Find the most recent type 2 (full snapshot) and the type 4 (meta) that
  // immediately precedes it. Scan from end so "most recent" wins first.
  let latestFullIdx = -1
  let latestMetaIdx = -1
  for (let i = state.buffer.length - 1; i >= 0; i--) {
    const ev = state.buffer[i] as { type?: number }
    if (latestFullIdx === -1 && ev.type === 2) {
      latestFullIdx = i
      // Look backwards for the matching meta event
      for (let j = i - 1; j >= 0; j--) {
        const prev = state.buffer[j] as { type?: number }
        if (prev.type === 4) { latestMetaIdx = j; break }
      }
      break
    }
  }

  const kept: unknown[] = []
  let bytes = 0
  for (let i = 0; i < state.buffer.length; i++) {
    const ev = state.buffer[i]
    const ts = (ev as { timestamp?: number }).timestamp ?? 0
    const pinned = i === latestFullIdx || i === latestMetaIdx
    if (pinned || ts >= cutoff) {
      kept.push(ev)
      bytes += estimateSize(ev)
    }
  }
  state.buffer = kept
  state.bufferBytes = bytes
}

/**
 * Promote the session from "buffer" to "streaming" mode after an error.
 * The accumulated ring buffer becomes the first block — that's the pre-error
 * context a reviewer needs to understand what led to the crash.
 *
 * Gated by `errorSampleRate` so apps can cap the % of error sessions they
 * record (useful at high traffic).
 */
function triggerErrorFlush(): void {
  if (!state) return
  if (state.mode === "streaming") return
  if (Math.random() >= state.errorSampleRate) return  // not sampled

  state.mode = "streaming"
  state.errorTriggeredAt = Date.now()
  if (state.debug) {
    console.warn("[@inariwatch/capture/replay] error detected — switching to streaming mode")
  }
  // Flush the buffer immediately as block 0
  void flushBlock()
}

/**
 * POST the current buffer as a replay block. Swallows errors — replay is
 * best-effort and must never crash the host app.
 */
async function flushBlock(opts: { isFinal: boolean } = { isFinal: false }): Promise<void> {
  if (!state || state.buffer.length === 0) return
  // In buffer mode we never hit the network — the ring buffer stays local
  // until an error promotes the session. On final flush (unload) we also
  // skip if nothing triggered streaming: the session was uneventful, no
  // reason to pay storage for it.
  if (state.mode === "buffer") return

  const events = state.buffer
  const myIndex = state.blockIndex
  const myBlockStart = state.blockStartMs - state.sessionStartMs
  const myBlockEnd = Date.now() - state.sessionStartMs

  // Reset buffer before network call so new events land in the next block
  state.buffer = []
  state.bufferBytes = 0
  state.blockIndex = myIndex + 1
  state.blockStartMs = Date.now()

  const body = {
    sessionId: state.sessionId,
    projectId: state.projectId,
    blockIndex: myIndex,
    startMs: Math.max(0, myBlockStart),
    endMs: myBlockEnd,
    events,
    metadata: {
      startedAt: state.sessionStartMs,
      endedAt: opts.isFinal ? Date.now() : undefined,
      browser: typeof navigator !== "undefined" ? navigator.userAgent.slice(0, 200) : undefined,
      os: typeof navigator !== "undefined" ? inferOS(navigator.userAgent) : undefined,
      viewport: typeof window !== "undefined" ? {
        width: window.innerWidth,
        height: window.innerHeight,
        dpr: window.devicePixelRatio,
      } : undefined,
      isFinal: opts.isFinal,
      // Phase F — read end-user identity from a global the host page sets.
      // Shape: `window.__INARIWATCH_USER__ = { id?: string, email?: string }`.
      // Both fields optional. Read on every flush so logout / login mid-session
      // is reflected in late blocks (the server's first-write-wins clause
      // protects the session's canonical user from being overwritten).
      user: readEndUser(),
    },
  }

  const url = `${state.endpoint}/api/replay/ingest`
  const payload = JSON.stringify(body)

  // On page unload, sendBeacon is the only reliable transport
  if (opts.isFinal && typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function") {
    try {
      const blob = new Blob([payload], { type: "application/json" })
      navigator.sendBeacon(url, blob)
      return
    } catch {
      // fall through to fetch
    }
  }

  try {
    await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: payload,
      keepalive: opts.isFinal,
    })
  } catch (err) {
    if (state?.debug) {
      console.warn("[@inariwatch/capture/replay] flush failed:", err instanceof Error ? err.message : err)
    }
  }
}

function inferOS(ua: string): string | undefined {
  if (/Windows/i.test(ua)) return "Windows"
  if (/Mac OS X|Macintosh/i.test(ua)) return "macOS"
  if (/Android/i.test(ua)) return "Android"
  if (/iPhone|iPad|iOS/i.test(ua)) return "iOS"
  if (/Linux/i.test(ua)) return "Linux"
  return undefined
}

/**
 * Non-rrweb events emitted into the buffer. Prefixed with `_kind` so the
 * server-side indexer + causal chain detector can distinguish them from
 * rrweb DOM snapshots (which use numeric `type` field).
 */
type NetworkEvent = {
  _kind: "network"
  timestamp: number
  method: string
  url: string
  status?: number
  durationMs?: number
  errorMessage?: string
  // Phase I.d — optional body capture. Off by default; enabled per project
  // via `replaySettings.captureNetworkBodies`. All four fields land together
  // (or none) and are pre-masked client-side; the server trusts the SDK
  // to have enforced the size cap + denylist already.
  requestBody?: { text: string; truncated: boolean; originalBytes: number }
  responseBody?: { text: string; truncated: boolean; originalBytes: number }
  requestHeaders?: Record<string, string>
  responseHeaders?: Record<string, string>
  /** Set when bodies were SUPPRESSED on purpose (denylist match, wrong
   *  content type) so the player can show "Body omitted: <reason>" instead
   *  of a confusing empty viewer. */
  bodyOmittedReason?: "denied-url" | "binary-content" | "empty" | "off"
}
type ConsoleEvent = { _kind: "console"; timestamp: number; level: "error" | "warn"; message: string }
type ErrorCaptureEvent = { _kind: "error"; timestamp: number; fingerprint: string; message: string; stack?: string; source?: string; line?: number; col?: number }
// SPA route change. rrweb only emits a meta (type 4) on initial snapshot +
// every `checkoutEveryNms` — it does NOT observe history.pushState. Without
// this, replays of single-page apps show a single URL chip even after the
// user navigates through 5 routes.
type NavEvent = { _kind: "nav"; timestamp: number; href: string }
// Phase G — Core Web Vital. One event per metric, emitted once when its
// final value is known (LCP/CLS/INP on visibility hide; FCP/TTFB shortly
// after page load). Rating thresholds follow the official Google ranges.
type VitalEvent = {
  _kind: "vital";
  timestamp: number;
  name: "LCP" | "CLS" | "INP" | "FCP" | "TTFB";
  value: number;
  rating: "good" | "needs-improvement" | "poor";
}

function pushCustomEvent(ev: NetworkEvent | ConsoleEvent | ErrorCaptureEvent | NavEvent | VitalEvent): void {
  if (!state) return
  state.buffer.push(ev)
  state.bufferBytes += 300

  // Uncaught errors promote a buffer-mode session to streaming so reviewers
  // get the pre-error context + live recording after the crash.
  if (ev._kind === "error") triggerErrorFlush()
}

/** Compute a short fingerprint for grouping identical errors across a session. */
function fingerprintError(message: string, stack?: string): string {
  // Use first stack frame (or message) — stable enough for session dedup.
  const topFrame = stack?.split("\n")[1]?.trim() ?? ""
  const base = `${message.slice(0, 200)}|${topFrame.slice(0, 200)}`
  let hash = 5381
  for (let i = 0; i < base.length; i++) hash = ((hash << 5) + hash) ^ base.charCodeAt(i)
  return Math.abs(hash).toString(36)
}

interface BodyCaptureConfig {
  enabled: boolean
  urlDenylist: string[]
  maxBytes: number
  mode: "failed" | "all"
}

/**
 * Patch global fetch so:
 *  1. Same-origin requests get a session correlation header.
 *  2. Request/response outcomes are emitted as network events in the stream,
 *     which the causal chain detector uses to trace error → request → click.
 *  3. (Phase I.d, opt-in) Request/response bodies are captured + masked.
 * Cross-origin requests skip the header (avoids CORS preflight) but still
 * get timed so they appear in the Network track.
 */
function patchFetch(sessionId: string, bodyCapture: BodyCaptureConfig): void {
  if (typeof globalThis === "undefined" || typeof globalThis.fetch !== "function") return
  const orig = globalThis.fetch
  if ((orig as { __inariwatchPatched?: boolean }).__inariwatchPatched) return

  const patched: typeof fetch = async (input, init) => {
    const started = Date.now()
    let url = ""
    let method = "GET"
    try {
      url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url
      method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase()
    } catch {
      // If we can't introspect the input, just pass through
      return orig(input, init)
    }

    // Never patch our own ingest URL — would recurse
    if (url.includes("/api/replay/ingest")) return orig(input, init)

    const isSameOrigin = typeof window !== "undefined"
      ? !url.startsWith("http") || url.startsWith(window.location.origin)
      : true

    let finalInit: RequestInit | undefined = init
    if (isSameOrigin) {
      try {
        const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined))
        if (!headers.has("x-inariwatch-session")) {
          headers.set("x-inariwatch-session", sessionId)
        }
        finalInit = { ...init, headers }
      } catch {
        // fall through with original init
      }
    }

    // Phase I.d — decide WHETHER to capture bodies for this request. Done
    // BEFORE the network call so we can clone headers / read the request
    // body without hitting it twice.
    const captureRequestBody = bodyCapture.enabled && !urlIsDenied(url, bodyCapture.urlDenylist)
    let capturedRequestBody: ProcessedBody | null = null
    let capturedRequestHeaders: Record<string, string> | undefined = undefined
    if (captureRequestBody) {
      try {
        const reqHeaders = new Headers(
          (finalInit && finalInit.headers) ?? (input instanceof Request ? input.headers : undefined),
        )
        capturedRequestHeaders = redactHeaders(headersToRecord(reqHeaders))
        // Read the request body. Strings/JSON are easy; ReadableStreams
        // need a clone via Request constructor.
        const reqBodyRaw = await readRequestBody(input, finalInit)
        if (reqBodyRaw !== null) {
          capturedRequestBody = processBody({
            raw: reqBodyRaw,
            contentType: reqHeaders.get("content-type"),
            maxBytes: bodyCapture.maxBytes,
          })
        }
      } catch {
        // Body capture must NEVER break the user's fetch call.
      }
    }

    try {
      const resp = await orig(input, finalInit)

      // Decide whether to capture the response body. Skip when the mode is
      // "failed" and the response was successful — saves storage + PII risk.
      const shouldCaptureResp =
        bodyCapture.enabled &&
        !urlIsDenied(url, bodyCapture.urlDenylist) &&
        (bodyCapture.mode === "all" || resp.status >= 400)

      let capturedResponseBody: ProcessedBody | null = null
      let capturedResponseHeaders: Record<string, string> | undefined = undefined
      let bodyOmittedReason: NetworkEvent["bodyOmittedReason"] = undefined

      if (shouldCaptureResp) {
        try {
          // Clone first so the user's `.json()` etc. still works on the original.
          const cloned = resp.clone()
          capturedResponseHeaders = redactHeaders(headersToRecord(cloned.headers))
          const respCt = cloned.headers.get("content-type")
          if (!contentTypeIsCapturable(respCt)) {
            bodyOmittedReason = "binary-content"
          } else {
            const respText = await cloned.text()
            capturedResponseBody = processBody({
              raw: respText,
              contentType: respCt,
              maxBytes: bodyCapture.maxBytes,
            })
            if (!capturedResponseBody) bodyOmittedReason = "empty"
          }
        } catch {
          // Body read failed — log the request without it.
        }
      } else if (bodyCapture.enabled && urlIsDenied(url, bodyCapture.urlDenylist)) {
        bodyOmittedReason = "denied-url"
      } else if (!bodyCapture.enabled) {
        bodyOmittedReason = "off"
      }

      pushCustomEvent({
        _kind: "network",
        timestamp: started,
        method,
        url: url.slice(0, 500),
        status: resp.status,
        durationMs: Date.now() - started,
        ...(capturedRequestBody ? { requestBody: capturedRequestBody } : {}),
        ...(capturedResponseBody ? { responseBody: capturedResponseBody } : {}),
        ...(capturedRequestHeaders ? { requestHeaders: capturedRequestHeaders } : {}),
        ...(capturedResponseHeaders ? { responseHeaders: capturedResponseHeaders } : {}),
        ...(bodyOmittedReason ? { bodyOmittedReason } : {}),
      })
      return resp
    } catch (err) {
      pushCustomEvent({
        _kind: "network",
        timestamp: started,
        method,
        url: url.slice(0, 500),
        durationMs: Date.now() - started,
        errorMessage: err instanceof Error ? err.message.slice(0, 200) : String(err).slice(0, 200),
        ...(capturedRequestBody ? { requestBody: capturedRequestBody } : {}),
        ...(capturedRequestHeaders ? { requestHeaders: capturedRequestHeaders } : {}),
      })
      throw err
    }
  }

  ;(patched as { __inariwatchPatched?: boolean }).__inariwatchPatched = true
  globalThis.fetch = patched
}

/** Convert a Headers iterable into a plain record so it can be JSON-stringified. */
function headersToRecord(h: Headers): Record<string, string> {
  const out: Record<string, string> = {}
  h.forEach((value, name) => { out[name] = value })
  return out
}

/**
 * Read a request body without consuming the original. The user might pass:
 *   - a string
 *   - URLSearchParams / FormData
 *   - a ReadableStream (rare in practice — most apps stringify before fetch)
 *   - a Request object with its own body
 *
 * For the Request case we use `.clone()`. For init.body we read the value
 * directly when it's a primitive type and skip when it's a stream
 * (consuming would break the user's call).
 */
async function readRequestBody(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
): Promise<string | null> {
  try {
    if (input instanceof Request) {
      const cloned = input.clone()
      const text = await cloned.text()
      return text || null
    }
    const body = init?.body
    if (body == null) return null
    if (typeof body === "string") return body
    if (body instanceof URLSearchParams) return body.toString()
    if (body instanceof FormData) {
      // FormData → urlencoded-style preview. Files become "[file:name]".
      const parts: string[] = []
      body.forEach((value, key) => {
        if (typeof value === "string") parts.push(`${key}=${encodeURIComponent(value)}`)
        else parts.push(`${key}=[file:${(value as File).name ?? "blob"}]`)
      })
      return parts.join("&")
    }
    // ReadableStream / Blob / ArrayBuffer — skip. Consuming a stream would
    // break the actual fetch call, which is unacceptable.
    return null
  } catch {
    return null
  }
}

/**
 * Patch console.error / console.warn to mirror entries into the replay stream.
 * Calls the original console first so the user's own devtools still see logs.
 */
function patchConsole(): void {
  if (typeof console === "undefined") return
  if ((console as { __inariwatchPatched?: boolean }).__inariwatchPatched) return

  const origError = console.error.bind(console)
  const origWarn = console.warn.bind(console)

  console.error = (...args: unknown[]) => {
    try {
      pushCustomEvent({
        _kind: "console",
        timestamp: Date.now(),
        level: "error",
        message: args.map((a) => (typeof a === "string" ? a : safeStringify(a))).join(" ").slice(0, 500),
      })
    } catch {
      // Never fail the original console call
    }
    origError(...args)
  }

  console.warn = (...args: unknown[]) => {
    try {
      pushCustomEvent({
        _kind: "console",
        timestamp: Date.now(),
        level: "warn",
        message: args.map((a) => (typeof a === "string" ? a : safeStringify(a))).join(" ").slice(0, 500),
      })
    } catch {
      // Never fail the original console call
    }
    origWarn(...args)
  }

  ;(console as { __inariwatchPatched?: boolean }).__inariwatchPatched = true
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

/**
 * Capture uncaught errors and unhandled promise rejections. Each error lands
 * in the replay stream as an `_kind: "error"` event with a short fingerprint
 * — this is what /api/replay/ingest pulls into error_fingerprints[].
 */
function attachErrorHandlers(): void {
  if (typeof window === "undefined") return
  if ((window as { __inariwatchErrorsPatched?: boolean }).__inariwatchErrorsPatched) return

  window.addEventListener("error", (event) => {
    try {
      const err = event.error
      const message = event.message || (err instanceof Error ? err.message : String(err))
      const stack = err instanceof Error ? err.stack : undefined
      pushCustomEvent({
        _kind: "error",
        timestamp: Date.now(),
        fingerprint: fingerprintError(message, stack),
        message: String(message).slice(0, 500),
        stack: stack?.slice(0, 2000),
        source: event.filename?.slice(0, 300),
        line: event.lineno,
        col: event.colno,
      })
    } catch {
      // Error in error handler — swallow
    }
  })

  window.addEventListener("unhandledrejection", (event) => {
    try {
      const reason = event.reason
      const message = reason instanceof Error ? reason.message : String(reason)
      const stack = reason instanceof Error ? reason.stack : undefined
      pushCustomEvent({
        _kind: "error",
        timestamp: Date.now(),
        fingerprint: fingerprintError(message, stack),
        message: `Unhandled rejection: ${message}`.slice(0, 500),
        stack: stack?.slice(0, 2000),
      })
    } catch {
      // swallow
    }
  })

  ;(window as { __inariwatchErrorsPatched?: boolean }).__inariwatchErrorsPatched = true
}

/**
 * Watch SPA navigations (Next.js, React Router, anything that uses the
 * History API). rrweb only emits a meta event on initial snapshot + every
 * `checkoutEveryNms`, so without this hook a SPA session shows a single
 * URL chip in the breadcrumb strip even when the user visited 5 routes.
 *
 * We monkey-patch `history.pushState` / `history.replaceState` and listen
 * for `popstate` (back/forward). Each detected change emits a lightweight
 * `_kind: "nav"` event — much cheaper than a full DOM snapshot, and the
 * player reads it the same way it reads rrweb meta events.
 */
/**
 * Read `window.__INARIWATCH_USER__` and shape-guard it before sending. We
 * do NOT auto-scrape forms / DOM for emails — the host page must explicitly
 * publish the user. This is the privacy contract the docs make to customers.
 *
 * Returns undefined when the global is missing or malformed so the JSON
 * payload omits the field entirely (matches the type `user?`).
 */
function readEndUser(): { id?: string; email?: string } | undefined {
  if (typeof window === "undefined") return undefined
  const raw = (window as { __INARIWATCH_USER__?: unknown }).__INARIWATCH_USER__
  if (!raw || typeof raw !== "object") return undefined
  const u = raw as { id?: unknown; email?: unknown }
  const out: { id?: string; email?: string } = {}
  if (typeof u.id === "string" && u.id.length > 0) out.id = u.id.slice(0, 200)
  if (typeof u.email === "string" && u.email.length > 0) out.email = u.email.slice(0, 200)
  return out.id || out.email ? out : undefined
}

function attachNavWatcher(): void {
  if (typeof window === "undefined") return
  const flag = window as { __inariwatchNavPatched?: boolean }
  if (flag.__inariwatchNavPatched) return

  let lastHref = location.href

  const emitIfChanged = () => {
    const href = location.href
    if (href === lastHref) return
    lastHref = href
    pushCustomEvent({ _kind: "nav", timestamp: Date.now(), href })
  }

  const origPush = history.pushState
  const origReplace = history.replaceState

  // Use function() (not arrow) so `this` binds to history naturally.
  history.pushState = function (...args: Parameters<typeof history.pushState>) {
    const ret = origPush.apply(this, args)
    // Defer to a microtask so frameworks that read location synchronously
    // after pushState (e.g. Next.js router) finish their bookkeeping first.
    queueMicrotask(emitIfChanged)
    return ret
  }
  history.replaceState = function (...args: Parameters<typeof history.replaceState>) {
    const ret = origReplace.apply(this, args)
    queueMicrotask(emitIfChanged)
    return ret
  }
  window.addEventListener("popstate", emitIfChanged)
  // Hash-only navigations don't fire popstate consistently across browsers.
  window.addEventListener("hashchange", emitIfChanged)

  flag.__inariwatchNavPatched = true
}

/**
 * Attach Core Web Vitals observers. Each metric resolves at a different
 * lifecycle moment:
 *   - FCP / TTFB  → shortly after first paint
 *   - LCP / CLS / INP → only finalised on visibility hide / pagehide
 *
 * We mirror the canonical Google `web-vitals` library's logic without the
 * dependency. ~80 lines instead of ~5 KB. Edge cases NOT covered:
 *   - Back/forward cache restorations (we don't re-emit on bfcache restore)
 *   - Soft navigations (each SPA route gets its own initial vitals only
 *     for the first load — subsequent route changes don't re-trigger LCP)
 * Both are acceptable for v1 — the analyzer treats vitals as session-level.
 *
 * Rating thresholds: web.dev/vitals (Mar 2024 spec).
 */
function attachVitalsWatcher(): void {
  if (typeof window === "undefined" || typeof PerformanceObserver === "undefined") return
  const flag = window as { __inariwatchVitalsPatched?: boolean }
  if (flag.__inariwatchVitalsPatched) return

  const rate = (name: VitalEvent["name"], v: number): VitalEvent["rating"] => {
    if (name === "LCP")  return v <= 2500  ? "good" : v <= 4000  ? "needs-improvement" : "poor"
    if (name === "CLS")  return v <= 0.1   ? "good" : v <= 0.25  ? "needs-improvement" : "poor"
    if (name === "INP")  return v <= 200   ? "good" : v <= 500   ? "needs-improvement" : "poor"
    if (name === "FCP")  return v <= 1800  ? "good" : v <= 3000  ? "needs-improvement" : "poor"
    /* TTFB */           return v <= 800   ? "good" : v <= 1800  ? "needs-improvement" : "poor"
  }

  const emit = (name: VitalEvent["name"], value: number) => {
    if (!Number.isFinite(value) || value < 0) return
    pushCustomEvent({ _kind: "vital", timestamp: Date.now(), name, value: Math.round(value * 1000) / 1000, rating: rate(name, value) })
  }

  // FCP — fires once
  try {
    new PerformanceObserver((list, observer) => {
      for (const e of list.getEntries()) {
        if (e.name === "first-contentful-paint") {
          emit("FCP", e.startTime)
          observer.disconnect()
          break
        }
      }
    }).observe({ type: "paint", buffered: true })
  } catch { /* unsupported entry type */ }

  // LCP — track latest, emit on hide
  let latestLcp = 0
  try {
    new PerformanceObserver((list) => {
      for (const e of list.getEntries()) latestLcp = e.startTime
    }).observe({ type: "largest-contentful-paint", buffered: true })
  } catch { /* unsupported */ }

  // CLS — accumulate (excluding shifts within 500ms of input, per spec)
  let cls = 0
  try {
    new PerformanceObserver((list) => {
      for (const raw of list.getEntries()) {
        const e = raw as { hadRecentInput?: boolean; value?: number }
        if (!e.hadRecentInput && typeof e.value === "number") cls += e.value
      }
    }).observe({ type: "layout-shift", buffered: true })
  } catch { /* unsupported */ }

  // INP — interaction-to-next-paint, take the largest
  let maxInp = 0
  try {
    new PerformanceObserver((list) => {
      for (const e of list.getEntries()) {
        const dur = (e as { duration?: number }).duration ?? 0
        if (dur > maxInp) maxInp = dur
      }
    }).observe({ type: "event", buffered: true, durationThreshold: 16 } as PerformanceObserverInit & { durationThreshold?: number })
  } catch { /* unsupported */ }

  // TTFB — synchronous read from navigation timing
  try {
    const nav = performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined
    if (nav && nav.responseStart > 0) emit("TTFB", nav.responseStart)
  } catch { /* unsupported */ }

  // Flush deferred metrics on hide. We use BOTH visibilitychange AND
  // pagehide so single-page apps that never trigger pagehide (sample of
  // mobile Safari quirks) still get final values.
  let flushed = false
  const flushFinals = () => {
    if (flushed) return
    flushed = true
    if (latestLcp > 0) emit("LCP", latestLcp)
    if (cls > 0)        emit("CLS", cls)
    if (maxInp > 0)     emit("INP", maxInp)
  }
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") flushFinals()
  }, { once: false })
  window.addEventListener("pagehide", flushFinals, { once: true })

  flag.__inariwatchVitalsPatched = true
}

/**
 * Initialize replay recording. Browser-only, no-ops in Node. Idempotent
 * (second call is ignored). Never throws — all errors are logged in debug mode.
 */
export async function initReplay(
  replayConfig: ReplayConfig,
  captureConfig: CaptureConfig,
): Promise<void> {
  if (typeof window === "undefined") return
  if (replayActive) return

  if (!captureConfig.projectId) {
    if (!captureConfig.silent) {
      console.warn("[@inariwatch/capture/replay] replay: true but projectId is missing. Set config.projectId.")
    }
    return
  }

  // Resolve the endpoint early — we need it for the config fetch below.
  const endpoint = getEndpoint(captureConfig, replayConfig)

  // Fetch dashboard-set config for this project. Server settings for
  // `enabled`, `errorSampleRate`, `sessionSampleRate`, and `bufferSeconds`
  // OVERRIDE the options passed to replayIntegration() — otherwise a
  // customer could just hardcode `sessionSampleRate: 1.0` in their code to
  // bypass the Pro-gated slider. Non-security options (endpoint, custom
  // hooks, piiClassifier) remain code-driven.
  const remoteConfig = await fetchRemoteConfig(endpoint, captureConfig.projectId, !!captureConfig.debug)

  if (remoteConfig && remoteConfig.enabled === false) {
    if (captureConfig.debug && !captureConfig.silent) {
      console.warn("[@inariwatch/capture-replay] replay disabled for this project in the dashboard")
    }
    return
  }

  const blockDurationSec = replayConfig.blockDurationSec ?? DEFAULT_BLOCK_DURATION_SEC
  const maxBufferBytes = replayConfig.maxBufferBytes ?? DEFAULT_MAX_BUFFER_BYTES
  // Server wins over code for the safety-relevant settings. If the fetch
  // failed, fall back to code → sensible default.
  const bufferSeconds = remoteConfig?.bufferSeconds ?? replayConfig.bufferSeconds ?? DEFAULT_BUFFER_SECONDS
  const errorSampleRate = clampRate(
    remoteConfig?.errorSampleRate ?? replayConfig.errorSampleRate,
    DEFAULT_ERROR_SAMPLE_RATE,
  )
  const sessionSampleRate = clampRate(
    remoteConfig?.sessionSampleRate ?? replayConfig.sessionSampleRate,
    DEFAULT_SESSION_SAMPLE_RATE,
  )
  // Coin flip: if this session wins the `sessionSampleRate` lottery, start
  // streaming immediately (same state as "error triggered"). Otherwise
  // start in buffer mode and only flush if an error occurs.
  const initialMode: ReplayMode = Math.random() < sessionSampleRate ? "streaming" : "buffer"

  let record: ((opts: Record<string, unknown>) => unknown) | null = null
  try {
    // rrweb is a direct dependency — let the bundler resolve and code-split
    // it. (The previous `webpackIgnore` + variable-literal pattern existed
    // because rrweb used to be an optional peer dep; now it's always present.)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rrweb: any = await import("rrweb")
    record = rrweb.record ?? rrweb.default?.record ?? null
  } catch (err) {
    if (!captureConfig.silent) {
      console.warn(
        "[@inariwatch/capture-replay] rrweb failed to load — replay disabled. This is unexpected since rrweb is a direct dependency; please file an issue at https://github.com/orbita-pos/inariwatch-capture/issues",
        err instanceof Error ? err.message : err,
      )
    }
    return
  }

  if (!record) {
    if (!captureConfig.silent) {
      console.warn("[@inariwatch/capture/replay] rrweb.record not found in installed rrweb module.")
    }
    return
  }

  const sessionId = generateSessionId()
  currentSessionId = sessionId
  const now = Date.now()
  state = {
    sessionId,
    projectId: captureConfig.projectId,
    endpoint,
    blockIndex: 0,
    buffer: [],
    bufferBytes: 0,
    blockStartMs: now,
    sessionStartMs: now,
    timer: null,
    debug: !!captureConfig.debug,
    mode: initialMode,
    bufferMaxMs: bufferSeconds * 1000,
    errorSampleRate,
    errorTriggeredAt: null,
  }

  // Phase I.d body-capture config — server settings win (so the dashboard
  // toggle takes effect on the next session) with code defaults as the
  // fallback. Off by default; clamped to absolute byte ceiling regardless
  // of what the server returns to defend against misconfiguration.
  const bodyCaptureConfig: BodyCaptureConfig = {
    enabled: remoteConfig?.captureNetworkBodies === true,
    urlDenylist: Array.isArray(remoteConfig?.networkUrlDenylist) ? remoteConfig.networkUrlDenylist : [],
    maxBytes: Math.min(
      remoteConfig?.networkBodyMaxBytes ?? 100_000,
      ABSOLUTE_MAX_BODY_BYTES,
    ),
    mode: remoteConfig?.networkBodyMode === "all" ? "all" : "failed",
  }

  // Expose session id for other SDK layers (error capture attaches it).
  ;(window as unknown as { __INARIWATCH_SESSION__?: string }).__INARIWATCH_SESSION__ = sessionId
  patchFetch(sessionId, bodyCaptureConfig)
  patchConsole()
  attachErrorHandlers()
  attachNavWatcher()
  attachVitalsWatcher()

  // PII classifier — run synchronously on every existing input BEFORE rrweb's
  // first full-snapshot fires, then keep watching via MutationObserver.
  // Heuristics are O(form-count), zero network. If `piiClassifier: "ai"`,
  // uncertain fields are batched to /api/replay/classify-pii in the background.
  const piiStrategy = replayConfig.piiClassifier ?? "ai"
  if (piiStrategy !== false) {
    applyPiiMasking(piiStrategy, state.endpoint, state.projectId, !!captureConfig.debug)
  }

  // When the classifier is enabled, default maskAllInputs to false so non-PII
  // fields (search boxes, comments) stay readable in the replay. Explicit
  // config always wins.
  const defaultMaskAll = piiStrategy === false ? true : false
  const maskAllResolved = replayConfig.maskAllInputs ?? defaultMaskAll

  record({
    maskAllInputs: maskAllResolved,
    maskInputOptions: { password: true, email: true },
    maskTextSelector: replayConfig.redactSelectors?.join(", ") || undefined,
    blockClass: "iw-block",
    ignoreClass: "iw-ignore",
    maskTextClass: "iw-mask",
    // rrweb v2: `maskInputClass` masks INPUT VALUES by CSS class. Aligning it
    // with `maskTextClass` means the classifier just needs to add `iw-mask`
    // to the element — both text and input values get masked.
    maskInputClass: "iw-mask",
    // Force a fresh full DOM snapshot every `bufferMaxMs` so the ring buffer
    // can be trimmed without losing the initial snapshot — otherwise the
    // replay wouldn't render when played back after an error.
    checkoutEveryNms: bufferSeconds * 1000,
    emit(event: unknown) {
      if (!state) return
      state.buffer.push(event)
      // Cheap approximation of byte size — JSON.stringify on every event is
      // expensive. Use a running sum of a per-event estimate.
      state.bufferBytes += estimateSize(event)
      // Streaming-mode back-pressure: flush early when buffer caps hit.
      // Buffer-mode: trim instead (keeps last bufferMaxMs of context).
      if (state.bufferBytes >= maxBufferBytes || state.buffer.length >= MAX_EVENTS_PER_BLOCK) {
        if (state.mode === "streaming") void flushBlock()
        else trimBuffer()
      }
    },
  })

  // Periodic tick: in streaming mode, flush the accumulated block. In buffer
  // mode, trim events older than the ring-buffer window so memory stays
  // bounded while we wait for an error to maybe happen.
  state.timer = setInterval(() => {
    if (!state) return
    if (state.mode === "streaming") void flushBlock()
    else trimBuffer()
  }, blockDurationSec * 1000)

  // Flush on unload — best-effort via sendBeacon
  const finalFlush = () => void flushBlock({ isFinal: true })
  window.addEventListener("pagehide", finalFlush)
  window.addEventListener("beforeunload", finalFlush)

  replayActive = true
  if (captureConfig.debug && !captureConfig.silent) {
    console.warn(`[@inariwatch/capture/replay] active (session=${sessionId}, block=${blockDurationSec}s)`)
  }
}

function estimateSize(event: unknown): number {
  // Skip full JSON.stringify on every event. Estimate from a shallow inspection:
  // most rrweb events are 200-2000 bytes; mutations can be bigger but are rare.
  // If the event has a data.source of 3 (mutation), lean high.
  if (event && typeof event === "object") {
    const e = event as { type?: number; data?: { source?: number; attributes?: unknown[]; texts?: unknown[]; adds?: unknown[]; removes?: unknown[] } }
    if (e.type === 3 && e.data?.source === 0) {
      const counts =
        (e.data.attributes?.length ?? 0) +
        (e.data.texts?.length ?? 0) +
        (e.data.adds?.length ?? 0) +
        (e.data.removes?.length ?? 0)
      return Math.max(800, counts * 200)
    }
  }
  return 400
}

// ── PII classifier integration ───────────────────────────────────────────────

const MASK_CLASS = "iw-mask"
const AI_DEBOUNCE_MS = 500
const AI_MAX_BATCH = 20
/** LRU cache of server-AI classifications so we don't re-query identical fields. */
const aiCache = new Map<string, Classification>()
/** Queue of pending fields + their DOM nodes awaiting AI classification. */
let aiQueue: { hash: string; features: FieldFeatures; node: Element }[] = []
let aiFlushTimer: ReturnType<typeof setTimeout> | null = null

function extractFieldFeatures(el: Element): FieldFeatures {
  const tagName = el.tagName.toLowerCase()
  const attrs = el as unknown as { type?: string; name?: string; id?: string; placeholder?: string; autocomplete?: string }
  let labelText = ""
  // 1. aria-labelledby
  const labelledBy = el.getAttribute("aria-labelledby")
  if (labelledBy) {
    const labelEl = document.getElementById(labelledBy)
    if (labelEl) labelText = (labelEl.textContent ?? "").trim().slice(0, 200)
  }
  // 2. <label for="id">
  if (!labelText && el.id) {
    try {
      const labelEl = document.querySelector(`label[for="${CSS.escape(el.id)}"]`)
      if (labelEl) labelText = (labelEl.textContent ?? "").trim().slice(0, 200)
    } catch {
      // CSS.escape fails on weird ids — skip
    }
  }
  // 3. Enclosing <label>
  if (!labelText) {
    const closest = (el as Element).closest?.("label")
    if (closest) labelText = (closest.textContent ?? "").trim().slice(0, 200)
  }
  return {
    tagName,
    inputType: attrs.type,
    name: attrs.name,
    id: attrs.id,
    placeholder: attrs.placeholder,
    ariaLabel: el.getAttribute("aria-label") ?? undefined,
    labelText,
    autocomplete: attrs.autocomplete,
  }
}

function applyMaskClass(node: Element): void {
  if (!node.classList.contains(MASK_CLASS)) node.classList.add(MASK_CLASS)
}

function removeMaskClass(node: Element): void {
  if (node.classList.contains(MASK_CLASS)) node.classList.remove(MASK_CLASS)
}

/**
 * Track nodes we masked *provisionally* while waiting for the AI classifier.
 * Only these nodes are eligible to be unmasked when the AI says `not_pii`.
 * A field the user already marked via any means (heuristic hit, manual class,
 * server cache) is NOT in this set and stays masked forever.
 */
const provisionallyMasked = new WeakSet<Element>()

function classifyAndMark(node: Element, strategy: "ai" | "heuristic"): Classification {
  const features = extractFieldFeatures(node)
  const hash = hashFeatures(features)

  // 1. Cache hit from a previous AI call — apply or unmask based on result.
  //    If the cached result is `not_pii`, we still leave alone any pre-existing
  //    mask class the user may have applied manually (never remove external).
  const cached = aiCache.get(hash)
  if (cached) {
    if (shouldMask(cached)) applyMaskClass(node)
    return cached
  }

  // 2. Heuristic classification
  const heuristic = classifyField(features)
  if (shouldMask(heuristic)) {
    applyMaskClass(node)
    return heuristic
  }

  // 3. Uncertain + AI enabled → FAIL CLOSED: mask now, queue for classification,
  //    and only un-mask if the server confirms `not_pii`. This closes the race
  //    where a user types into a just-added input during the ~500ms AI window.
  if (strategy === "ai" && isUncertain(heuristic)) {
    if (!node.classList.contains(MASK_CLASS)) {
      applyMaskClass(node)
      provisionallyMasked.add(node)
    }
    aiQueue.push({ hash, features, node })
    scheduleAiFlush()
  }

  return heuristic
}

function scheduleAiFlush(): void {
  if (aiFlushTimer) return
  aiFlushTimer = setTimeout(() => {
    aiFlushTimer = null
    void flushAiQueue()
  }, AI_DEBOUNCE_MS)
}

async function flushAiQueue(): Promise<void> {
  if (!state || aiQueue.length === 0) return
  const batch = aiQueue.splice(0, AI_MAX_BATCH)
  try {
    const resp = await fetch(`${state.endpoint}/api/replay/classify-pii`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        projectId: state.projectId,
        fields: batch.map((b) => ({ hash: b.hash, features: b.features })),
      }),
    })
    if (!resp.ok) return
    const data = (await resp.json()) as { results?: { hash: string; category: PiiCategory; confidence: number; reason: string }[] }
    const results = data.results ?? []
    for (const r of results) {
      const classification: Classification = { category: r.category, confidence: r.confidence, reason: r.reason }
      aiCache.set(r.hash, classification)
      const entry = batch.find((b) => b.hash === r.hash)
      if (!entry) continue
      if (shouldMask(classification)) {
        applyMaskClass(entry.node)
      } else if (r.category === "not_pii" && provisionallyMasked.has(entry.node)) {
        // Only un-mask nodes we provisionally masked ourselves — never remove
        // a class the user applied manually or a heuristic-confirmed mask.
        removeMaskClass(entry.node)
        provisionallyMasked.delete(entry.node)
      }
      // `uncertain` from AI → leave the provisional mask in place. Fail-closed.
    }
  } catch (err) {
    if (state?.debug) {
      console.warn("[@inariwatch/capture/replay] classify-pii failed:", err instanceof Error ? err.message : err)
    }
  }

  // Anything still queued (batch overflow) — schedule another flush
  if (aiQueue.length > 0) scheduleAiFlush()
}

function walkInputs(root: ParentNode): Element[] {
  try {
    return Array.from(root.querySelectorAll<HTMLElement>("input, textarea, select"))
  } catch {
    return []
  }
}

function applyPiiMasking(
  strategy: "ai" | "heuristic",
  _endpoint: string,
  _projectId: string,
  debug: boolean,
): void {
  if (typeof document === "undefined") return

  // 1. Classify every existing input before rrweb snapshots the DOM
  for (const node of walkInputs(document)) {
    try {
      classifyAndMark(node, strategy)
    } catch (err) {
      if (debug) console.warn("[@inariwatch/capture/replay] classify error:", err instanceof Error ? err.message : err)
    }
  }

  // 2. Watch the DOM for new inputs. Classify them synchronously — the
  //    mutation fires before the user can interact with the element, so
  //    rrweb captures the masked class on the next incremental snapshot.
  try {
    const observer = new MutationObserver((records) => {
      for (const rec of records) {
        for (const added of rec.addedNodes) {
          if (!(added instanceof Element)) continue
          // Classify the node itself if it's an input, plus any descendants
          if (added.matches("input, textarea, select")) {
            classifyAndMark(added, strategy)
          }
          for (const node of walkInputs(added)) {
            classifyAndMark(node, strategy)
          }
        }
      }
    })
    observer.observe(document.documentElement, { childList: true, subtree: true })
  } catch (err) {
    if (debug) console.warn("[@inariwatch/capture/replay] MutationObserver failed:", err instanceof Error ? err.message : err)
  }
}

/** For tests: reset module state. Not exported from index.ts. */
export function __resetForTests(): void {
  replayActive = false
  currentSessionId = null
  if (state?.timer) clearInterval(state.timer)
  state = null
  aiCache.clear()
  aiQueue = []
  if (aiFlushTimer) clearTimeout(aiFlushTimer)
  aiFlushTimer = null
}

/** Expose estimator for unit tests. */
export { estimateSize as __estimateSize }
