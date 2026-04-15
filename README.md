# @inariwatch/capture-replay

Session replay for `@inariwatch/capture`. Captures the DOM, network, console,
Web Vitals and user frustration signals so you can reproduce any user session
frame-by-frame in the InariWatch dashboard — with an AI narrator on top.

- **Automatic PII masking** (25 heuristic rules + optional AI classifier)
- **Core Web Vitals** inline (LCP, CLS, INP, FCP, TTFB) — no extra SDK
- **Rage + dead-click detection** server-side, no config
- **Opt-in network body capture** with 4-layer PII defence
- **Generate Fix** from any captured error — AI opens a PR
- **~150 KB gzipped**, lazy-loaded, zero impact on initial render

## Install

```bash
npm install @inariwatch/capture @inariwatch/capture-replay
```

`rrweb` is bundled internally — no additional install required.

## Usage (Next.js App Router)

```tsx
// app/capture-init.tsx
"use client"
import { useEffect } from "react"

export function CaptureInit() {
  useEffect(() => {
    void (async () => {
      const [{ init }, { replayIntegration }] = await Promise.all([
        import("@inariwatch/capture"),
        import("@inariwatch/capture-replay"),
      ])

      init({
        dsn: process.env.NEXT_PUBLIC_INARIWATCH_DSN,
        projectId: process.env.NEXT_PUBLIC_INARIWATCH_PROJECT_ID,
        integrations: [replayIntegration()],
      })
    })()
  }, [])
  return null
}
```

```tsx
// app/layout.tsx
import { CaptureInit } from "./capture-init"

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <CaptureInit />
        {children}
      </body>
    </html>
  )
}
```

That's it. The SDK now captures everything below automatically.

## What gets captured

| Signal | How | When |
|---|---|---|
| DOM mutations | rrweb | Continuous, 30-second blocks |
| Network requests | `fetch` + `XHR` patch | Every request (URL, method, status, duration) |
| Console logs | `console.error` / `.warn` patch | Every call |
| Uncaught errors | `window.onerror` + `unhandledrejection` | Every error, with stack + fingerprint |
| SPA navigations | `history.pushState` / `popstate` / `hashchange` hook | Every client-side route change |
| Core Web Vitals | `PerformanceObserver` | LCP/CLS/INP on tab hide; FCP/TTFB at load |
| End-user identity | Reads `window.__INARIWATCH_USER__` on each flush | Opt-in (see below) |
| Rage / dead clicks | Detected server-side from the click stream | Post-session, surfaced in the replay player |

## Options

```ts
replayIntegration({
  blockDurationSec: 30,           // flush interval (default: 30s)
  maxBufferBytes: 262144,         // force flush at 256 KB
  piiClassifier: "ai",            // "ai" | "heuristic" | false (default: "ai")
  maskAllInputs: false,           // override classifier
  redactSelectors: [".secret"],   // always-redacted CSS selectors
  endpoint: "https://app.inariwatch.com",  // override (default: parsed from DSN)
})
```

Most project-scoped settings (sampling rate, retention, **network body capture**,
email hashing) are configured from the InariWatch dashboard — they take effect
on the next session without a code change.

## PII masking

By default (`piiClassifier: "ai"`) every `<input>` is classified before rrweb
takes its first snapshot:

- **Tier 1 — heuristics (synchronous, ~25 rules):** `type=password`,
  `autocomplete=cc-number`, `name~="ssn"`, etc. Covers 90%+ of common PII.
- **Tier 2 — AI classifier (optional, batched):** ambiguous fields are sent
  to `/api/replay/classify-pii` (GPT-4o-mini). Runs in background, ~500ms.
- **Fail-closed:** while Tier 2 is pending, the field is preemptively masked.
  Only un-masked if the AI returns `not_pii` with high confidence.

No field content ever leaves the browser — only metadata (name, label, placeholder).

Set `piiClassifier: false` if you prefer the simpler `maskAllInputs: true`
behaviour.

## Identifying users

Attach the signed-in user to every replay session so the dashboard can group
sessions, search by email, and answer *"show me all sessions for juan@acme.com"*:

```ts
// After the user logs in (anywhere in your app):
window.__INARIWATCH_USER__ = {
  id: user.id,            // optional, app-side stable id (recommended)
  email: user.email,      // optional, displayed in dashboard
}

// On logout:
delete window.__INARIWATCH_USER__
```

The SDK reads this global on every block flush — there is **no DOM scraping**.
Both fields are optional and capped at 200 chars. The first block that carries
a user wins for the session (server-side first-write-wins prevents a stray
late block from overwriting the canonical user).

**Privacy:** by default the dashboard displays the raw email. Toggle *Hash
end-user emails* in the project's Replay settings to render sha256 hashes
instead — the plain value stays in the database so you can flip back without
losing data.

## Core Web Vitals

The SDK registers `PerformanceObserver` on `largest-contentful-paint`,
`layout-shift`, `event`, and `paint`, plus reads `navigation` timing for TTFB.
Each metric is emitted as a `_kind: "vital"` event with the official Google
rating thresholds (`good` / `needs-improvement` / `poor`).

- **FCP / TTFB** resolve at load — emitted within the first second
- **LCP / CLS / INP** resolve at tab hide — flushed via `visibilitychange` +
  `pagehide` so the final values land even on close

The dashboard renders the 5 metrics as coloured chips in the player header
and surfaces the worst rating as a badge on the `/replays` list cards.

## Network body capture *(opt-in)*

**Off by default.** Turn it on per-project in the dashboard's Replay settings
when you need the actual request/response JSON to debug an API integration.

Four layers of PII defence apply the moment you flip it on:

1. **URL denylist** — `/auth`, `/login`, `/oauth`, `/payment`, `/2fa`, etc.
   built-in, case-insensitive, extensible per project.
2. **JSON key masking** — any field whose key looks like a secret
   (`password`, `token`, `jwt`, `apikey`, `credential`, `cvv`, `ssn`, …) has
   its value replaced with `[REDACTED]` before the body is serialised.
3. **Value-shape regex masking** — catches embedded credentials in fields
   whose keys aren't suspect: JWTs, AWS access keys (`AKIA…` / `ASIA…`),
   Stripe keys (`sk_live_…`), GitHub PATs (`ghp_…`), Slack tokens.
4. **Header redaction** — `Authorization`, `Cookie`, `X-API-Key`,
   `X-Amz-Security-Token`, `X-Google-AuthUser`, etc. always stripped from
   both request and response headers.

Per-body cap defaults to **100 KB** (hard ceiling 500 KB). Content types
outside the text/json/form-urlencoded allowlist (images, PDFs, binary) are
never captured.

Modes:
- `failed` (default) — only capture bodies for HTTP 4xx/5xx or network error
- `all` — capture every response (higher PII surface, much higher storage)

## Correlation with errors

When a client-side error fires, the SDK:
1. Wraps it into the event stream as `_kind: "error"` with a stable fingerprint
2. Promotes a buffer-mode session to streaming so the post-error seconds are captured
3. Sends the session id on `x-inariwatch-session` header for every same-origin
   `fetch` — your server can correlate a 500 response back to the exact replay

If the fingerprint matches an existing alert in InariWatch (from Sentry, Vercel,
your `@inariwatch/capture` error handler, etc.), the replay gets linked
bidirectionally. Click *Generate Fix* in the dashboard and the AI agent opens
a PR against the customer's repo using the replay's event stream as context.

## Security

- Browser POSTs to `/api/replay/ingest` in 30-second compressed blocks
- Server validates `projectId`, `Origin` allowlist (configurable per project),
  per-IP and per-project rate limits, and per-block size caps
- Blocks land in Cloudflare R2; signed URLs expire in 5 min
- Session ids are 128-bit crypto-random — not guessable

## Bundle impact

- `@inariwatch/capture` alone: ~32 KB gzipped
- `@inariwatch/capture-replay` added: +150 KB gzipped (rrweb + PII classifier)
- Both are lazy-loaded via dynamic `import()` so initial page render is unaffected
- `tree-shakable` — importing `replayIntegration` without enabling network
  body capture keeps that code path out of your bundle

## What's new in 0.2.0

- SPA navigation watcher (`history.pushState` / `popstate` / `hashchange`)
  — route changes now show up as breadcrumb chips in the player
- End-user identification via `window.__INARIWATCH_USER__` with per-project
  email-hashing toggle
- Core Web Vitals capture (LCP, CLS, INP, FCP, TTFB) via `PerformanceObserver`
- Opt-in network body capture with 4-layer PII defence
- Rage + dead-click detection (server-side, no config)

## Peer dependency

`@inariwatch/capture >= 0.8.0` — earlier versions lack the `projectId` config
field the replay integration requires.

## License

MIT — © Jesus Bernal
