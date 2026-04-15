/**
 * @inariwatch/capture-replay — session replay integration for @inariwatch/capture.
 *
 * Usage:
 *   import { init } from "@inariwatch/capture"
 *   import { replayIntegration } from "@inariwatch/capture-replay"
 *
 *   init({
 *     dsn: process.env.INARIWATCH_DSN,
 *     projectId: "<uuid-from-dashboard>",
 *     integrations: [
 *       replayIntegration({ piiClassifier: "ai" })
 *     ]
 *   })
 *
 * The integration is browser-only — it no-ops in Node so it's safe to import
 * from isomorphic code paths.
 */

import type { Integration, CaptureConfig } from "@inariwatch/capture"
import { initReplay, getSessionId, type ReplayConfig } from "./replay.js"

export type { ReplayConfig } from "./replay.js"
export type { PiiCategory, Classification, FieldFeatures } from "./pii-classifier.js"

/**
 * Create a replay integration. Pass the returned object in
 * `init({ integrations: [replayIntegration()] })`.
 *
 * Requires `projectId` on the root CaptureConfig — the server uses it to
 * identify the target workspace. Without it, the integration warns and
 * no-ops (fail-safe).
 */
export function replayIntegration(options: ReplayConfig = {}): Integration {
  return {
    name: "Replay",
    setup(config: CaptureConfig) {
      // Browser-only — silently skip on the server. Users frequently import
      // this from isomorphic code; crashing server-side would be annoying.
      if (typeof window === "undefined") return

      if (!config.projectId) {
        if (!config.silent) {
          console.warn(
            "[@inariwatch/capture-replay] replayIntegration() needs `projectId` on init() config. Skipping.",
          )
        }
        return
      }

      // initReplay is async (dynamic-imports rrweb) — fire and forget.
      // It logs its own errors when `debug: true`.
      void initReplay(options, config)
    },
  }
}

/** Re-export session id accessor so apps can correlate server-side errors. */
export { getSessionId }
