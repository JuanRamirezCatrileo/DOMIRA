// DOMIRA REST API v1 — thin transport adapter. All logic (authorisation, validation,
// error shape, security headers) lives in src/server/api/router.ts so it can be
// exercised by the test suite without an HTTP server.
import { createFileRoute } from "@tanstack/react-router";

import { dispatchApi } from "~/server/api/router";

export const Route = createFileRoute("/api/scans")({
  server: {
    handlers: {
      GET: ({ request }) => dispatchApi(request),
      POST: ({ request }) => dispatchApi(request),
    },
  },
});
