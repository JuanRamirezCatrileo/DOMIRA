import { createFileRoute } from "@tanstack/react-router";
import { dispatchApi } from "~/server/api/router";
export const Route = createFileRoute("/api/scans/$id/cancel")({
  server: {
    handlers: {
      POST: ({ request }) => dispatchApi(request),
    },
  },
});
