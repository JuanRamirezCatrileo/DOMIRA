import { createFileRoute } from "@tanstack/react-router";
import { dispatchApi } from "~/server/api/router";
export const Route = createFileRoute("/api/domains/$id/scan")({
  server: {
    handlers: {
      POST: ({ request }) => dispatchApi(request),
    },
  },
});
