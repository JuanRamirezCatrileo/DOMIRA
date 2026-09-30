import { createFileRoute } from "@tanstack/react-router";
import { dispatchApi } from "~/server/api/router";
export const Route = createFileRoute("/api/domains/$id/security")({
  server: {
    handlers: {
      GET: ({ request }) => dispatchApi(request),
    },
  },
});
