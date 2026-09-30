import { createFileRoute } from "@tanstack/react-router";
import { dispatchApi } from "~/server/api/router";
export const Route = createFileRoute("/api/domains/$id")({
  server: {
    handlers: {
      GET: ({ request }) => dispatchApi(request),
      PATCH: ({ request }) => dispatchApi(request),
      DELETE: ({ request }) => dispatchApi(request),
    },
  },
});
