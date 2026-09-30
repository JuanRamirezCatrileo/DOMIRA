import { createFileRoute } from "@tanstack/react-router";
import { dispatchApi } from "~/server/api/router";
export const Route = createFileRoute("/api/findings/$id")({
  server: {
    handlers: {
      PATCH: ({ request }) => dispatchApi(request),
    },
  },
});
