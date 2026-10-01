import { createFileRoute } from "@tanstack/react-router";
import { dispatchApi } from "~/server/api/router";
export const Route = createFileRoute("/api/certificates")({
  server: {
    handlers: {
      GET: ({ request }) => dispatchApi(request),
    },
  },
});
