import { HeadContent, Outlet, Scripts, createRootRoute } from "@tanstack/react-router";
import type { ReactNode } from "react";

import { Shell } from "~/components/ui";
import { I18nProvider } from "~/i18n";
import appCss from "~/styles/app.css?url";

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: "DOMIRA" },
      {
        name: "description",
        content:
          "DOMIRA — defensive domain monitoring: TLS, certificates, DNS, SPF/DMARC and security headers for the domains you authorise.",
      },
      // Baseline hardening; the same headers are set by the API layer for /api/*.
      { httpEquiv: "X-Content-Type-Options", content: "nosniff" },
      { name: "referrer", content: "strict-origin-when-cross-origin" },
    ],
    links: [{ rel: "stylesheet", href: appCss }],
  }),
  notFoundComponent: () => <NotFound />,
  component: RootComponent,
});

function NotFound() {
  return (
    <Shell>
      <h1 className="text-xl font-semibold">404</h1>
      <p className="mt-2 text-sm text-slate-300">
        {/* Kept language-neutral on purpose: the shell resolves the locale on the client. */}
        Page not found · Página no encontrada
      </p>
      <a className="mt-4 inline-block text-sm text-sky-400 hover:text-sky-300" href="/">
        DOMIRA
      </a>
    </Shell>
  );
}

function RootComponent() {
  return (
    <RootDocument>
      <Outlet />
    </RootDocument>
  );
}

function RootDocument({ children }: { children: ReactNode }) {
  return (
    <html lang="es">
      <head>
        <HeadContent />
      </head>
      <body className="bg-slate-950">
        <I18nProvider>
          <Shell>{children}</Shell>
        </I18nProvider>
        <Scripts />
      </body>
    </html>
  );
}
