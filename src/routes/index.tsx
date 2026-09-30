import { createFileRoute, Link } from "@tanstack/react-router";

import { Alert, Card } from "~/components/ui";
import { useI18n } from "~/i18n";

export const Route = createFileRoute("/")({
  component: Home,
});

/**
 * Honest landing placeholder for deliverable 1. The full landing page (with the
 * product story, screenshots and pricing tiers) is deliverable 5 and is NOT
 * simulated here: no fake customers, no fake certifications, no fake pricing.
 */
function Home() {
  const { t } = useI18n();
  return (
    <div className="space-y-8">
      <div className="space-y-4">
        <p className="text-xs uppercase tracking-[0.3em] text-sky-400">{t("app.name")}</p>
        <h1 className="max-w-3xl text-3xl font-semibold leading-tight sm:text-4xl">
          {t("landing.title")}
        </h1>
        <p className="max-w-3xl text-slate-300">{t("landing.lead")}</p>
        <p className="max-w-3xl text-sm text-slate-400">{t("landing.honest")}</p>
      </div>

      <div className="flex flex-wrap gap-3">
        <Link
          to="/signup"
          className="rounded bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500"
        >
          {t("landing.cta.signup")}
        </Link>
        <Link
          to="/login"
          className="rounded border border-white/20 px-4 py-2 text-sm font-medium text-slate-200 hover:border-white/40"
        >
          {t("landing.cta.login")}
        </Link>
      </div>

      <Card title={t("app.notYet.title")}>
        <ul className="space-y-2 text-sm text-slate-300">
          <li>{t("app.notYet.domains")}</li>
          <li>{t("app.notYet.scanning")}</li>
          <li>{t("app.notYet.findings")}</li>
          <li>{t("app.notYet.alerts")}</li>
          <li>{t("app.notYet.reports")}</li>
          <li>{t("app.notYet.billing")}</li>
        </ul>
      </Card>

      <Alert tone="info">{t("landing.onlyAuthorized")}</Alert>
    </div>
  );
}
