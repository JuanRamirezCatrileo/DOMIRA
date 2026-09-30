import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useState } from "react";

import { Alert, Card, Field, SubmitButton, useErrorMessage } from "~/components/ui";
import { useI18n } from "~/i18n";
import { ApiClientError, apiRequest } from "~/lib/api-client";

export const Route = createFileRoute("/login")({
  component: Login,
});

function Login() {
  const { t } = useI18n();
  const message = useErrorMessage();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await apiRequest("POST", "/api/auth/login", { email, password });
      await navigate({ to: "/app" });
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? message(caught.failure) : message({ message: t("common.error") })
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <Card title={t("login.title")}>
      <form className="space-y-4" onSubmit={onSubmit}>
        {error ? <Alert tone="error">{error}</Alert> : null}
        <Field
          label={t("signup.email")}
          name="email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={setEmail}
        />
        <Field
          label={t("signup.password")}
          name="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={setPassword}
        />
        <div className="flex flex-wrap items-center gap-4">
          <SubmitButton pending={pending}>{t("login.submit")}</SubmitButton>
          <Link to="/forgot-password" className="text-sm text-sky-400 hover:text-sky-300">
            {t("login.forgot")}
          </Link>
          <Link to="/signup" className="text-sm text-slate-400 hover:text-slate-200">
            {t("login.noAccount")} {t("nav.signup")}
          </Link>
        </div>
      </form>
    </Card>
  );
}
