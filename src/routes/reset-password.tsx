import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";

import { Alert, Card, Field, SubmitButton, useErrorMessage } from "~/components/ui";
import { useI18n } from "~/i18n";
import { ApiClientError, apiRequest } from "~/lib/api-client";

export const Route = createFileRoute("/reset-password")({
  component: ResetPassword,
});

function ResetPassword() {
  const { t } = useI18n();
  const message = useErrorMessage();
  const [token, setToken] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setToken(params.get("token") ?? "");
  }, []);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await apiRequest("POST", "/api/auth/reset-password", { token, password });
      setDone(true);
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? message(caught.failure) : message({ message: t("common.error") })
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <Card title={t("reset.title")}>
      <form className="space-y-4" onSubmit={onSubmit}>
        {error ? <Alert tone="error">{error}</Alert> : null}
        {done ? (
          <Alert tone="success">
            {t("reset.done")} <Link to="/login" className="underline">{t("nav.login")}</Link>
          </Alert>
        ) : null}
        {!token ? (
          <Alert tone="error">{t("reset.missingToken")}</Alert>
        ) : (
          <Field
            label={t("signup.password")}
            name="password"
            type="password"
            autoComplete="new-password"
            required
            help={t("signup.passwordHelp")}
            value={password}
            onChange={setPassword}
          />
        )}
        <SubmitButton pending={pending} disabled={!token}>
          {t("reset.submit")}
        </SubmitButton>
      </form>
    </Card>
  );
}
