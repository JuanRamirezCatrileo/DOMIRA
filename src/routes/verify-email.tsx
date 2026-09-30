import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";

import { Alert, Card, Field, SubmitButton, useErrorMessage } from "~/components/ui";
import { useI18n } from "~/i18n";
import { ApiClientError, apiRequest } from "~/lib/api-client";

export const Route = createFileRoute("/verify-email")({
  component: VerifyEmail,
});

function VerifyEmail() {
  const { t } = useI18n();
  const message = useErrorMessage();
  const [token, setToken] = useState("");
  const [pending, setPending] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const fromLink = params.get("token");
    if (fromLink) setToken(fromLink);
  }, []);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await apiRequest("POST", "/api/auth/verify-email", { token });
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
    <Card title={t("verify.title")}>
      <form className="space-y-4" onSubmit={onSubmit}>
        {error ? <Alert tone="error">{error}</Alert> : null}
        {done ? (
          <Alert tone="success">
            {t("verify.done")} <Link to="/app" className="underline">{t("nav.app")}</Link>
          </Alert>
        ) : null}
        <Field
          label={t("signup.verificationLink")}
          name="token"
          required
          value={token}
          onChange={setToken}
        />
        <SubmitButton pending={pending}>{t("verify.submit")}</SubmitButton>
      </form>
    </Card>
  );
}
