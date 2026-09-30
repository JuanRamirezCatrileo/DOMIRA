import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";

import { Alert, Card, Field, SubmitButton, useErrorMessage } from "~/components/ui";
import { useI18n } from "~/i18n";
import { ApiClientError, apiRequest } from "~/lib/api-client";

export const Route = createFileRoute("/forgot-password")({
  component: ForgotPassword,
});

function ForgotPassword() {
  const { t } = useI18n();
  const message = useErrorMessage();
  const [email, setEmail] = useState("");
  const [pending, setPending] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await apiRequest("POST", "/api/auth/forgot-password", { email });
      setSent(true);
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? message(caught.failure) : message({ message: t("common.error") })
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <Card title={t("forgot.title")}>
      <form className="space-y-4" onSubmit={onSubmit}>
        <p className="text-sm text-slate-400">{t("forgot.help")}</p>
        {error ? <Alert tone="error">{error}</Alert> : null}
        {sent ? <Alert tone="success">{t("forgot.sent")}</Alert> : null}
        <Field
          label={t("signup.email")}
          name="email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={setEmail}
        />
        <SubmitButton pending={pending}>{t("forgot.submit")}</SubmitButton>
      </form>
    </Card>
  );
}
