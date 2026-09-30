import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";

import { Alert, Card, Field, SubmitButton, useErrorMessage } from "~/components/ui";
import { useI18n } from "~/i18n";
import { ApiClientError, apiRequest } from "~/lib/api-client";

export const Route = createFileRoute("/signup")({
  component: Signup,
});

interface RegisterResponse {
  user: { id: string; email: string };
  organization: { id: string; name: string } | null;
  emailVerification: { emailSent: boolean; token: string; link: string; expiresAt: string };
}

function Signup() {
  const { t } = useI18n();
  const message = useErrorMessage();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<RegisterResponse | null>(null);

  useEffect(() => {
    if (created) {
      // Nothing to do: the session cookie is already set by the API response.
    }
  }, [created]);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      const response = await apiRequest<RegisterResponse>("POST", "/api/auth/register", {
        email,
        password,
        ...(fullName ? { fullName } : {}),
        ...(organizationName ? { organizationName } : {}),
      });
      setCreated(response);
    } catch (caught) {
      setError(
        caught instanceof ApiClientError
          ? message(caught.failure)
          : message({ message: t("common.error") })
      );
    } finally {
      setPending(false);
    }
  }

  if (created) {
    return (
      <Card title={t("signup.success")}>
        <div className="space-y-4">
          <Alert tone="success">{created.user.email}</Alert>
          <Alert tone="info">{t("signup.verificationNotice")}</Alert>
          <div className="space-y-1 text-sm">
            <span className="block text-slate-300">{t("signup.verificationLink")}</span>
            <code className="block overflow-x-auto rounded bg-slate-900 px-3 py-2 text-xs text-sky-300">
              {created.emailVerification.link}
            </code>
          </div>
          <div className="flex flex-wrap gap-3">
            <a
              href={created.emailVerification.link}
              className="rounded bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500"
            >
              {t("signup.goToVerification")}
            </a>
            <Link
              to="/app"
              className="rounded border border-white/20 px-4 py-2 text-sm text-slate-200 hover:border-white/40"
            >
              {t("nav.app")}
            </Link>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <Card title={t("signup.title")}>
      <form className="space-y-4" onSubmit={onSubmit}>
        <p className="text-sm text-slate-400">{t("signup.subtitle")}</p>
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
          autoComplete="new-password"
          required
          help={t("signup.passwordHelp")}
          value={password}
          onChange={setPassword}
        />
        <Field
          label={t("signup.fullName")}
          name="fullName"
          autoComplete="name"
          value={fullName}
          onChange={setFullName}
        />
        <Field
          label={t("signup.organizationName")}
          name="organizationName"
          help={t("signup.organizationNameHelp")}
          value={organizationName}
          onChange={setOrganizationName}
        />
        <div className="flex items-center gap-4">
          <SubmitButton pending={pending}>{t("signup.submit")}</SubmitButton>
          <Link to="/login" className="text-sm text-sky-400 hover:text-sky-300">
            {t("signup.haveAccount")} {t("nav.login")}
          </Link>
        </div>
      </form>
    </Card>
  );
}
