/**
 * Shared UI primitives. No user-facing string is ever hardcoded here: text comes
 * from useI18n().
 */
import { Link, useNavigate } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { useState } from "react";

import { useI18n, type Locale } from "~/i18n";
import { apiRequest } from "~/lib/api-client";

export function Shell({ children }: { children: ReactNode }) {
  const { t } = useI18n();
  return (
    <div className="flex min-h-dvh flex-col bg-slate-950 text-slate-100">
      <header className="border-b border-white/10">
        <nav className="mx-auto flex max-w-5xl flex-wrap items-center gap-4 px-6 py-4">
          <Link to="/" className="text-lg font-semibold tracking-tight">
            {t("app.name")}
          </Link>
          <span className="hidden text-sm text-slate-400 sm:inline">{t("app.tagline")}</span>
          <div className="ml-auto flex items-center gap-4 text-sm">
            <Link to="/app" className="text-slate-300 hover:text-white">
              {t("nav.app")}
            </Link>
            <Link to="/login" className="text-slate-300 hover:text-white">
              {t("nav.login")}
            </Link>
            <Link to="/signup" className="text-slate-300 hover:text-white">
              {t("nav.signup")}
            </Link>
            <LanguageSwitcher />
          </div>
        </nav>
      </header>
      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-10">{children}</main>
      <footer className="border-t border-white/10 px-6 py-6 text-center text-xs text-slate-500">
        {t("footer.note")}
      </footer>
    </div>
  );
}

export function LanguageSwitcher() {
  const { locale, setLocale, t } = useI18n();
  return (
    <label className="flex items-center gap-1 text-slate-400">
      <span className="sr-only">{t("nav.language")}</span>
      <select
        aria-label={t("nav.language")}
        value={locale}
        onChange={(event) => setLocale(event.target.value as Locale)}
        className="rounded border border-white/20 bg-slate-900 px-2 py-1 text-xs"
      >
        <option value="es">ES</option>
        <option value="en">EN</option>
      </select>
    </label>
  );
}

export function Card({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <section className="rounded-lg border border-white/10 bg-white/5 p-6">
      {title ? <h2 className="mb-4 text-base font-semibold">{title}</h2> : null}
      {children}
    </section>
  );
}

export function Alert({ tone, children }: { tone: "error" | "success" | "info"; children: ReactNode }) {
  const tones = {
    error: "border-red-500/40 bg-red-500/10 text-red-100",
    success: "border-emerald-500/40 bg-emerald-500/10 text-emerald-100",
    info: "border-sky-500/40 bg-sky-500/10 text-sky-100",
  } as const;
  return (
    <div role="status" className={`rounded border px-4 py-3 text-sm ${tones[tone]}`}>
      {children}
    </div>
  );
}

export function Field({
  label,
  name,
  type = "text",
  autoComplete,
  required,
  help,
  value,
  onChange,
}: {
  label: string;
  name: string;
  type?: string;
  autoComplete?: string;
  required?: boolean;
  help?: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block text-slate-300">{label}</span>
      <input
        name={name}
        type={type}
        autoComplete={autoComplete}
        required={required}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="w-full rounded border border-white/20 bg-slate-900 px-3 py-2 text-slate-100 outline-none focus:border-sky-500"
      />
      {help ? <span className="mt-1 block text-xs text-slate-400">{help}</span> : null}
    </label>
  );
}

export function SubmitButton({
  children,
  pending,
  disabled,
  type = "submit",
  onClick,
}: {
  children: ReactNode;
  pending?: boolean;
  disabled?: boolean;
  type?: "submit" | "button";
  onClick?: () => void;
}) {
  const { t } = useI18n();
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled ?? pending}
      className="rounded bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
    >
      {pending ? t("common.working") : children}
    </button>
  );
}

/**
 * Maps an API failure to a translated message. The server message is used as-is
 * when it already explains the situation; the code drives the friendly fallback.
 */
export function useErrorMessage() {
  const { t } = useI18n();
  return (failure: { code?: string; message?: string; status?: number }): string => {
    switch (failure.code) {
      case "DATABASE_UNAVAILABLE":
        return t("error.database");
      case "RATE_LIMITED":
        return t("error.rateLimited");
      case "UNAUTHENTICATED":
        return t("error.unauthorized");
      case "FORBIDDEN":
        return failure.message ? failure.message : t("error.forbidden");
      case "CONFLICT":
        return failure.message ? failure.message : t("error.conflict");
      case "VALIDATION_ERROR":
        return failure.message ? failure.message : t("error.validation");
      default:
        return failure.message || t("common.error");
    }
  };
}

/** A section that is deliberately not built yet — labelled, never faked. */
export function NotYet({ title, items }: { title: string; items: string[] }) {
  const { t } = useI18n();
  return (
    <Card title={title}>
      <ul className="space-y-2 text-sm text-slate-300">
        {items.map((item) => (
          <li key={item} className="flex gap-2">
            <span className="rounded bg-slate-700 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-slate-300">
              {t("common.notImplemented")}
            </span>
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

export function LogoutButton() {
  const { t } = useI18n();
  const navigate = useNavigate();
  const [pending, setPending] = useState(false);
  return (
    <SubmitButton
      type="button"
      pending={pending}
      onClick={async () => {
        setPending(true);
        try {
          await apiRequest("POST", "/api/auth/logout");
        } finally {
          setPending(false);
          await navigate({ to: "/" });
        }
      }}
    >
      {t("nav.logout")}
    </SubmitButton>
  );
}
