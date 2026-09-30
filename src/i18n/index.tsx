/**
 * i18n: locale resolution + `t()` helper.
 *
 * Resolution order: the `domira_locale` cookie (what the user chose) → the browser
 * language → Spanish (the owner's default). No component contains a literal
 * user-facing string; everything comes from src/i18n/dictionaries.ts.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { dictionaries, LOCALES, type Locale, type TranslationKey } from "./dictionaries";

export { LOCALES, dictionaries };
export type { Locale, TranslationKey };

const LOCALE_COOKIE = "domira_locale";

export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (LOCALES as readonly string[]).includes(value);
}

export function readLocaleCookie(): Locale | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp(`(?:^|; )${LOCALE_COOKIE}=([^;]*)`));
  return match ? (isLocale(match[1]) ? match[1] : null) : null;
}

function detectLocale(): Locale {
  const fromCookie = readLocaleCookie();
  if (fromCookie) return fromCookie;
  if (typeof navigator !== "undefined") {
    const languages = navigator.languages?.length ? navigator.languages : [navigator.language];
    for (const language of languages) {
      if (typeof language === "string" && language.toLowerCase().startsWith("en")) return "en";
    }
  }
  return "es";
}

export interface I18nValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: (key: TranslationKey, values?: Record<string, string | number>) => string;
}

export const I18nContext = createContext<I18nValue | null>(null);

export function translate(
  locale: Locale,
  key: TranslationKey,
  values?: Record<string, string | number>
): string {
  const table = dictionaries[locale] as Record<string, string>;
  const fallback = dictionaries.es as Record<string, string>;
  let text = table[key] ?? fallback[key] ?? key;
  if (values) {
    for (const [name, value] of Object.entries(values)) {
      text = text.replaceAll(`{${name}}`, String(value));
    }
  }
  return text;
}

export function useI18n(): I18nValue {
  const value = useContext(I18nContext);
  if (!value) throw new Error("useI18n must be used inside <I18nProvider>");
  return value;
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>("es");

  useEffect(() => {
    setLocaleState(detectLocale());
  }, []);

  useEffect(() => {
    if (typeof document !== "undefined") document.documentElement.lang = locale;
  }, [locale]);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    if (typeof document !== "undefined") {
      const secure = window.location.protocol === "https:" ? "; Secure" : "";
      document.cookie = `${LOCALE_COOKIE}=${next}; Path=/; Max-Age=31536000; SameSite=Lax${secure}`;
    }
  }, []);

  const value = useMemo<I18nValue>(
    () => ({
      locale,
      setLocale,
      t: (key, values) => translate(locale, key, values),
    }),
    [locale, setLocale]
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}
