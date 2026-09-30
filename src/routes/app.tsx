import { createFileRoute, Link } from "@tanstack/react-router";
import { useCallback, useEffect, useState } from "react";

import {
  Alert,
  Card,
  Field,
  LogoutButton,
  NotYet,
  SubmitButton,
  useErrorMessage,
} from "~/components/ui";
import { useI18n } from "~/i18n";
import { ApiClientError, apiRequest } from "~/lib/api-client";

export const Route = createFileRoute("/app")({
  component: AppDashboard,
});

interface MeResponse {
  user: {
    id: string;
    email: string;
    fullName: string | null;
    isSuperAdmin: boolean;
    emailVerified: boolean;
  };
  memberships: Array<{ organizationId: string; name: string; slug: string; role: string }>;
}

interface OrganizationResponse {
  organization: { id: string; name: string; slug: string; status: string; createdAt: string };
  role: string;
  permissions: string[];
  counts: {
    members: number;
    domains: number;
    scans: number;
    openFindings: number;
    openAlerts: number;
  };
}

interface Member {
  membershipId: string;
  userId: string;
  email: string;
  fullName: string | null;
  role: string;
  joinedAt: string;
  emailVerified: boolean;
}

type LoadState = "loading" | "anonymous" | "no-organization" | "ready" | "error";

function AppDashboard() {
  const { t } = useI18n();
  const message = useErrorMessage();
  const [state, setState] = useState<LoadState>("loading");
  const [me, setMe] = useState<MeResponse | null>(null);
  const [organization, setOrganization] = useState<OrganizationResponse | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const meResponse = await apiRequest<MeResponse>("GET", "/api/me");
      setMe(meResponse);
      if (meResponse.memberships.length === 0) {
        setState("no-organization");
        return;
      }
      const organizationId = meResponse.memberships[0]!.organizationId;
      const [organizationResponse, membersResponse] = await Promise.all([
        apiRequest<OrganizationResponse>("GET", `/api/organizations/${organizationId}`),
        apiRequest<{ members: Member[] }>("GET", `/api/organizations/${organizationId}/members`),
      ]);
      setOrganization(organizationResponse);
      setMembers(membersResponse.members);
      setState("ready");
    } catch (caught) {
      if (caught instanceof ApiClientError && caught.failure.status === 401) {
        setState("anonymous");
        return;
      }
      setError(caught instanceof ApiClientError ? message(caught.failure) : t("common.error"));
      setState("error");
    }
  }, [message, t]);

  useEffect(() => {
    void load();
  }, [load]);

  if (state === "loading") {
    return <Card>{t("app.loading")}</Card>;
  }

  if (state === "anonymous") {
    return (
      <Card>
        <p className="text-sm text-slate-300">{t("app.noSession")}</p>
        <div className="mt-4 flex gap-3">
          <Link to="/login" className="rounded bg-sky-600 px-4 py-2 text-sm text-white">
            {t("nav.login")}
          </Link>
          <Link to="/signup" className="rounded border border-white/20 px-4 py-2 text-sm">
            {t("nav.signup")}
          </Link>
        </div>
      </Card>
    );
  }

  if (state === "error") {
    return (
      <Card>
        <Alert tone="error">{error ?? t("common.error")}</Alert>
        <div className="mt-4">
          <SubmitButton type="button" onClick={() => void load()}>
            {t("common.retry")}
          </SubmitButton>
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">{organization?.organization.name ?? t("app.title")}</h1>
        {organization ? (
          <span className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-300">
            {t("app.role")}: {organization.role}
          </span>
        ) : null}
        <span className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-300">{me?.user.email}</span>
        <div className="ml-auto">
          <LogoutButton />
        </div>
      </div>

      {notice ? <Alert tone="success">{notice}</Alert> : null}
      {error ? <Alert tone="error">{error}</Alert> : null}

      {state === "no-organization" ? (
        <CreateOrganization
          onCreated={async (created) => {
            setNotice(created);
            await load();
          }}
        />
      ) : null}

      {organization ? (
        <Card title={t("app.counts")}>
          <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-5">
            <Count label={t("app.count.members")} value={organization.counts.members} />
            <Count label={t("app.count.domains")} value={organization.counts.domains} />
            <Count label={t("app.count.scans")} value={organization.counts.scans} />
            <Count label={t("app.count.openFindings")} value={organization.counts.openFindings} />
            <Count label={t("app.count.openAlerts")} value={organization.counts.openAlerts} />
          </dl>
        </Card>
      ) : null}

      {organization ? (
        <MembersSection
          organizationId={organization.organization.id}
          role={organization.role}
          members={members}
          onChanged={async (messageKey) => {
            setNotice(messageKey);
            await load();
          }}
          selfUserId={me?.user.id ?? ""}
        />
      ) : null}

      <NotYet
        title={t("app.notYet.title")}
        items={[
          t("app.notYet.domains"),
          t("app.notYet.scanning"),
          t("app.notYet.findings"),
          t("app.notYet.alerts"),
          t("app.notYet.reports"),
          t("app.notYet.billing"),
        ]}
      />

      {me?.user.isSuperAdmin ? <PlatformAdmin /> : null}
    </div>
  );
}

function Count({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-slate-400">{label}</dt>
      <dd className="text-lg font-semibold text-slate-100">{value}</dd>
    </div>
  );
}

function CreateOrganization({ onCreated }: { onCreated: (message: string) => Promise<void> }) {
  const { t } = useI18n();
  const message = useErrorMessage();
  const [name, setName] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <Card title={t("app.createOrganization")}>
      <form
        className="space-y-4"
        onSubmit={async (event) => {
          event.preventDefault();
          setPending(true);
          setError(null);
          try {
            await apiRequest("POST", "/api/organizations", { name });
            await onCreated(t("app.create"));
          } catch (caught) {
            setError(
              caught instanceof ApiClientError
                ? message(caught.failure)
                : message({ message: t("common.error") })
            );
          } finally {
            setPending(false);
          }
        }}
      >
        {error ? <Alert tone="error">{error}</Alert> : null}
        <p className="text-sm text-slate-400">{t("app.noOrganization")}</p>
        <Field
          label={t("app.organizationName")}
          name="name"
          required
          value={name}
          onChange={setName}
        />
        <SubmitButton pending={pending}>{t("app.create")}</SubmitButton>
      </form>
    </Card>
  );
}

function MembersSection({
  organizationId,
  role,
  members,
  onChanged,
  selfUserId,
}: {
  organizationId: string;
  role: string;
  members: Member[];
  onChanged: (message: string) => Promise<void>;
  selfUserId: string;
}) {
  const { t } = useI18n();
  const message = useErrorMessage();
  const canManage = role === "ADMIN" || role === "SUPER_ADMIN";
  const [email, setEmail] = useState("");
  const [newRole, setNewRole] = useState("MEMBER");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(action: () => Promise<void>, successKey: string) {
    setPending(true);
    setError(null);
    try {
      await action();
      await onChanged(t(successKey as never));
    } catch (caught) {
      setError(
        caught instanceof ApiClientError ? message(caught.failure) : message({ message: t("common.error") })
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <Card title={t("app.members")}>
      {error ? <Alert tone="error">{error}</Alert> : null}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="py-2">{t("signup.email")}</th>
              <th className="py-2">{t("app.member.role")}</th>
              <th className="py-2">{t("app.member.verified")}</th>
              <th className="py-2">{t("app.member.joined")}</th>
              {canManage ? <th className="py-2" /> : null}
            </tr>
          </thead>
          <tbody>
            {members.length === 0 ? (
              <tr>
                <td className="py-3 text-slate-400" colSpan={canManage ? 5 : 4}>
                  {t("app.members.empty")}
                </td>
              </tr>
            ) : null}
            {members.map((member) => (
              <tr key={member.membershipId} className="border-t border-white/10">
                <td className="py-2">{member.email}</td>
                <td className="py-2">
                  {canManage && member.userId !== selfUserId ? (
                    <select
                      aria-label={t("app.member.role")}
                      value={member.role}
                      disabled={pending}
                      onChange={(event) =>
                        void run(
                          async () => {
                            await apiRequest(
                              "PATCH",
                              `/api/organizations/${organizationId}/members/${member.userId}`,
                              { role: event.target.value }
                            );
                          },
                          "app.member.updated"
                        )
                      }
                      className="rounded border border-white/20 bg-slate-900 px-2 py-1 text-xs"
                    >
                      <option value="ADMIN">ADMIN</option>
                      <option value="MEMBER">MEMBER</option>
                      <option value="VIEWER">VIEWER</option>
                    </select>
                  ) : (
                    <span className="text-slate-300">{member.role}</span>
                  )}
                </td>
                <td className="py-2 text-slate-400">
                  {member.emailVerified ? "✓" : "—"}
                </td>
                <td className="py-2 text-slate-400">
                  {new Date(member.joinedAt).toISOString().slice(0, 10)}
                </td>
                {canManage ? (
                  <td className="py-2 text-right">
                    {member.userId !== selfUserId ? (
                      <button
                        type="button"
                        disabled={pending}
                        onClick={() =>
                          void run(async () => {
                            await apiRequest(
                              "DELETE",
                              `/api/organizations/${organizationId}/members/${member.userId}`
                            );
                          }, "app.member.removed")
                        }
                        className="text-xs text-red-300 hover:text-red-200 disabled:opacity-50"
                      >
                        {t("app.member.remove")}
                      </button>
                    ) : null}
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {canManage ? (
        <form
          className="mt-6 space-y-3 border-t border-white/10 pt-4"
          onSubmit={async (event) => {
            event.preventDefault();
            await run(async () => {
              await apiRequest("POST", `/api/organizations/${organizationId}/members`, {
                email,
                role: newRole,
              });
              setEmail("");
            }, "app.member.added");
          }}
        >
          <p className="text-xs text-slate-400">{t("app.member.addHelp")}</p>
          <div className="grid gap-3 sm:grid-cols-[2fr_1fr_auto] sm:items-end">
            <Field
              label={t("app.member.email")}
              name="memberEmail"
              type="email"
              required
              value={email}
              onChange={setEmail}
            />
            <label className="block text-sm">
              <span className="mb-1 block text-slate-300">{t("app.member.role")}</span>
              <select
                aria-label={t("app.member.role")}
                value={newRole}
                onChange={(event) => setNewRole(event.target.value)}
                className="w-full rounded border border-white/20 bg-slate-900 px-3 py-2 text-slate-100"
              >
                <option value="ADMIN">ADMIN</option>
                <option value="MEMBER">MEMBER</option>
                <option value="VIEWER">VIEWER</option>
              </select>
            </label>
            <SubmitButton pending={pending}>{t("app.member.add")}</SubmitButton>
          </div>
        </form>
      ) : null}
    </Card>
  );
}

interface OutboxMessage {
  id: string;
  kind: string;
  toEmail: string;
  subject: string;
  actionUrl: string | null;
  status: string;
  createdAt: string;
}

interface AuditEntry {
  id: string;
  action: string;
  actorEmail: string | null;
  outcome: string;
  createdAt: string;
}

function PlatformAdmin() {
  const { t } = useI18n();
  const [messages, setMessages] = useState<OutboxMessage[]>([]);
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const [outbox, audit] = await Promise.all([
          apiRequest<{ messages: OutboxMessage[] }>("GET", "/api/admin/outbox?limit=20"),
          apiRequest<{ entries: AuditEntry[] }>("GET", "/api/admin/audit?limit=20"),
        ]);
        setMessages(outbox.messages);
        setEntries(audit.entries);
      } catch {
        setError(t("error.forbidden"));
      }
    })();
  }, [t]);

  return (
    <div className="space-y-6">
      <Card title={`${t("app.platform.title")} — ${t("app.platform.outbox")}`}>
        {error ? <Alert tone="error">{error}</Alert> : null}
        <p className="mb-4 text-xs text-slate-400">{t("app.platform.outboxNote")}</p>
        {messages.length === 0 ? (
          <p className="text-sm text-slate-400">{t("app.platform.outbox.empty")}</p>
        ) : (
          <ul className="space-y-3 text-sm">
            {messages.map((entry) => (
              <li key={entry.id} className="rounded border border-white/10 p-3">
                <div className="flex flex-wrap gap-2 text-xs text-slate-400">
                  <span className="rounded bg-slate-800 px-1.5 py-0.5">{entry.kind}</span>
                  <span>{entry.toEmail}</span>
                  <span>{entry.status}</span>
                  <span>{new Date(entry.createdAt).toISOString().slice(0, 19).replace("T", " ")}</span>
                </div>
                {entry.actionUrl ? (
                  <a href={entry.actionUrl} className="mt-2 block break-all text-xs text-sky-400">
                    {entry.actionUrl}
                  </a>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title={`${t("app.platform.title")} — ${t("app.audit.title")}`}>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="py-2">{t("app.audit.date")}</th>
                <th className="py-2">{t("app.audit.action")}</th>
                <th className="py-2">{t("app.audit.actor")}</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.id} className="border-t border-white/10">
                  <td className="py-2 text-slate-400">
                    {new Date(entry.createdAt).toISOString().slice(0, 19).replace("T", " ")}
                  </td>
                  <td className="py-2">{entry.action}</td>
                  <td className="py-2 text-slate-400">{entry.actorEmail ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
