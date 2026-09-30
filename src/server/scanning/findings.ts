/**
 * The finding catalogue and the rules that turn raw check results into rows in
 * `findings`.
 *
 * Every finding carries: a stable machine `code` (unique per domain while it is
 * open — enforced by `findings_domain_code_open_key`), a severity, a category, the
 * technical description and the plain-language trio in ES and EN that follows
 * "what happens → why it matters → what you can do".
 *
 * Lifecycle rule (deliverable 2a): a finding that reappears is UPDATED (last_seen,
 * occurrences, evidence, scan id) and its human status — new / acknowledged /
 * resolved / ignored — is preserved. DOMIRA never silently closes or reopens a
 * human decision; re-resolution belongs to deliverable 4.
 */
import type { QueryRunner } from "~/db";

import type { Category, MethodologyConfig } from "./methodology";
import type { TlsProbeResult } from "./tls";
import type { AvailabilityProbeResult } from "./availability";
import type { DnsAnswer } from "./dns";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface FindingDefinition {
  code: string;
  category: Category;
  severity: Severity;
  titleEs: string;
  titleEn: string;
  simpleEs: string;
  simpleEn: string;
  impactEs: string;
  impactEn: string;
  recommendationEs: string;
  recommendationEn: string;
}

/** The complete catalogue for deliverable 2a. Codes are stable and documented. */
export const FINDING_CATALOGUE: FindingDefinition[] = [
  {
    code: "tls.handshake_failed",
    category: "tls",
    severity: "critical",
    titleEs: "No se pudo establecer TLS en el puerto 443",
    titleEn: "TLS could not be established on port 443",
    simpleEs:
      "DOMIRA intentó una conexión TLS al puerto 443 del dominio y no obtuvo ninguna respuesta válida. " +
      "Esto significa que el cifrado que protege a los visitantes no está funcionando ahora mismo.",
    simpleEn:
      "DOMIRA attempted a TLS connection to port 443 and got no valid response. " +
      "That means the encryption protecting your visitors is not working right now.",
    impactEs:
      "Los navegadores avisarán a los visitantes de que el sitio no es seguro y los datos pueden viajar sin cifrar.",
    impactEn:
      "Browsers will warn visitors that the site is not secure, and data may travel unencrypted.",
    recommendationEs:
      "Comprueba que el servicio escucha en 443, que el certificado está instalado y que el cortafuegos permite el tráfico TLS.",
    recommendationEn:
      "Check that the service listens on port 443, that a certificate is installed and that the firewall allows TLS traffic.",
  },
  {
    code: "tls.legacy_protocol",
    category: "tls",
    severity: "high",
    titleEs: "TLS obsoleto (TLS 1.0/1.1)",
    titleEn: "Obsolete TLS (TLS 1.0/1.1)",
    simpleEs:
      "El servidor negoció una versión de cifrado muy antigua (TLS 1.0 o 1.1) en lugar de una actual.",
    simpleEn:
      "The server negotiated a very old encryption version (TLS 1.0 or 1.1) instead of a current one.",
    impactEs:
      "Las versiones antiguas de TLS tienen debilidades conocidas y ya no están permitidas por los estándares de pago y navegadores.",
    impactEn:
      "Old TLS versions have known weaknesses and are no longer allowed by payment standards or browsers.",
    recommendationEs:
      "Configura el servidor para ofrecer únicamente TLS 1.2 y TLS 1.3 y desactiva 1.0/1.1.",
    recommendationEn: "Configure the server to offer only TLS 1.2 and TLS 1.3, and disable 1.0/1.1.",
  },
  {
    code: "tls.outdated_protocol",
    category: "tls",
    severity: "low",
    titleEs: "El servidor negocia TLS 1.2",
    titleEn: "The server negotiates TLS 1.2",
    simpleEs: "La conexión usa TLS 1.2, que sigue siendo aceptable pero no es la versión más reciente.",
    simpleEn: "The connection uses TLS 1.2, which is still acceptable but not the newest version.",
    impactEs: "TLS 1.3 ofrece un cifrado más simple y moderno; TLS 1.2 sigue siendo seguro hoy.",
    impactEn: "TLS 1.3 offers a simpler, more modern cipher suite; TLS 1.2 remains secure today.",
    recommendationEs: "Habilita TLS 1.3 en el servidor cuando tu plataforma lo permita.",
    recommendationEn: "Enable TLS 1.3 on the server where your platform supports it.",
  },
  {
    code: "certificate.expired",
    category: "certificate",
    severity: "critical",
    titleEs: "El certificado está caducado",
    titleEn: "The certificate has expired",
    simpleEs: "El certificado del dominio dejó de ser válido. Los navegadores lo rechazan en lugar de mostrar el sitio.",
    simpleEn: "The domain's certificate is no longer valid. Browsers reject it instead of showing the site.",
    impactEs: "Los visitantes ven una pantalla de advertencia y muchos se van; las integraciones que comprueban el certificado fallan.",
    impactEn: "Visitors see a warning screen and many leave; integrations that validate the certificate fail.",
    recommendationEs: "Renueva el certificado hoy y automatiza la renovación (por ejemplo con ACME/Let's Encrypt).",
    recommendationEn: "Renew the certificate today and automate renewal (for example with ACME/Let's Encrypt).",
  },
  {
    code: "certificate.expiring_soon",
    category: "certificate",
    severity: "high",
    titleEs: "El certificado caduca en menos de 30 días",
    titleEn: "The certificate expires in less than 30 days",
    simpleEs: "Al certificado le quedan pocos días de validez; si caduca, el sitio pasará a mostrar avisos.",
    simpleEn: "The certificate has only a few days of validity left; when it expires the site will start showing warnings.",
    impactEs: "Una caducidad inesperada produce caídas visibles, avisos de navegador y pérdida de confianza.",
    impactEn: "An unexpected expiry causes visible outages, browser warnings and lost trust.",
    recommendationEs: "Renueva el certificado ahora y configura la renovación automática.",
    recommendationEn: "Renew the certificate now and set up automatic renewal.",
  },
  {
    code: "certificate.expiring_warning",
    category: "certificate",
    severity: "medium",
    titleEs: "El certificado caduca en menos de 60 días",
    titleEn: "The certificate expires in less than 60 days",
    simpleEs: "El certificado todavía es válido, pero conviene planificar su renovación.",
    simpleEn: "The certificate is still valid, but its renewal should be planned.",
    impactEs: "Sin una renovación planificada el servicio puede caducar en un momento inoportuno.",
    impactEn: "Without planned renewal the service can expire at an inconvenient moment.",
    recommendationEs: "Programa la renovación y verifica que el proceso automático existe.",
    recommendationEn: "Schedule the renewal and verify that the automated process exists.",
  },
  {
    code: "certificate.hostname_mismatch",
    category: "certificate",
    severity: "critical",
    titleEs: "El certificado no cubre este dominio",
    titleEn: "The certificate does not cover this domain",
    simpleEs: "El certificado que responde no incluye el nombre del dominio, así que los navegadores no lo aceptan como válido.",
    simpleEn: "The certificate that answers does not include the domain name, so browsers do not accept it as valid.",
    impactEs: "Los visitantes reciben un aviso de seguridad aunque el cifrado funcione.",
    impactEn: "Visitors get a security warning even though encryption works.",
    recommendationEs: "Emite un certificado que incluya este dominio (y sus subdominios) y vuelve a desplegarlo.",
    recommendationEn: "Issue a certificate that includes this domain (and its subdomains) and redeploy it.",
  },
  {
    code: "certificate.chain_invalid",
    category: "certificate",
    severity: "high",
    titleEs: "La cadena del certificado no es de confianza",
    titleEn: "The certificate chain is not trusted",
    simpleEs: "Un cliente TLS que valida el certificado correctamente rechazó la conexión: falta o está mal algún eslabón de la cadena.",
    simpleEn: "A TLS client that validates certificates properly refused the connection: a link in the chain is missing or wrong.",
    impactEs: "Algunos clientes (móviles, APIs, otros servidores) rechazan la conexión aunque el certificado esté vigente.",
    impactEn: "Some clients (mobile apps, APIs, other servers) refuse the connection even when the certificate is current.",
    recommendationEs: "Instala la cadena intermedia completa que entrega tu emisor y comprueba desde varios clientes.",
    recommendationEn: "Install the complete intermediate chain your issuer provides and check from several clients.",
  },
  {
    code: "certificate.self_signed",
    category: "certificate",
    severity: "high",
    titleEs: "Certificado autofirmado",
    titleEn: "Self-signed certificate",
    simpleEs: "El certificado lo firma el propio servidor, no una autoridad en la que confíen los navegadores.",
    simpleEn: "The certificate is signed by the server itself, not by an authority browsers trust.",
    impactEs: "Ningún cliente lo acepta sin una excepción manual; no sirve para un sitio público.",
    impactEn: "No client accepts it without a manual exception; it is not usable for a public site.",
    recommendationEs: "Emite un certificado de una autoridad de confianza (Let's Encrypt es gratuito) y sustitúyelo.",
    recommendationEn: "Issue a certificate from a trusted authority (Let's Encrypt is free) and replace it.",
  },
  {
    code: "certificate.weak_key",
    category: "certificate",
    severity: "high",
    titleEs: "Clave criptográfica débil",
    titleEn: "Weak cryptographic key",
    simpleEs: "El certificado usa una clave más corta de lo que se considera seguro hoy (RSA de menos de 2048 bits o curvas muy pequeñas).",
    simpleEn: "The certificate uses a key shorter than what is considered safe today (RSA under 2048 bits or very small curves).",
    impactEs: "Una clave corta es más fácil de romper con recursos de computación actuales.",
    impactEn: "A short key is easier to break with today's computing resources.",
    recommendationEs: "Genera una clave nueva de al menos 2048 bits (RSA) o 256 bits (ECDSA) y reemite el certificado.",
    recommendationEn: "Generate a new key of at least 2048 bits (RSA) or 256 bits (ECDSA) and reissue the certificate.",
  },
  {
    code: "dns.not_resolving",
    category: "dns",
    severity: "critical",
    titleEs: "El dominio no resuelve",
    titleEn: "The domain does not resolve",
    simpleEs: "Las consultas DNS públicas no devuelven ninguna respuesta para este dominio.",
    simpleEn: "Public DNS queries return no answer at all for this domain.",
    impactEs: "Si el DNS no responde, nadie encuentra el sitio ni el correo: es una caída total, no un problema parcial.",
    impactEn: "If DNS does not answer, nobody finds the site or the e-mail: that is a complete outage, not a partial one.",
    recommendationEs: "Comprueba la delegación del dominio, los servidores NS y que la zona siga publicada.",
    recommendationEn: "Check the domain delegation, its NS servers and that the zone is still published.",
  },
  {
    code: "dns.no_a_record",
    category: "dns",
    severity: "high",
    titleEs: "Sin registro A",
    titleEn: "No A record",
    simpleEs: "El dominio no publica ninguna dirección IPv4 (registro A), así que los navegadores no tienen a dónde conectarse.",
    simpleEn: "The domain publishes no IPv4 address (A record), so browsers have nowhere to connect.",
    impactEs: "Los visitantes que lleguen por IPv4 no verán el sitio.",
    impactEn: "Visitors arriving over IPv4 will not see the site.",
    recommendationEs: "Publica un registro A con la dirección del servidor web.",
    recommendationEn: "Publish an A record with your web server's address.",
  },
  {
    code: "dns.no_aaaa_record",
    category: "dns",
    severity: "info",
    titleEs: "Sin registro AAAA (IPv6)",
    titleEn: "No AAAA record (IPv6)",
    simpleEs: "El dominio no publica direcciones IPv6, aunque sí puede funcionar por IPv4.",
    simpleEn: "The domain publishes no IPv6 address, though it can still work over IPv4.",
    impactEs: "Los usuarios en redes solo IPv6 no pueden llegar al sitio y pierdes la modernización de infraestructura.",
    impactEn: "Users on IPv6-only networks cannot reach the site and you lose infrastructure modernisation.",
    recommendationEs: "Añade un registro AAAA cuando tu proveedor de hosting lo soporte.",
    recommendationEn: "Add an AAAA record when your hosting provider supports it.",
  },
  {
    code: "dns.no_mx_record",
    category: "dns",
    severity: "info",
    titleEs: "Sin registro MX",
    titleEn: "No MX record",
    simpleEs: "El dominio no publica servidores de correo, así que no puede recibir mensajes.",
    simpleEn: "The domain publishes no mail servers, so it cannot receive messages.",
    impactEs: "Si esperabas recibir correo en este dominio, los mensajes se rechazan y quien te escribe cree que no existes.",
    impactEn: "If you expected to receive mail on this domain, messages are rejected and senders believe you do not exist.",
    recommendationEs: "Añade los registros MX de tu proveedor de correo; si el dominio no debe recibir correo, documenta ese MX nulo.",
    recommendationEn: "Add your mail provider's MX records; if the domain should not receive mail, document the null MX.",
  },
  {
    code: "dns.no_caa_record",
    category: "dns",
    severity: "low",
    titleEs: "Sin registro CAA",
    titleEn: "No CAA record",
    simpleEs: "No hay un registro CAA que indique qué autoridades pueden emitir certificados para este dominio.",
    simpleEn: "No CAA record states which authorities may issue certificates for this domain.",
    impactEs: "Cualquier autoridad podría emitir un certificado para tu dominio si alguien lo solicita de forma indebida.",
    impactEn: "Any authority could issue a certificate for your domain if someone requests one improperly.",
    recommendationEs: "Publica un registro CAA con la autoridad que usas (por ejemplo letsencrypt.org).",
    recommendationEn: "Publish a CAA record for the authority you use (for example letsencrypt.org).",
  },
  {
    code: "availability.unreachable",
    category: "availability",
    severity: "critical",
    titleEs: "El sitio no responde por HTTPS",
    titleEn: "The site does not answer over HTTPS",
    simpleEs: "La petición HTTPS no obtuvo respuesta: el dominio no está sirviendo contenido ahora mismo.",
    simpleEn: "The HTTPS request got no response: the domain is not serving content right now.",
    impactEs: "Los visitantes no pueden usar el sitio y cualquier integración que dependa de él falla.",
    impactEn: "Visitors cannot use the site and any integration depending on it fails.",
    recommendationEs: "Revisa el estado del servidor web, del DNS y del certificado para descartar la causa.",
    recommendationEn: "Check the web server, DNS and certificate state to rule out the cause.",
  },
  {
    code: "availability.server_error",
    category: "availability",
    severity: "high",
    titleEs: "El sitio devuelve un error de servidor (5xx)",
    titleEn: "The site returns a server error (5xx)",
    simpleEs: "El sitio respondió con un código de error de servidor en la portada.",
    simpleEn: "The site answered with a server error code on the home page.",
    impactEs: "Los visitantes ven una página de error y el negocio no puede atenderles.",
    impactEn: "Visitors see an error page and the business cannot serve them.",
    recommendationEs: "Revisa los registros del servidor de aplicaciones y la disponibilidad de sus dependencias.",
    recommendationEn: "Check the application server logs and the availability of its dependencies.",
  },
  {
    code: "availability.client_error",
    category: "availability",
    severity: "medium",
    titleEs: "La portada devuelve un error de cliente (4xx)",
    titleEn: "The home page returns a client error (4xx)",
    simpleEs: "La raíz del dominio responde con un código 4xx a una petición estándar.",
    simpleEn: "The domain root answers a standard request with a 4xx code.",
    impactEs: "Un visitante nuevo puede recibir un error al entrar, aunque otras rutas funcionen.",
    impactEn: "A new visitor may hit an error on entry, even if other paths work.",
    recommendationEs: "Comprueba qué devuelve / para un visitante anónimo y ajusta la regla que lo bloquea.",
    recommendationEn: "Check what / returns for an anonymous visitor and adjust the rule blocking it.",
  },
  {
    code: "availability.no_https_redirect",
    category: "availability",
    severity: "medium",
    titleEs: "HTTP no redirige a HTTPS",
    titleEn: "HTTP does not redirect to HTTPS",
    simpleEs: "El puerto 80 sirve contenido en claro en lugar de redirigir a la versión cifrada.",
    simpleEn: "Port 80 serves content in the clear instead of redirecting to the encrypted version.",
    impactEs: "Quien abra el enlace http:// viaja sin cifrar y queda expuesto a interceptación.",
    impactEn: "Anyone opening the http:// link travels unencrypted and can be intercepted.",
    recommendationEs: "Configura una redirección 301 permanente de http:// a https:// y activa HSTS.",
    recommendationEn: "Configure a permanent 301 redirect from http:// to https:// and enable HSTS.",
  },
  {
    code: "availability.slow_response",
    category: "availability",
    severity: "low",
    titleEs: "Respuesta lenta",
    titleEn: "Slow response",
    simpleEs: "La portada tardó entre 1,5 y 3 segundos en responder, más de lo recomendable.",
    simpleEn: "The home page took between 1.5 and 3 seconds to respond, more than recommended.",
    impactEs: "Los visitantes abandonan antes y los buscadores penalizan la lentitud.",
    impactEn: "Visitors leave sooner and search engines penalise slowness.",
    recommendationEs: "Revisa caché, tamaño de respuesta y latencia del servidor o del CDN.",
    recommendationEn: "Review caching, response size and server or CDN latency.",
  },
  {
    code: "availability.very_slow_response",
    category: "availability",
    severity: "medium",
    titleEs: "Respuesta muy lenta",
    titleEn: "Very slow response",
    simpleEs: "La portada tardó más de 3 segundos en responder.",
    simpleEn: "The home page took more than 3 seconds to respond.",
    impactEs: "Es una experiencia degradada para los visitantes y suele indicar un problema de capacidad.",
    impactEn: "It is a degraded experience for visitors and usually signals a capacity problem.",
    recommendationEs: "Analiza el tiempo de servidor y de base de datos, y añade caché en la capa de borde.",
    recommendationEn: "Analyse server and database time and add caching at the edge layer.",
  },
  {
    code: "scan.refused_private_address",
    category: "availability",
    severity: "info",
    titleEs: "Análisis detenido: dirección no pública",
    titleEn: "Scan stopped: non-public address",
    simpleEs: "El dominio resuelve a una dirección privada, reservada o local, así que DOMIRA no abrió ninguna conexión.",
    simpleEn: "The domain resolves to a private, reserved or local address, so DOMIRA opened no connection.",
    impactEs: "Sin conexión no hay datos de TLS ni de disponibilidad: es una medida de seguridad deliberada, no un fallo.",
    impactEn: "Without a connection there is no TLS or availability data: that is a deliberate safety measure, not a failure.",
    recommendationEs: "Registra dominios con direcciones públicas, o usa un dominio de prueba expuesto por internet.",
    recommendationEn: "Register domains with public addresses, or use a test domain exposed on the internet.",
  },
];

const CATALOGUE_BY_CODE = new Map(FINDING_CATALOGUE.map((entry) => [entry.code, entry]));

export function findingDefinition(code: string): FindingDefinition | null {
  return CATALOGUE_BY_CODE.get(code) ?? null;
}

export interface DnsSnapshot {
  resolved: boolean;
  errorCode: string | null;
  error: string | null;
  answers: DnsAnswer[];
}

export interface ScanInputs {
  hostname: string;
  tls: TlsProbeResult | null;
  dns: DnsSnapshot;
  availability: AvailabilityProbeResult | null;
  refusal: { code: string; message: string; evidence: Record<string, unknown> } | null;
}

export interface DetectedFinding {
  code: string;
  evidence: Record<string, unknown>;
}

function valuesOf(answers: DnsAnswer[], type: string): string[] {
  return answers.filter((answer) => answer.type === type).map((answer) => answer.value);
}

/** Pure detection: raw check results in, finding codes + evidence out. */
export function detectFindings(
  inputs: ScanInputs,
  methodology: MethodologyConfig
): DetectedFinding[] {
  const detected: DetectedFinding[] = [];
  const push = (code: string, evidence: Record<string, unknown> = {}) => {
    if (findingDefinition(code)) detected.push({ code, evidence });
  };

  if (inputs.refusal) {
    push(inputs.refusal.code, inputs.refusal.evidence);
    return detected;
  }

  if (!inputs.dns.resolved) {
    push("dns.not_resolving", { errorCode: inputs.dns.errorCode, error: inputs.dns.error });
  } else {
    if (valuesOf(inputs.dns.answers, "A").length === 0) push("dns.no_a_record");
    if (valuesOf(inputs.dns.answers, "AAAA").length === 0) push("dns.no_aaaa_record");
    if (valuesOf(inputs.dns.answers, "NS").length === 0) push("dns.no_ns_record");
    if (valuesOf(inputs.dns.answers, "MX").length === 0) push("dns.no_mx_record");
    if (valuesOf(inputs.dns.answers, "CAA").length === 0) push("dns.no_caa_record");
  }

  const tls = inputs.tls;
  if (tls && !tls.ok) {
    push("tls.handshake_failed", { errorCode: tls.errorCode, error: tls.error });
  }
  if (tls?.ok) {
    if (tls.protocol === "TLSv1" || tls.protocol === "TLSv1.1") {
      push("tls.legacy_protocol", { protocol: tls.protocol });
    } else if (tls.protocol === "TLSv1.2") {
      push("tls.outdated_protocol", { protocol: tls.protocol });
    }
    const certificate = tls.certificate;
    if (!certificate) {
      push("tls.handshake_failed", { errorCode: "NO_CERTIFICATE", error: "No certificate in the handshake." });
    } else {
      const dropped = certificate.daysRemaining;
      if (dropped !== null && dropped < 0) {
        push("certificate.expired", {
          daysRemaining: dropped,
          notAfter: certificate.notAfter,
          issuer: certificate.issuerCn,
        });
      } else if (dropped !== null && dropped <= methodology.thresholds.expiringSoonDays) {
        push("certificate.expiring_soon", { daysRemaining: dropped, notAfter: certificate.notAfter });
      } else if (dropped !== null && dropped <= methodology.thresholds.expiringWarningDays) {
        push("certificate.expiring_warning", { daysRemaining: dropped, notAfter: certificate.notAfter });
      }
      if (!certificate.hostnameMatches) {
        push("certificate.hostname_mismatch", {
          checkedHostname: tls.checkedHostname,
          san: certificate.san,
        });
      }
      if (certificate.chainValid === false) {
        push("certificate.chain_invalid", { chainError: certificate.chainError });
      }
      if (certificate.selfSigned) push("certificate.self_signed", { subject: certificate.subjectCn });
      const weakRsa =
        (certificate.keyAlgorithm === "rsa" || certificate.keyAlgorithm === "rsa-pss") &&
        typeof certificate.keySize === "number" &&
        certificate.keySize < methodology.thresholds.weakRsaBits;
      const weakEc =
        certificate.keyAlgorithm === "ec" &&
        typeof certificate.keySize === "number" &&
        certificate.keySize < 256;
      if (weakRsa || weakEc) {
        push("certificate.weak_key", {
          keyAlgorithm: certificate.keyAlgorithm,
          keySize: certificate.keySize,
        });
      }
    }
  }

  const availability = inputs.availability;
  if (availability && !availability.ok) {
    push("availability.unreachable", {
      errorCode: availability.errorCode,
      error: availability.error,
      hops: availability.hops,
    });
  }
  if (availability?.ok) {
    const status = availability.statusCode ?? 0;
    if (status >= 500) push("availability.server_error", { statusCode: status, finalUrl: availability.finalUrl });
    else if (status >= 400)
      push("availability.client_error", { statusCode: status, finalUrl: availability.finalUrl });
    if (availability.httpToHttpsRedirect === false) {
      push("availability.no_https_redirect", {
        plainHttpStatus: availability.plainHttpStatus,
        plainHttpLocation: availability.plainHttpLocation,
      });
    }
    const responseTime = availability.responseTimeMs;
    if (responseTime !== null && responseTime > methodology.thresholds.slowResponseMs) {
      if (responseTime > methodology.thresholds.verySlowResponseMs) {
        push("availability.very_slow_response", { responseTimeMs: responseTime });
      } else {
        push("availability.slow_response", { responseTimeMs: responseTime });
      }
    }
  }

  return detected;
}

export interface RecordFindingsResult {
  opened: number;
  updated: number;
  findingIds: string[];
}

/**
 * Persists detected findings for one scan.
 *
 * A finding that is already open (status new/acknowledged) for the same domain and
 * code is updated in place — `last_seen_at`, `occurrences`, `evidence`, `scan_id`
 * — and its status is left exactly as the human left it. Only genuinely new codes
 * are inserted. The partial unique index `findings_domain_code_open_key` guarantees
 * there can never be two open findings with the same code for one domain.
 */
export async function recordFindings(
  tx: QueryRunner,
  context: { organizationId: string; domainId: string; scanId: string },
  detected: DetectedFinding[]
): Promise<RecordFindingsResult> {
  let opened = 0;
  let updated = 0;
  const findingIds: string[] = [];

  for (const item of detected) {
    const definition = findingDefinition(item.code);
    if (!definition) continue;
    const existing = await tx.query<{ id: string }>(
      `select id from findings
        where domain_id = $1 and code = $2 and status in ('new', 'acknowledged')`,
      [context.domainId, item.code]
    );
    const row = existing.rows[0];
    if (row) {
      await tx.query(
        `update findings
            set last_seen_at = now(), last_scan_id = $2, scan_id = $2, severity = $3,
                evidence = $4::jsonb, occurrences = occurrences + 1, updated_at = now()
          where id = $1`,
        [row.id, context.scanId, definition.severity, JSON.stringify(item.evidence)]
      );
      findingIds.push(row.id);
      updated += 1;
      continue;
    }
    const inserted = await tx.query<{ id: string }>(
      `insert into findings
         (organization_id, domain_id, scan_id, last_scan_id, category, code, severity, status,
          title_es, title_en, explanation_simple_es, explanation_simple_en, explanation_tech,
          impact_es, impact_en, recommendation_es, recommendation_en, evidence)
       values ($1, $2, $3, $3, $4, $5, $6, 'new',
               $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb)
       on conflict (domain_id, code) where status in ('new', 'acknowledged') do update
         set last_seen_at = now(), last_scan_id = excluded.scan_id, scan_id = excluded.scan_id,
             severity = excluded.severity, evidence = excluded.evidence,
             occurrences = findings.occurrences + 1, updated_at = now()
       returning id`,
      [
        context.organizationId,
        context.domainId,
        context.scanId,
        definition.category,
        definition.code,
        definition.severity,
        definition.titleEs,
        definition.titleEn,
        definition.simpleEs,
        definition.simpleEn,
        `${definition.titleEn} — detected by the DOMIRA passive scan.`,
        definition.impactEs,
        definition.impactEn,
        definition.recommendationEs,
        definition.recommendationEn,
        JSON.stringify(item.evidence),
      ]
    );
    const id = inserted.rows[0]?.id;
    if (id) {
      findingIds.push(id);
      opened += 1;
    }
  }

  return { opened, updated, findingIds };
}
