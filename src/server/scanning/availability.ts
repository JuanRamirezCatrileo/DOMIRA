/**
 * Passive availability check.
 *
 * A single real HTTPS GET of `/` on port 443, followed by at most
 * DOMIRA_HTTP_MAX_REDIRECTS redirects, recording every hop (URL + status +
 * Location), the final status, the final URL and the time to response headers.
 * A second request to plain HTTP `/` on port 80 only answers one question:
 * "does this host redirect HTTP to HTTPS?". Nothing else is requested — no path
 * enumeration, no POST, no authentication, no payloads.
 *
 * Failures (DNS, TCP, TLS, timeout, invalid redirect loop) are returned as errors
 * with the real error text, never as invented results.
 */
export interface HttpHop {
  url: string;
  status: number;
  location: string | null;
}

export interface AvailabilityProbeResult {
  ok: boolean;
  errorCode: string | null;
  error: string | null;
  durationMs: number;
  finalUrl: string | null;
  statusCode: number | null;
  responseTimeMs: number | null;
  hops: HttpHop[];
  redirectCount: number;
  serverHeader: string | null;
  /** true = HTTP answers with a redirect to HTTPS, false = HTTP serves content. */
  httpToHttpsRedirect: boolean | null;
  plainHttpStatus: number | null;
  plainHttpError: string | null;
  plainHttpLocation: string | null;
}

export interface AvailabilityProbeOptions {
  timeoutMs?: number;
  maxRedirects?: number;
  userAgent?: string;
}

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

function describeError(error: unknown): { code: string; message: string } {
  const raw = error as { code?: string; name?: string; message?: string; cause?: { code?: string } };
  const code = raw.code ?? raw.cause?.code ?? (raw.name === "TimeoutError" ? "TIMEOUT" : "NETWORK_ERROR");
  const message = raw.message ?? String(error);
  return { code, message: `${code}: ${message}` };
}

export async function probeAvailability(
  hostname: string,
  options: AvailabilityProbeOptions = {}
): Promise<AvailabilityProbeResult> {
  const timeoutMs = options.timeoutMs ?? 10000;
  const maxRedirects = options.maxRedirects ?? Number(process.env.DOMIRA_HTTP_MAX_REDIRECTS ?? 5);
  const userAgent = options.userAgent ?? "DOMIRA-Monitor/1.0";
  const started = Date.now();

  const result: AvailabilityProbeResult = {
    ok: false,
    errorCode: null,
    error: null,
    durationMs: 0,
    finalUrl: null,
    statusCode: null,
    responseTimeMs: null,
    hops: [],
    redirectCount: 0,
    serverHeader: null,
    httpToHttpsRedirect: null,
    plainHttpStatus: null,
    plainHttpError: null,
    plainHttpLocation: null,
  };

  let current = `https://${hostname}/`;
  const startedAt = Date.now();
  try {
    for (let hop = 0; hop <= maxRedirects; hop += 1) {
      const response = await fetch(current, {
        method: "GET",
        redirect: "manual",
        headers: { "user-agent": userAgent, accept: "*/*" },
        signal: AbortSignal.timeout(timeoutMs),
      });
      const location = response.headers.get("location");
      result.hops.push({ url: current, status: response.status, location });
      result.serverHeader ??= response.headers.get("server");
      // Drain a bounded amount so the socket is released without reading a body.
      try {
        await response.body?.cancel();
      } catch {
        /* already consumed or empty */
      }
      if (REDIRECT_CODES.has(response.status) && location) {
        if (hop === maxRedirects) {
          result.errorCode = "TOO_MANY_REDIRECTS";
          result.error = `More than ${maxRedirects} redirects; stopped following.`;
          result.durationMs = Date.now() - started;
          result.responseTimeMs = Date.now() - startedAt;
          return result;
        }
        const next = new URL(location, current).toString();
        if (!/^https?:\/\//i.test(next)) {
          result.errorCode = "INVALID_REDIRECT";
          result.error = `Redirect to a non-HTTP(S) URL was refused: ${next}`;
          result.durationMs = Date.now() - started;
          return result;
        }
        current = next;
        continue;
      }
      result.ok = true;
      result.statusCode = response.status;
      result.finalUrl = current;
      result.responseTimeMs = Date.now() - startedAt;
      result.redirectCount = result.hops.length - 1;
      result.durationMs = Date.now() - started;
      break;
    }
  } catch (error) {
    const described = describeError(error);
    result.errorCode = described.code;
    result.error = described.message;
    result.durationMs = Date.now() - started;
    result.responseTimeMs = Date.now() - startedAt;
  }

  // Plain HTTP: one request, only to learn whether HTTP→HTTPS redirection exists.
  try {
    const response = await fetch(`http://${hostname}/`, {
      method: "GET",
      redirect: "manual",
      headers: { "user-agent": userAgent, accept: "*/*" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    const location = response.headers.get("location");
    result.plainHttpStatus = response.status;
    result.plainHttpLocation = location;
    result.httpToHttpsRedirect = Boolean(location && /^https:\/\//i.test(location));
    try {
      await response.body?.cancel();
    } catch {
      /* ignore */
    }
  } catch (error) {
    // Port 80 closed or filtered is not a security problem; record why we could
    // not answer the question instead of guessing.
    const described = describeError(error);
    result.plainHttpError = described.message;
    result.httpToHttpsRedirect = null;
  }

  return result;
}
