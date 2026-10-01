# DOMIRA — scanning engine

How DOMIRA turns "these are the domains I am authorised to monitor" into real,
passive observations and a Security Score. Nothing here exploits anything: every
check reads publicly available information with standard, non-destructive
requests.

## Defence policy (non-negotiable)

* Only domains a tenant has added **and verified** (DNS TXT ownership check) are
  ever scanned. The gate is enforced in the service *and* re-checked in the engine
  at execution time (`executeScan`), so a stale job can never scan a domain that
  lost authorisation in the meantime.
* Only passive checks: DNS resolution, a TCP/TLS handshake, and one HTTPS (plus
  one plain-HTTP) request. No brute force, no exploitation, no crawling, no
  authentication attempts.
* The scanner identifies itself with `DOMIRA_SCANNER_USER_AGENT`.
* SSRF defence in two layers: strict hostname validation before storage
  (`src/server/api/domain-validation.ts`) and, at scan time, a refusal to connect
  when the name resolves to any non-public address (`findNonPublicAddresses` in
  `src/server/scanning/dns.ts`). The second layer is fail-closed.

## Pipeline

```
API  POST /api/domains/:id/scan          <- returns 202, no analysis in the request
  -> scans row (queued) + jobs row (queued)     src/server/scanning/service.ts
  -> worker claims the job (SELECT ... FOR UPDATE SKIP LOCKED)
                                                src/server/queue/{jobs,worker}.ts
  -> executeScan()                               src/server/scanning/engine.ts
       DNS (A/AAAA/CNAME/MX/NS/TXT/CAA)
       SSRF address guard
       TLS handshake + certificate              src/server/scanning/tls.ts
       HTTPS availability + redirects           src/server/scanning/availability.ts
       findings (severity, plain-language text) src/server/scanning/findings.ts
       Security Score (per category, configurable methodology)
                                                src/server/scanning/{score,methodology}.ts
  -> one transaction: scan_results, certificates, dns_records, findings,
     security_scores, scan finalisation, domain counters
```

The worker runs in-process (`ensureRuntime()`) or standalone (`bun run worker`);
both run exactly the same code. Failure policy: an exception consumes an attempt
with exponential backoff, and after `DOMIRA_JOB_MAX_ATTEMPTS` the job is `failed`
and its scan is marked failed so a domain is never left blocked. A scan that
*completes* but observes a broken domain is a recorded result, not a queue error.

## What is collected today, and what is not

| Category | Status | Notes |
|---|---|---|
| TLS | collected | protocol, cipher, handshake duration |
| Certificate | collected | subject, issuer, serial, SHA-256 fingerprint, validity window, days remaining, key algorithm/size, SAN list, wildcard, self-signed, chain validity/length, hostname match |
| DNS | collected | A, AAAA, CNAME, MX, NS, TXT, CAA with TTL, compared with the previous scan for changes |
| Availability | collected | HTTPS status, final URL after redirects (max `DOMIRA_HTTP_MAX_REDIRECTS`), response time, server header, whether plain HTTP redirects to HTTPS |
| E-mail (SPF/DMARC/DKIM) | **not collected yet** | deliverable 2b |
| HTTP security headers | **not collected yet** | deliverable 2b |

Categories that are not collected are written to `scan_results` with
`status = 'skipped'` and `not_collected = true`, are excluded from the score and
are **never** credited with full marks (`uncollectedPolicy =
"exclude_and_renormalise"` in the active methodology). The API and the UI report
them as `not_collected`; nothing is estimated.

## Seams used by the tests

`setDnsResolver()`, `setTlsProbe()` and `setAvailabilityProbe()` exist so the
whole pipeline can be exercised deterministically (see `tests/helpers/scanning.ts`).
The real implementations are the defaults and are never mocked inside application
code. Because the suite always injects fixtures, it is the *script* below — not the
suite — that proves the real network path.

## Real run evidence

**Date:** 2026-10-01 (UTC) · **Command:** `bun run verify:real-scan`
( = `bun run scripts/verify-real-scan.ts`, target `example.com`, the IANA-operated
documentation domain).

This is a real scan: no fixture resolver, no fixture TLS probe, no fixture
availability probe. The script boots the real schema on an in-process PGlite,
registers a tenant through the real HTTP handlers, adds the domain through
`POST /api/domains`, marks it verified locally (DOMIRA cannot publish a TXT record
for a domain it does not control — the operator asserts the authorisation out of
band; that is the only shortcut and the script prints a warning about it), queues
the scan through `POST /api/domains/:id/scan`, runs the real worker
(`runWorkerOnce` → `executeScan`), and prints what the database recorded.

Raw output (excerpt; the script prints the whole thing, including both API
responses):

```
PASS  no fixture resolver installed: resolver kind = fallback(doh+node) (DOMIRA_DNS_RESOLVER=auto)
POST /api/domains -> 201   { hostname: example.com, registeredDomain: example.com,
                             verification: _domira-verification.example.com TXT "domira-site-verification=..." }
POST /api/domains/:id/scan -> 202   { scan.status queued, job.type scan_domain, reused: false }
runWorkerOnce() -> { status: completed, attempts: 1,
                     result: { scanStatus: "completed", score: 94, checksFailed: 0,
                               findings: { opened: 2, updated: 0 } } }   wall clock 143 ms

scan status: completed | duration 109 ms | checks completed 4 (failed 0) | error: none

-- scan_results --
[certificate] status=ok        score=100
[dns]         status=ok        score=90
[tls]         status=ok        score=100  duration=40 ms
[availability] status=warning  score=85   duration=30 ms
[email]       status=skipped   NOT_COLLECTED
[http]        status=skipped   NOT_COLLECTED

-- certificate (real X.509 leaf observed over the wire) --
checked hostname    : example.com:443
subject CN          : example.com
issuer              : Cloudflare TLS Issuing ECC CA 3 (SSL Corporation)
serial              : 01EEE6AABB521D5E14FC315FD9985690
SHA-256 fingerprint : 85ca6ab068e9bcce88b6c4aa3c47f7d17228134a457f870d3800e6223a0df07a
validity            : 2026-09-26T22:49:11Z -> 2026-12-25T22:56:35Z  (days remaining 85)
key                 : ec 256
protocol / cipher   : TLSv1.3 / TLS_AES_128_GCM_SHA256
SAN count           : 2 -> ["example.com","*.example.com"]
wildcard=true self_signed=false chain_valid=true chain_length=4 hostname_matches=true issues=[]

-- DNS records (real resolution, resolver: fallback(doh+node)) --
  A     104.20.23.154 ttl 166
  A     172.66.147.243 ttl 166
  AAAA  2606:4700:10::6814:179a ttl 9
  AAAA  2606:4700:10::ac42:93f3 ttl 9
  MX    (priority 0) ttl 6            <- Cloudflare's "null MX" (".", priority 0)
  NS    elliott.ns.cloudflare.com ttl 76279
  NS    hera.ns.cloudflare.com ttl 76279
  TXT   _k2n1y4vw3qtb4skdx9e7dxt97qrmmq9 ttl 300
  TXT   v=spf1 -all ttl 300
  (no CAA record published -> NODATA, recorded as an empty result, not an error)

-- HTTPS availability (real request) --
ok=true status=200 finalUrl=https://example.com/ responseTime=30 ms redirects=0
server=cloudflare plainHttp->https=false (plain HTTP status 200)
hops: [{"url":"https://example.com/","status":200,"location":null}]

-- findings --
[medium] availability.no_https_redirect — HTTP does not redirect to HTTPS
[low]    dns.no_caa_record              — No CAA record

-- Security Score --
DOMIRA Security Score: 94/100 (grade A, methodology 1.0.0)
certificate 100 (weight 30) | tls 100 (20) | dns 90 (25) | availability 85 (25)
email: not_collected (weight 0) | http: not_collected (weight 0)
coverage: policy exclude_and_renormalise, collected [tls, certificate, dns, availability],
          notCollected [email, http]

RESULT: a real end-to-end scan ran against a real public domain. All checks above passed.
```

Observations worth keeping:

* the certificate DOMIRA observed matches what a plain `openssl s_client`/`curl`
  sees from this machine (issuer Cloudflare TLS Issuing ECC CA 3, `notAfter`
  2026-12-25) — the probe reads the real chain, it is not synthesised;
* the plain-HTTP check is honest about a Cloudflare nuance: `http://example.com`
  answers 200 rather than redirecting, so the engine raises a real finding;
* the e-mail and HTTP header categories are reported as `not_collected` in the
  database, in `GET /api/scans/:id` and in `GET /api/domains/:id/security`.

### Two real defects this run exposed (both fixed)

The script was written to prove the pipeline; on its first runs it proved the
pipeline was broken in two places that the fixture-based suite could not see,
because no test executed the engine's write path:

1. `executeScan` finalised the domain with
   `... where id = $1` while passing three parameters, so `$2`
   (`organization_id`) was never referenced. PostgreSQL cannot infer its type:
   `42P18: could not determine data type of parameter $2`. Every scan failed at
   the last write, after the real network work — invisible to fixtures. Fixed by
   restoring the tenant scoping the query was meant to have:
   `where id = $1 and organization_id = $2`.
2. The `public_suffix_only` guard in `src/server/api/domain-validation.ts`
   compared the hostname against the *registered* domain instead of the public
   suffix, so a bare registrable domain (`example.com` — the product's most common
   input) was rejected with 400. Fixed with an explicit `publicSuffix()` and
   regression tests covering `example.com`, `domira-demo.cl`, `something.co.uk`,
   `algo.com.ar`, a subdomain, `foo.co.uk → foo.co.uk`, and `com`/`co.uk`.

Both fixes are on `feat/2a-closure-scanning-flow`. A `DOMIRA_SCAN_DEBUG=1` run
prints the failing SQL and stack, which is how defect 1 was located.

### Running it yourself

```bash
bun run verify:real-scan                  # default target: example.com
bun run verify:real-scan mi-dominio.cl    # any domain you are authorised to scan
DOMIRA_DNS_RESOLVER=node bun run verify:real-scan   # force the system resolver
```

The script needs outbound DNS (UDP/53 or DoH) and outbound HTTPS. It exits `0`
only when every check in its verdict section passes, so it is usable as a
deployment smoke test against a domain the operator controls. It never needs
`DATABASE_URL`: it runs on an in-process PGlite and throws the database away.

## Methodology

The active methodology lives in `score_methodologies` (version 1.0.0 by default,
`src/server/scanning/methodology.ts`). Weights, per-category penalties and the
uncollected policy are data, not code: a new version means inserting a new row and
activating it, with no deploy. The frontend never contains score arithmetic — it
renders whatever the API returns, including each factor's points and detail.
