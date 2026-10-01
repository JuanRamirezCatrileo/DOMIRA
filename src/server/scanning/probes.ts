/**
 * Network probe seam for the scan engine.
 *
 * The engine never calls `probeTls` / `probeAvailability` directly: it asks this
 * registry for the current implementation. In production the registry holds the
 * real probes (real TCP/TLS handshake, real HTTPS request). In tests
 * `setTlsProbe()` / `setAvailabilityProbe()` inject deterministic fixtures, so the
 * whole pipeline — engine, persistence, findings, score — can be exercised end to
 * end without touching the network or depending on a third-party domain.
 *
 * This is the same pattern as `setDnsResolver()` in ./dns.ts: the real
 * implementation is the default and is never mocked inside application code.
 */
import { probeAvailability, type AvailabilityProbeOptions, type AvailabilityProbeResult } from "./availability";
import { probeTls, type TlsProbeOptions, type TlsProbeResult } from "./tls";

export type TlsProbe = (hostname: string, options: TlsProbeOptions) => Promise<TlsProbeResult>;
export type AvailabilityProbe = (
  hostname: string,
  options: AvailabilityProbeOptions
) => Promise<AvailabilityProbeResult>;

let tlsProbe: TlsProbe = probeTls;
let availabilityProbe: AvailabilityProbe = probeAvailability;

export function getTlsProbe(): TlsProbe {
  return tlsProbe;
}

export function getAvailabilityProbe(): AvailabilityProbe {
  return availabilityProbe;
}

/** Test seam: inject a deterministic TLS probe. Pass null to restore the real one. */
export function setTlsProbe(probe: TlsProbe | null): void {
  tlsProbe = probe ?? probeTls;
}

/** Test seam: inject a deterministic availability probe. Pass null to restore. */
export function setAvailabilityProbe(probe: AvailabilityProbe | null): void {
  availabilityProbe = probe ?? probeAvailability;
}

export function resetProbes(): void {
  tlsProbe = probeTls;
  availabilityProbe = probeAvailability;
}
