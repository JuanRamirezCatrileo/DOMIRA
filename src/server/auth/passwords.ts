/**
 * Password hashing with argon2id (Bun.password — a modern, memory-hard KDF).
 *
 * - The plaintext password is never logged, stored or returned.
 * - Verification is constant-time at the library level, and `verifyPassword`
 *   returns false (never throws) on a malformed hash.
 * - `burnPasswordTime()` performs a dummy verification so that a login attempt for
 *   a non-existent account costs the same as for an existing one — the response
 *   time must not reveal whether an e-mail is registered.
 */
const ARGON2_OPTIONS = {
  algorithm: "argon2id" as const,
  memoryCost: 19456,
  timeCost: 2,
  outputLen: 32,
};

let dummyHashPromise: Promise<string> | null = null;

function dummyHash(): Promise<string> {
  dummyHashPromise ??= Bun.password.hash(
    `domira-timing-equalizer-${Math.random().toString(36).slice(2)}`,
    ARGON2_OPTIONS
  );
  return dummyHashPromise;
}

export async function hashPassword(password: string): Promise<string> {
  return Bun.password.hash(password, ARGON2_OPTIONS);
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await Bun.password.verify(password, hash);
  } catch {
    return false;
  }
}

/** Equalise timing for accounts that do not exist (or are suspended). */
export async function burnPasswordTime(password: string): Promise<void> {
  await verifyPassword(await dummyHash(), password);
}

export interface PasswordStrength {
  /** 0 (very weak) … 4 (strong). */
  score: number;
  label: "very_weak" | "weak" | "fair" | "good" | "strong";
  problems: string[];
}

/**
 * Strength check used both by the API (rejects anything below the policy:
 * >= 12 characters, at least one letter and one non-letter) and by the UI meter,
 * so the user sees exactly what the server will enforce.
 */
export function passwordStrength(password: string): PasswordStrength {
  const problems: string[] = [];
  const hasLetter = /[A-Za-z]/.test(password);
  const hasNonLetter = /[^A-Za-z]/.test(password);
  if (password.length < 12) problems.push("too_short");
  if (!hasLetter) problems.push("needs_letter");
  if (!hasNonLetter) problems.push("needs_number_or_symbol");

  let score = 0;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  if (hasLetter && hasNonLetter) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  if (problems.length > 0) score = Math.min(score, 1);
  const labels: PasswordStrength["label"][] = ["very_weak", "weak", "fair", "good", "strong"];
  return { score, label: labels[score] ?? "very_weak", problems };
}
