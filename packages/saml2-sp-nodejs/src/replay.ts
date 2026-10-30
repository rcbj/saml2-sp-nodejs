// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

/**
 * Remembers which assertions have been accepted, so none is accepted twice (SAML Profiles 4.1.4.5).
 * Give the service provider one shared by every process when the application runs more than one.
 */
export interface ReplayCache {
  /**
   * Records `id` as used until `expiresAt`, and answers whether it had ALREADY been recorded. Must be
   * atomic: two concurrent calls with one id must not both answer false.
   */
  checkAndRecord(id: string, expiresAt: Date): boolean | Promise<boolean>;
}

/**
 * The default: one process's memory, at most `max` live entries. Expired entries are dropped as new ones
 * arrive, and when every slot holds a live assertion the next one is REFUSED rather than forgetting one
 * that could still be replayed.
 */
export class MemoryReplayCache implements ReplayCache {
  readonly #entries = new Map<string, number>();
  readonly #max: number;

  constructor(max = 10_000) {
    this.#max = max;
  }

  checkAndRecord(id: string, expiresAt: Date): boolean {
    const now = Date.now();
    const until = this.#entries.get(id);
    if (until !== undefined && until > now) return true;
    if (this.#entries.size >= this.#max) {
      for (const [k, v] of this.#entries) if (v <= now) this.#entries.delete(k);
      if (this.#entries.size >= this.#max) {
        throw new Error(`the replay cache holds ${this.#max} live assertions and cannot record another`);
      }
    }
    this.#entries.set(id, expiresAt.getTime());
    return false;
  }
}
