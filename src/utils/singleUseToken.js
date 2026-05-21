import crypto from "node:crypto"

const TOKEN_BYTES = 32                       // 64 hex chars, 256 bits of entropy
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000   // 24h

/**
 * Generate a new single-use token (email verification, password reset, etc.).
 *
 * The plaintext is sent to the user via email; the hash is stored in the DB.
 * The plaintext is never persisted — verification recomputes the hash from the
 * URL parameter and compares.
 *
 * @param {object} [opts]
 * @param {number} [opts.ttlMs]  Token lifetime in ms. Defaults to 24h.
 * @returns {{ plain: string, hash: string, expiresAt: Date }}
 */
export function generateToken({ ttlMs = DEFAULT_TTL_MS } = {}) {
    const plain = crypto.randomBytes(TOKEN_BYTES).toString("hex")
    const hash = hashToken(plain)
    const expiresAt = new Date(Date.now() + ttlMs)
    return { plain, hash, expiresAt }
}

/**
 * Hash a plaintext single-use token for storage / lookup.
 * SHA-256, lowercase hex. Deterministic — same input always produces same hash.
 *
 * @param {string} plain
 * @returns {string} 64-char lowercase hex
 */
export function hashToken(plain) {
    return crypto.createHash("sha256").update(String(plain)).digest("hex")
}
