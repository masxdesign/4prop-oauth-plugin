import crypto from "node:crypto"

const TOKEN_BYTES = 32                       // 64 hex chars, 256 bits of entropy
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000   // 24h

/**
 * Generate a new email-verification token.
 *
 * The plaintext token is emailed to the user; the hash is stored in the DB.
 * We never persist the plaintext — verification recomputes the hash from the
 * URL parameter and compares.
 *
 * @returns {{ plain: string, hash: string, expiresAt: Date }}
 */
export function generateEmailVerifyToken({ ttlMs = DEFAULT_TTL_MS } = {}) {
    const plain = crypto.randomBytes(TOKEN_BYTES).toString("hex")
    const hash = hashEmailVerifyToken(plain)
    const expiresAt = new Date(Date.now() + ttlMs)
    return { plain, hash, expiresAt }
}

/**
 * Hash a plaintext verification token for storage / lookup.
 * SHA-256, lowercase hex. Deterministic — same input always produces same hash.
 *
 * @param {string} plain
 * @returns {string} 64-char lowercase hex
 */
export function hashEmailVerifyToken(plain) {
    return crypto.createHash("sha256").update(String(plain)).digest("hex")
}
