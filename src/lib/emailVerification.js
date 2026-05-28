/**
 * Email verification policy: EACH agents (neg_id) are exempt — only non-agent
 * seekers must verify before verify-gated capabilities / enquiry send.
 */

/** @param {{ neg_id?: string | null } | null | undefined} user */
export function isAgentAccount(user) {
  const negId = user?.neg_id
  return negId != null && String(negId).trim() !== ''
}

/** @param {{ email_verified_at?: Date | string | null, neg_id?: string | null } | null | undefined} user */
export function isEmailVerifiedForPolicy(user) {
  if (!user) return false
  if (isAgentAccount(user)) return true
  return !!user.email_verified_at
}
