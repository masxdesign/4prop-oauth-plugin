// Back-compat re-export. Email verification and password reset use the same
// crypto, so the underlying helpers moved to singleUseToken.js and these
// names are now aliases. New code should import from singleUseToken.js
// directly; existing imports of generateEmailVerifyToken / hashEmailVerifyToken
// keep working without churn.
import { generateToken, hashToken } from "./singleUseToken.js"

export const generateEmailVerifyToken = generateToken
export const hashEmailVerifyToken = hashToken
