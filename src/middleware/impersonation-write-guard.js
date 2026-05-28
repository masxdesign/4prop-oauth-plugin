import { impersonationReadOnlyResponse, isImpersonationWriteBlocked } from '../lib/impersonationMutations.js'

/** Reject BizChat / agent writes when JWT carries a restrictive impersonation allowlist. */
export function impersonationWriteGuard(req, res, next) {
    if (!isImpersonationWriteBlocked(req)) {
        return next()
    }
    return res.status(403).json(impersonationReadOnlyResponse())
}
