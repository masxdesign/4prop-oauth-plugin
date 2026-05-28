/**
 * Mutation scopes for impersonation sessions — keep in sync with:
 * - property-pub-react `src/config/impersonationMutations.js`
 * - bizchat imports `@4prop/oauth/impersonation-mutations` (same package, no copy)
 */
export const MUTATION_KEYS = /** @type {const} */ ({
    GRADE_WRITE: 'grade.write',
    SHORTLIST_WRITE: 'shortlist.write',
    SHORTLIST_SHARE: 'shortlist.share',
    CONVERSATION_REPLY: 'conversation.reply',
    DEPARTMENT_CLIENT_WRITE: 'departmentClient.write',
    ENQUIRY_SEND: 'enquiry.send',
})

/**
 * @param {string} method
 * @param {string} path
 * @returns {string | null}
 */
export function resolveImpersonationMutationKey(method, path) {
    const m = method.toUpperCase()
    const p = path.split('?')[0]

    if (m === 'PUT' && /\/api\/crm\/mag\/agentb\/[^/]+\/[^/]+\/grade$/.test(p)) {
        return MUTATION_KEYS.GRADE_WRITE
    }

    if (m === 'POST' && /\/api\/crm\/mag\/agentb\/[^/]+\/shortlists$/.test(p)) {
        return MUTATION_KEYS.SHORTLIST_WRITE
    }
    if ((m === 'PATCH' || m === 'DELETE') && /\/api\/crm\/mag\/agentb\/[^/]+\/shortlists\/[^/]+$/.test(p)) {
        return MUTATION_KEYS.SHORTLIST_WRITE
    }
    if (m === 'POST' && /\/api\/crm\/mag\/agentb\/[^/]+\/shortlists\/[^/]+\/merge$/.test(p)) {
        return MUTATION_KEYS.SHORTLIST_WRITE
    }
    if (m === 'POST' && /\/api\/crm\/mag\/agentb\/[^/]+\/[^/]+\/shortlists\/[^/]+$/.test(p)) {
        return MUTATION_KEYS.SHORTLIST_WRITE
    }
    if (m === 'DELETE' && /\/api\/crm\/mag\/agentb\/[^/]+\/[^/]+\/shortlists\/[^/]+$/.test(p)) {
        return MUTATION_KEYS.SHORTLIST_WRITE
    }

    if (m === 'POST' && /\/api\/crm\/mag\/agentb\/[^/]+\/shortlists\/[^/]+\/share(-one)?$/.test(p)) {
        return MUTATION_KEYS.SHORTLIST_SHARE
    }

    if (m === 'POST' && /^\/api\/messaging\/enquir/.test(p)) {
        return MUTATION_KEYS.ENQUIRY_SEND
    }

    if ((m === 'POST' || m === 'PATCH') && /^\/api\/crm\/mag\/department-clients/.test(p)) {
        if (p.includes('/onboarding/validate') || p.includes('/onboarding/accept')) {
            return null
        }
        return MUTATION_KEYS.DEPARTMENT_CLIENT_WRITE
    }

    return null
}

/**
 * @param {import('express').Request} req
 * @returns {boolean}
 */
export function isImpersonationWriteBlocked(req) {
    const allowlist = req.user?.impersonationAllowedMutations
    if (!Array.isArray(allowlist)) return false

    const key = resolveImpersonationMutationKey(req.method, req.path || req.originalUrl || '')
    if (!key) {
        // Restricted session: block unknown writes under agent surfaces.
        if (allowlist.length === 0 && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method.toUpperCase())) {
            const p = (req.path || req.originalUrl || '').split('?')[0]
            if (
                p.startsWith('/api/crm/mag/agentb')
                || p.startsWith('/api/crm/mag/department-clients')
                || p.startsWith('/api/messaging/enquir')
            ) {
                return true
            }
        }
        return false
    }

    return !allowlist.includes(key)
}

export function impersonationReadOnlyResponse() {
    return {
        error: 'This action is not allowed while viewing as a colleague (read-only).',
        code: 'IMPERSONATION_READ_ONLY',
    }
}
