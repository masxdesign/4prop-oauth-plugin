/**
 * Simple in-memory rate limiter keyed by arbitrary string (IP, email, etc.).
 * Suitable for single-instance deployments; use Redis for multi-pod.
 */

const store = new Map()
const CLEANUP_INTERVAL = 5 * 60 * 1000

setInterval(() => {
    const now = Date.now()
    for (const [key, data] of store.entries()) {
        if (now >= data.resetTime) {
            store.delete(key)
        }
    }
}, CLEANUP_INTERVAL).unref?.()

export function checkRateLimit(key, limit, windowMs) {
    const now = Date.now()
    const windowSeconds = Math.round(windowMs / 1000)

    let data = store.get(key)

    if (!data || now >= data.resetTime) {
        data = {
            count: 1,
            resetTime: now + windowMs,
        }
        store.set(key, data)

        return {
            allowed: true,
            remaining: limit - 1,
            resetIn: windowSeconds,
            limit,
            windowSeconds,
        }
    }

    data.count += 1

    const resetIn = Math.ceil((data.resetTime - now) / 1000)

    if (data.count > limit) {
        return {
            allowed: false,
            remaining: 0,
            resetIn,
            limit,
            windowSeconds,
        }
    }

    return {
        allowed: true,
        remaining: limit - data.count,
        resetIn,
        limit,
        windowSeconds,
    }
}

export class RateLimitError extends Error {
    constructor(message, retryAfter) {
        super(message)
        this.name = 'RateLimitError'
        this.status = 429
        this.retryAfter = retryAfter
    }
}

export function assertRateLimit(key, limit, windowMs) {
    const result = checkRateLimit(key, limit, windowMs)

    if (!result.allowed) {
        throw new RateLimitError(
            'Too many attempts. Please try again later.',
            result.resetIn,
        )
    }

    return result
}

export function getClientIp(req) {
    return req.ip || req.socket?.remoteAddress || 'unknown'
}
