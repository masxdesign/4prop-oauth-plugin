import jwt from '../services/jwt.js'

/** Cookie (same-origin) or Authorization Bearer (cross-origin SPA hosts). */
function extractAccessToken(req) {
    const authHeader = req.headers.authorization
    if (authHeader && authHeader.startsWith('Bearer ')) {
        return authHeader.substring(7)
    }
    return req.cookies.access_token || null
}

/** Validate token, attach decoded payload to req.user */
export async function authenticate(req, res, next) {
    try {
        const token = extractAccessToken(req)

        if (!token) {
            return res.status(401).json({ error: 'No token provided' })
        }

        const decoded = jwt.verifyAccessToken(token)
        req.user = decoded

        next()
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' })
    }
}

/** Validate token and fetch full user from repository */
export function authenticateWithUser(authRepository) {
    return async (req, res, next) => {
        try {
            const token = extractAccessToken(req)

            if (!token) {
                return res.status(401).json({ error: 'No token provided' })
            }

            const decoded = jwt.verifyAccessToken(token)
            const user = await authRepository.getUserById(decoded.userId)

            if (!user) {
                return res.status(401).json({ error: 'User not found' })
            }

            req.user = user
            next()
        } catch (error) {
            res.status(401).json({ error: 'Invalid token' })
        }
    }
}

/** Optional auth - continues even if no token */
export async function optionalAuth(req, res, next) {
    try {
        const token = extractAccessToken(req)
        if (token) {
            const decoded = jwt.verifyAccessToken(token)
            req.user = decoded
        }
    } catch (error) {
        // Ignore errors for optional auth
    }
    next()
}
