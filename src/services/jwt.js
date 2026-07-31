import { AsyncLocalStorage } from 'node:async_hooks'
import jwtLib from 'jsonwebtoken'
import { isProduction } from '../utils/env.js'

let jwtConfig = {
    accessSecret: null,
    refreshSecret: null,
    accessExpiry: '15m',
    refreshExpiry: '7d'
}

/** Per-request merged cookie options (preset + static overrides). */
const authCookieAsyncLocalStorage = new AsyncLocalStorage()

/** Static defaults; updated on each createAuthRouter() call. */
let authCookieDefaults = {
    cookieMode: 'same-site',
    cookies: {}
}

const COOKIE_OVERRIDE_KEYS = [
    'httpOnly',
    'secure',
    'sameSite',
    'domain',
    'path',
    'maxAgeAccess',
    'maxAgeRefresh'
]

export function setJwtConfig(config) {
    jwtConfig = {
        accessSecret: config.accessSecret,
        refreshSecret: config.refreshSecret,
        accessExpiry: config.accessExpiry || '15m',
        refreshExpiry: config.refreshExpiry || '7d'
    }
}

/**
 * Static auth cookie defaults for this process (and fallback when no per-request store).
 * @param {{ cookieMode?: 'same-site'|'cross-origin-spa', cookies?: Record<string, unknown> }} param0
 */
export function setAuthCookieDefaults({ cookieMode = 'same-site', cookies = {} } = {}) {
    if (cookieMode !== 'same-site' && cookieMode !== 'cross-origin-spa') {
        throw new Error(`Invalid cookieMode: ${String(cookieMode)}. Use 'same-site' or 'cross-origin-spa'.`)
    }
    authCookieDefaults = {
        cookieMode,
        cookies: cookies && typeof cookies === 'object' ? { ...cookies } : {}
    }
}

function normalizeCookieOverrides(cookies) {
    const out = {}
    if (!cookies || typeof cookies !== 'object') return out
    for (const k of COOKIE_OVERRIDE_KEYS) {
        if (cookies[k] !== undefined && cookies[k] !== null) {
            out[k] = cookies[k]
        }
    }
    return out
}

function buildPresetBase(cookieMode) {
    const isProd = isProduction()
    if (cookieMode === 'cross-origin-spa') {
        // NOTE: `SameSite=None` from a different registrable domain is a THIRD-PARTY
        // cookie, which WebKit (Safari, and every iOS browser) blocks by default via ITP.
        // Chrome still allows it. So this mode only ever works in Chromium browsers.
        //
        // CHIPS (`Partitioned`) does NOT rescue it: the cookie is set while the browser is
        // on the OAuth callback URL (the auth host's own top-level site), so it lands in
        // THAT partition — not the SPA's — and the SPA can never read it.
        //
        // The real fix is to stop being third-party: proxy `/api/auth/*` through the SPA's
        // own hostname so the cookies are first-party (see the nginx rule in 4prop-container
        // for www.4prop.com). Domains that do that don't need this mode at all.
        return {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            path: '/',
            maxAgeAccess: 15 * 60 * 1000,
            maxAgeRefresh: 7 * 24 * 60 * 60 * 1000
        }
    }
    return {
        httpOnly: true,
        secure: isProd,
        sameSite: 'strict',
        path: '/',
        maxAgeAccess: 15 * 60 * 1000,
        maxAgeRefresh: 7 * 24 * 60 * 60 * 1000
    }
}

function mergeCookieOptions(cookieMode, userCookies) {
    const preset = buildPresetBase(cookieMode)
    const overrides = normalizeCookieOverrides(userCookies)
    return { ...preset, ...overrides }
}

function getResolvedCookieOptions() {
    const fromStore = authCookieAsyncLocalStorage.getStore()
    if (fromStore) return fromStore
    return mergeCookieOptions(authCookieDefaults.cookieMode, authCookieDefaults.cookies)
}

/**
 * Express middleware: resolves per-request cookie flags via resolveCookieMode(req)
 * and optional resolveCookieOverrides(req), stored in AsyncLocalStorage for helpers.
 * @param {(req: import('express').Request) => ('same-site'|'cross-origin-spa'|undefined)} resolveCookieMode
 * @param {(req: import('express').Request) => Record<string, unknown>|undefined} [resolveCookieOverrides]
 */
export function createCookieModeMiddleware(resolveCookieMode, resolveCookieOverrides) {
    if (typeof resolveCookieMode !== 'function') {
        throw new Error('createCookieModeMiddleware: resolveCookieMode must be a function')
    }
    return (req, res, next) => {
        let mode = resolveCookieMode(req)
        if (mode !== 'same-site' && mode !== 'cross-origin-spa') {
            mode = authCookieDefaults.cookieMode
        }
        const perRequestOverrides =
            typeof resolveCookieOverrides === 'function' ? resolveCookieOverrides(req) : {}
        const opts = mergeCookieOptions(mode, {
            ...authCookieDefaults.cookies,
            ...normalizeCookieOverrides(perRequestOverrides),
        })
        return authCookieAsyncLocalStorage.run(opts, () => next())
    }
}

function getAccessSecret() {
    return jwtConfig.accessSecret
}

function getRefreshSecret() {
    return jwtConfig.refreshSecret
}

function getAccessExpiry() {
    return jwtConfig.accessExpiry
}

function getRefreshExpiry() {
    return jwtConfig.refreshExpiry
}

function buildUserClaims(user) {
    const claims = { userId: user.id, email: user.email }
    if (user.role !== undefined && user.role !== null) claims.role = user.role
    if (user.neg_id !== undefined && user.neg_id !== null) claims.neg_id = user.neg_id
    return claims
}

export function generateAccessToken(user) {
    return jwtLib.sign(
        buildUserClaims(user),
        getAccessSecret(),
        { expiresIn: getAccessExpiry() }
    )
}

export function generateRefreshToken(user) {
    return jwtLib.sign(
        { userId: user.id },
        getRefreshSecret(),
        { expiresIn: getRefreshExpiry() }
    )
}

export function generateTokens(user) {
    return {
        accessToken: generateAccessToken(user),
        refreshToken: generateRefreshToken(user)
    }
}

function buildImpersonationClaims(targetUser, originalUser, options = {}) {
    const claims = {
        ...buildUserClaims(targetUser),
        impersonating: true,
        adminUserId: originalUser.id,
        adminEmail: originalUser.email,
    }
    if (Array.isArray(options.impersonationAllowedMutations)) {
        claims.impersonationAllowedMutations = options.impersonationAllowedMutations
    }
    return claims
}

export function generateImpersonationAccessToken(targetUser, originalUser, options = {}) {
    return jwtLib.sign(
        buildImpersonationClaims(targetUser, originalUser, options),
        getAccessSecret(),
        { expiresIn: getAccessExpiry() }
    )
}

export function generateImpersonationRefreshToken(targetUser, originalUser, options = {}) {
    const payload = {
        userId: targetUser.id,
        impersonating: true,
        adminUserId: originalUser.id,
        adminEmail: originalUser.email,
    }
    if (Array.isArray(options.impersonationAllowedMutations)) {
        payload.impersonationAllowedMutations = options.impersonationAllowedMutations
    }
    return jwtLib.sign(
        payload,
        getRefreshSecret(),
        { expiresIn: getRefreshExpiry() }
    )
}

export function generateImpersonationTokens(targetUser, originalUser, options = {}) {
    return {
        accessToken: generateImpersonationAccessToken(targetUser, originalUser, options),
        refreshToken: generateImpersonationRefreshToken(targetUser, originalUser, options),
    }
}

export function verifyAccessToken(token) {
    return jwtLib.verify(token, getAccessSecret())
}

export function verifyRefreshToken(token) {
    return jwtLib.verify(token, getRefreshSecret())
}

export function setTokenCookies(res, tokens) {
    const o = getResolvedCookieOptions()
    const accessOpts = {
        httpOnly: o.httpOnly !== false,
        secure: o.secure,
        sameSite: o.sameSite,
        path: o.path || '/',
        maxAge: o.maxAgeAccess ?? 15 * 60 * 1000
    }
    const refreshOpts = {
        httpOnly: o.httpOnly !== false,
        secure: o.secure,
        sameSite: o.sameSite,
        path: o.path || '/',
        maxAge: o.maxAgeRefresh ?? 7 * 24 * 60 * 60 * 1000
    }
    if (o.domain) {
        accessOpts.domain = o.domain
        refreshOpts.domain = o.domain
    }
    res.cookie('access_token', tokens.accessToken, accessOpts)
    res.cookie('refresh_token', tokens.refreshToken, refreshOpts)
}

export function setAccessTokenCookie(res, accessToken) {
    const o = getResolvedCookieOptions()
    const opts = {
        httpOnly: o.httpOnly !== false,
        secure: o.secure,
        sameSite: o.sameSite,
        path: o.path || '/',
        maxAge: o.maxAgeAccess ?? 15 * 60 * 1000
    }
    if (o.domain) opts.domain = o.domain
    res.cookie('access_token', accessToken, opts)
}

export function clearTokenCookies(res) {
    const o = getResolvedCookieOptions()
    const base = {
        httpOnly: o.httpOnly !== false,
        secure: o.secure,
        sameSite: o.sameSite,
        path: o.path || '/'
    }
    const accessClear = { ...base }
    const refreshClear = { ...base }
    if (o.domain) {
        accessClear.domain = o.domain
        refreshClear.domain = o.domain
    }
    res.clearCookie('access_token', accessClear)
    res.clearCookie('refresh_token', refreshClear)
}

const AUTH_COOKIE_NAMES = ['access_token', 'refresh_token']
const AUTH_COOKIE_SAMESITE_VARIANTS = ['strict', 'lax', 'none']

/**
 * Clear auth cookies across domain / SameSite combinations. Used on logout to
 * remove legacy PHP cookies (e.g. Domain=.4prop.com, SameSite=None) that the
 * default clearTokenCookies() miss when the current preset is host-only Strict.
 */
export function clearTokenCookieVariants(res, { domain, secure = true } = {}) {
    for (const name of AUTH_COOKIE_NAMES) {
        for (const sameSite of AUTH_COOKIE_SAMESITE_VARIANTS) {
            const opts = {
                httpOnly: true,
                secure: sameSite === 'none' ? true : secure,
                sameSite,
                path: '/',
            }
            if (domain) opts.domain = domain
            res.clearCookie(name, opts)
        }
        if (domain) {
            for (const sameSite of AUTH_COOKIE_SAMESITE_VARIANTS) {
                res.clearCookie(name, {
                    httpOnly: true,
                    secure: sameSite === 'none' ? true : secure,
                    sameSite,
                    path: '/',
                })
            }
        }
    }
}

export default {
    setJwtConfig,
    setAuthCookieDefaults,
    createCookieModeMiddleware,
    generateAccessToken,
    generateRefreshToken,
    generateTokens,
    generateImpersonationAccessToken,
    generateImpersonationRefreshToken,
    generateImpersonationTokens,
    verifyAccessToken,
    verifyRefreshToken,
    setTokenCookies,
    setAccessTokenCookie,
    clearTokenCookies,
    clearTokenCookieVariants
}
