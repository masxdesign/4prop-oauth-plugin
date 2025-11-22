import jwt from 'jsonwebtoken'

let jwtConfig = {
    accessSecret: null,
    refreshSecret: null,
    accessExpiry: '15m',
    refreshExpiry: '7d',
    production: false
}

export function setJwtConfig(config) {
    jwtConfig = {
        accessSecret: config.accessSecret || config.access?.secret,
        refreshSecret: config.refreshSecret || config.refresh?.secret,
        accessExpiry: config.accessExpiry || config.access?.expiry || '15m',
        refreshExpiry: config.refreshExpiry || config.refresh?.expiry || '7d',
        production: config.production ?? (process.env.NODE_ENV === 'production')
    }
}

function getAccessSecret() {
    return jwtConfig.accessSecret || process.env.JWT_ACCESS_SECRET
}

function getRefreshSecret() {
    return jwtConfig.refreshSecret || process.env.JWT_REFRESH_SECRET
}

function getAccessExpiry() {
    return jwtConfig.accessExpiry || process.env.JWT_ACCESS_EXPIRY || '15m'
}

function getRefreshExpiry() {
    return jwtConfig.refreshExpiry || process.env.JWT_REFRESH_EXPIRY || '7d'
}

function isProduction() {
    return jwtConfig.production ?? (process.env.NODE_ENV === 'production')
}

export function generateAccessToken(user) {
    return jwt.sign(
        { userId: user.id, email: user.email },
        getAccessSecret(),
        { expiresIn: getAccessExpiry() }
    )
}

export function generateRefreshToken(user) {
    return jwt.sign(
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

export function verifyAccessToken(token) {
    return jwt.verify(token, getAccessSecret())
}

export function verifyRefreshToken(token) {
    return jwt.verify(token, getRefreshSecret())
}

export function setTokenCookies(res, tokens) {
    const isProd = isProduction()

    res.cookie('access_token', tokens.accessToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 minutes
    })

    res.cookie('refresh_token', tokens.refreshToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    })
}

export function setAccessTokenCookie(res, accessToken) {
    const isProd = isProduction()

    res.cookie('access_token', accessToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000
    })
}

export function clearTokenCookies(res) {
    res.clearCookie('access_token')
    res.clearCookie('refresh_token')
}

export default {
    setJwtConfig,
    generateAccessToken,
    generateRefreshToken,
    generateTokens,
    verifyAccessToken,
    verifyRefreshToken,
    setTokenCookies,
    setAccessTokenCookie,
    clearTokenCookies
}
