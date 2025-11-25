import jwt from 'jsonwebtoken'
import { isProduction } from '../utils/env.js'

let jwtConfig = {
    accessSecret: null,
    refreshSecret: null,
    accessExpiry: '15m',
    refreshExpiry: '7d'
}

export function setJwtConfig(config) {
    jwtConfig = {
        accessSecret: config.accessSecret,
        refreshSecret: config.refreshSecret,
        accessExpiry: config.accessExpiry || '15m',
        refreshExpiry: config.refreshExpiry || '7d'
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
        path: '/',
        maxAge: 15 * 60 * 1000 // 15 minutes
    })

    res.cookie('refresh_token', tokens.refreshToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'strict',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    })
}

export function setAccessTokenCookie(res, accessToken) {
    const isProd = isProduction()

    res.cookie('access_token', accessToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'strict',
        path: '/',
        maxAge: 15 * 60 * 1000
    })
}

export function clearTokenCookies(res) {
    const isProd = isProduction()

    res.clearCookie('access_token', {
        httpOnly: true,
        secure: isProd,
        sameSite: 'strict',
        path: '/'
    })

    res.clearCookie('refresh_token', {
        httpOnly: true,
        secure: isProd,
        sameSite: 'strict',
        path: '/'
    })
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
