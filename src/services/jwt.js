import jwt from 'jsonwebtoken'

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET
const ACCESS_EXPIRY = process.env.JWT_ACCESS_EXPIRY || '15m'
const REFRESH_EXPIRY = process.env.JWT_REFRESH_EXPIRY || '7d'

export function generateAccessToken(user) {
    return jwt.sign(
        { userId: user.id, email: user.email },
        ACCESS_SECRET,
        { expiresIn: ACCESS_EXPIRY }
    )
}

export function generateRefreshToken(user) {
    return jwt.sign(
        { userId: user.id },
        REFRESH_SECRET,
        { expiresIn: REFRESH_EXPIRY }
    )
}

export function generateTokens(user) {
    return {
        accessToken: generateAccessToken(user),
        refreshToken: generateRefreshToken(user)
    }
}

export function verifyAccessToken(token) {
    return jwt.verify(token, ACCESS_SECRET)
}

export function verifyRefreshToken(token) {
    return jwt.verify(token, REFRESH_SECRET)
}

export function setTokenCookies(res, tokens) {
    const isProduction = process.env.NODE_ENV === 'production'

    res.cookie('access_token', tokens.accessToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 minutes
    })

    res.cookie('refresh_token', tokens.refreshToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    })
}

export function setAccessTokenCookie(res, accessToken) {
    const isProduction = process.env.NODE_ENV === 'production'

    res.cookie('access_token', accessToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000
    })
}

export function clearTokenCookies(res) {
    res.clearCookie('access_token')
    res.clearCookie('refresh_token')
}

export default {
    generateAccessToken,
    generateRefreshToken,
    generateTokens,
    verifyAccessToken,
    verifyRefreshToken,
    setTokenCookies,
    setAccessTokenCookie,
    clearTokenCookies
}
