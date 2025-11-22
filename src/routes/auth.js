import express from 'express'
import passport from 'passport'
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'
import { Strategy as MicrosoftStrategy } from 'passport-microsoft'
import { Strategy as LinkedInStrategy } from 'passport-linkedin-oauth2'
import jwt from '../services/jwt.js'
import { authenticate } from '../middleware/authenticate.js'

let isPassportConfigured = false
let oauthConfig = {}
let jwtConfig = {}

/** Create auth router - pass your auth repository and optional config */
export default function createAuthRouter(authRepository, config = {}) {
    // Auto-configure passport on first call
    if (!isPassportConfigured) {
        oauthConfig = config.oauth || {}
        jwtConfig = config.jwt || {}

        // Configure JWT if config provided
        if (Object.keys(jwtConfig).length > 0) {
            jwt.setJwtConfig(jwtConfig)
        }

        configurePassport(authRepository, oauthConfig)
        configurePassportSerialization()
        isPassportConfigured = true
    }

    const router = express.Router()

    // OAuth - Google
    router.get('/google', (req, res, next) => {
        const { returnTo } = req.query
        if (returnTo && req.session) {
            req.session.returnTo = returnTo
        }

        passport.authenticate('google', {
            scope: ['profile', 'email']
        })(req, res, next)
    })

    router.get('/google/callback',
        passport.authenticate('google', { session: false }),
        async (req, res) => {
            const tokens = jwt.generateTokens(req.user)
            jwt.setTokenCookies(res, tokens)
            const redirectUrl = (req.session?.returnTo) || `/auth/callback`
            if (req.session?.returnTo) {
                delete req.session.returnTo
            }
            
            res.redirect(redirectUrl)
        }
    )

    // OAuth - Microsoft
    router.get('/microsoft', (req, res, next) => {
        const { returnTo } = req.query
        if (returnTo && req.session) {
            req.session.returnTo = returnTo
        }
        passport.authenticate('microsoft', {
            scope: ['user.read']
        })(req, res, next)
    })

    router.get('/microsoft/callback',
        passport.authenticate('microsoft', { session: false }),
        async (req, res) => {
            const tokens = jwt.generateTokens(req.user)
            jwt.setTokenCookies(res, tokens)
            const redirectUrl = (req.session?.returnTo) || `/auth/callback`
            if (req.session?.returnTo) {
                delete req.session.returnTo
            }
            res.redirect(redirectUrl)
        }
    )

    // OAuth - LinkedIn
    router.get('/linkedin', (req, res, next) => {
        const { returnTo } = req.query
        if (returnTo && req.session) {
            req.session.returnTo = returnTo
        }
        passport.authenticate('linkedin', {
            scope: ['r_emailaddress', 'r_liteprofile']
        })(req, res, next)
    })

    router.get('/linkedin/callback',
        passport.authenticate('linkedin', { session: false }),
        async (req, res) => {
            const tokens = jwt.generateTokens(req.user)
            jwt.setTokenCookies(res, tokens)
            const redirectUrl = (req.session?.returnTo) || `/auth/callback`
            if (req.session?.returnTo) {
                delete req.session.returnTo
            }
            res.redirect(redirectUrl)
        }
    )

    // Email/password login
    router.post('/login', async (req, res) => {
        try {
            const { email, password } = req.body

            if (!email || !password) {
                return res.status(400).json({ error: 'Email and password are required' })
            }

            const user = await authRepository.verifyPassword(email, password)
            const tokens = jwt.generateTokens(user)
            jwt.setTokenCookies(res, tokens)

            res.json({ success: true, user: sanitizeUser(user) })
        } catch (error) {
            res.status(401).json({ error: error.message })
        }
    })

    // Register
    router.post('/register', async (req, res) => {
        try {
            const { email, password, first, last } = req.body

            if (!email || !password) {
                return res.status(400).json({ error: 'Email and password are required' })
            }

            const user = await authRepository.createUser({ email, password, first, last })
            const tokens = jwt.generateTokens(user)
            jwt.setTokenCookies(res, tokens)

            res.json({ success: true, user: sanitizeUser(user) })
        } catch (error) {
            res.status(400).json({ error: error.message })
        }
    })

    // Refresh token
    router.post('/refresh', async (req, res) => {
        try {
            const refreshToken = req.cookies.refresh_token

            if (!refreshToken) {
                return res.status(401).json({ error: 'No refresh token provided' })
            }

            const decoded = jwt.verifyRefreshToken(refreshToken)
            const accessToken = jwt.generateAccessToken({ id: decoded.userId, email: decoded.email })

            jwt.setAccessTokenCookie(res, accessToken)
            res.json({ success: true })
        } catch (error) {
            res.status(401).json({ error: 'Invalid refresh token' })
        }
    })

    // Get current user
    router.get('/me', authenticate, async (req, res) => {
        try {
            const user = await authRepository.getUserById(req.user.userId)

            if (!user) {
                return res.status(404).json({ error: 'User not found' })
            }

            res.json({ user: sanitizeUser(user) })
        } catch (error) {
            res.status(500).json({ error: 'Failed to fetch user' })
        }
    })

    // Logout
    router.post('/logout', (req, res) => {
        jwt.clearTokenCookies(res)
        res.json({ success: true })
    })

    return router
}

function sanitizeUser(user) {
    const { password, ...sanitized } = user
    return sanitized
}

/** Configure passport strategies - call once during app initialization */
export function configurePassport(authRepository, oauth = {}) {
    // Google OAuth
    const googleConfig = oauth.google || (process.env.GOOGLE_CLIENT_ID ? {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET
    } : null)

    if (googleConfig) {
        passport.use(new GoogleStrategy({
            clientID: googleConfig.clientId,
            clientSecret: googleConfig.clientSecret,
            callbackURL: googleConfig.callbackURL || '/api/auth/google/callback'
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const user = await authRepository.findOrCreateUser({
                    provider: 'google',
                    id: profile.id,
                    email: profile.emails[0].value,
                    firstname: profile.name.givenName,
                    surname: profile.name.familyName,
                    avatar: profile.photos[0]?.value
                })
                done(null, user)
            } catch (error) {
                done(error, null)
            }
        }))
    }

    // Microsoft OAuth
    const microsoftConfig = oauth.microsoft || (process.env.MICROSOFT_CLIENT_ID ? {
        clientId: process.env.MICROSOFT_CLIENT_ID,
        clientSecret: process.env.MICROSOFT_CLIENT_SECRET
    } : null)

    if (microsoftConfig) {
        passport.use(new MicrosoftStrategy({
            clientID: microsoftConfig.clientId,
            clientSecret: microsoftConfig.clientSecret,
            callbackURL: microsoftConfig.callbackURL || '/api/auth/microsoft/callback',
            scope: ['user.read']
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const user = await authRepository.findOrCreateUser({
                    provider: 'microsoft',
                    id: profile.id,
                    email: profile.emails[0].value,
                    firstname: profile.name.givenName,
                    surname: profile.name.familyName,
                    avatar: null
                })
                done(null, user)
            } catch (error) {
                done(error, null)
            }
        }))
    }

    // LinkedIn OAuth
    const linkedinConfig = oauth.linkedin || (process.env.LINKEDIN_CLIENT_ID ? {
        clientId: process.env.LINKEDIN_CLIENT_ID,
        clientSecret: process.env.LINKEDIN_CLIENT_SECRET
    } : null)

    if (linkedinConfig) {
        passport.use(new LinkedInStrategy({
            clientID: linkedinConfig.clientId,
            clientSecret: linkedinConfig.clientSecret,
            callbackURL: linkedinConfig.callbackURL || '/api/auth/linkedin/callback',
            scope: ['r_emailaddress', 'r_liteprofile']
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const user = await authRepository.findOrCreateUser({
                    provider: 'linkedin',
                    id: profile.id,
                    email: profile.emails[0].value,
                    firstname: profile.name.givenName,
                    surname: profile.name.familyName,
                    avatar: profile.photos[0]?.value
                })
                done(null, user)
            } catch (error) {
                done(error, null)
            }
        }))
    }
}

/** Configure passport serialization for sessions */
function configurePassportSerialization() {
    // Serialize user to session (store minimal data)
    passport.serializeUser((user, done) => {
        done(null, user)
    })

    // Deserialize user from session
    passport.deserializeUser((user, done) => {
        done(null, user)
    })
}
