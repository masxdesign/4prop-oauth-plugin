import passport from 'passport'
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'
import { Strategy as MicrosoftStrategy } from 'passport-microsoft'
import { Strategy as LinkedInStrategy } from 'passport-linkedin-oauth2'
import jwt from '../services/jwt.js'
import { authenticate } from '../middleware/authenticate.js'

let isPassportConfigured = false

/** Create auth router - pass your Express app instance and auth repository */
export default function createAuthRouter(authRepository, expressApp) {
    // Auto-configure passport on first call
    if (!isPassportConfigured) {
        configurePassport(authRepository)
        isPassportConfigured = true
    }

    const router = expressApp.Router()

    // OAuth - Google
    router.get('/google', passport.authenticate('google', {
        scope: ['profile', 'email']
    }))

    router.get('/google/callback',
        passport.authenticate('google', { session: false }),
        async (req, res) => {
            const tokens = jwt.generateTokens(req.user)
            jwt.setTokenCookies(res, tokens)
            res.redirect(`${process.env.CLIENT_URL}/auth/callback`)
        }
    )

    // OAuth - Microsoft
    router.get('/microsoft', passport.authenticate('microsoft', {
        scope: ['user.read']
    }))

    router.get('/microsoft/callback',
        passport.authenticate('microsoft', { session: false }),
        async (req, res) => {
            const tokens = jwt.generateTokens(req.user)
            jwt.setTokenCookies(res, tokens)
            res.redirect(`${process.env.CLIENT_URL}/auth/callback`)
        }
    )

    // OAuth - LinkedIn
    router.get('/linkedin', passport.authenticate('linkedin', {
        scope: ['r_emailaddress', 'r_liteprofile']
    }))

    router.get('/linkedin/callback',
        passport.authenticate('linkedin', { session: false }),
        async (req, res) => {
            const tokens = jwt.generateTokens(req.user)
            jwt.setTokenCookies(res, tokens)
            res.redirect(`${process.env.CLIENT_URL}/auth/callback`)
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
export function configurePassport(authRepository) {
    // Google OAuth
    if (process.env.GOOGLE_CLIENT_ID) {
        passport.use(new GoogleStrategy({
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: '/api/auth/google/callback'
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
    if (process.env.MICROSOFT_CLIENT_ID) {
        passport.use(new MicrosoftStrategy({
            clientID: process.env.MICROSOFT_CLIENT_ID,
            clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
            callbackURL: '/api/auth/microsoft/callback',
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
    if (process.env.LINKEDIN_CLIENT_ID) {
        passport.use(new LinkedInStrategy({
            clientID: process.env.LINKEDIN_CLIENT_ID,
            clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
            callbackURL: '/api/auth/linkedin/callback',
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
