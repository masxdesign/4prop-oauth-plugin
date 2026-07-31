import express from 'express'
import passport from 'passport'
import phpPassword from 'node-php-password'
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'
import { Strategy as MicrosoftStrategy } from 'passport-microsoft'
import { Strategy as LinkedInStrategy } from 'passport-linkedin-oauth2'
import jwt from '../services/jwt.js'
import { authenticate, optionalAuth } from '../middleware/authenticate.js'
import { generateToken, hashToken } from '../utils/singleUseToken.js'
import { isAgentAccount, isEmailVerifiedForPolicy } from '../lib/emailVerification.js'
import { assertRateLimit, getClientIp, RateLimitError } from '../lib/rateLimit.js'
import { validateSignupInput, SignupValidationError } from '../lib/signupValidation.js'

// Resend rate-limit knobs — same for both verify and reset flows.
//
// The 60s COOLDOWN is the primary guard: it defeats rapid-fire bursts (the
// real mail-bombing vector) while staying invisible to a normal user. The
// 24h CAP is only a backstop, set generously (10) so a legitimate user who
// didn't get the first email — spam folder, typo, slow delivery — can retry
// across the day without being locked out. (A tight cap of 5 previously locked
// real users out after a handful of attempts.)
const RESEND_COOLDOWN_MS = 60 * 1000
const RESEND_MAX_PER_24H = 10

// Password-reset tokens are more sensitive than verify tokens, so they live
// for less time (1h vs 24h).
const PASSWORD_RESET_TTL_MS = 60 * 60 * 1000

// Minimum password length on reset. Matches the register form's client-side
// rule. Tightening later would need a one-time forced reset for users below
// the new floor.
const MIN_PASSWORD_LENGTH = 6
// Deliberately stricter than MIN_PASSWORD_LENGTH, which also governs register
// and token-driven reset. Someone changing a working password is making a free
// choice and should not be able to weaken the account below current guidance.
const CHANGE_PASSWORD_MIN_LENGTH = 8

const REGISTER_IP_LIMIT = 5
const REGISTER_IP_WINDOW_MS = 60 * 60 * 1000
const REGISTER_EMAIL_LIMIT = 3
const REGISTER_EMAIL_WINDOW_MS = 60 * 60 * 1000

// Role bitmask constants - aligned with PHP/4prop and bizchat dual-auth
export const ROLES = {
    USER: 2,
    AUTHOR: 4,
    ADMIN: 8,
    SEO_ADMIN: 16,
    EACH: 32,
    ADVERTISER: 64
}

const hasRole = (roleMask, role) => ((roleMask || 0) & role) === role

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

    jwt.setAuthCookieDefaults({
        cookieMode: config.cookieMode ?? 'same-site',
        cookies: config.cookies ?? {}
    })
    if (typeof config.resolveCookieMode === 'function' || typeof config.resolveCookieOverrides === 'function') {
        router.use(jwt.createCookieModeMiddleware(
            config.resolveCookieMode ?? (() => undefined),
            config.resolveCookieOverrides,
        ))
    }

    // Optional verification email sender. If provided, /register issues a
    // token and calls this; /resend-verification can also dispatch. Shape:
    //   async (user, plainToken, advertiserId, delivery?) => void
    // `delivery` comes from resolveAuthEmailDelivery when that hook is wired.
    const sendVerificationEmail = typeof config.sendVerificationEmail === 'function'
        ? config.sendVerificationEmail
        : null

    // Optional password-reset email sender. If provided, /forgot-password
    // issues a token and calls this; /reset-password consumes it.
    const sendPasswordResetEmail = typeof config.sendPasswordResetEmail === 'function'
        ? config.sendPasswordResetEmail
        : null

    // Optional sandbox delivery policy for auth emails. Called before each
    // verify/reset send so the host app controls who receives mail in sandbox
    // mode without forking the mailer. Shape:
    //   ({ kind: 'verify'|'reset', user, advertiserId }) => delivery
    const resolveAuthEmailDelivery = typeof config.resolveAuthEmailDelivery === 'function'
        ? config.resolveAuthEmailDelivery
        : null

    function resolveDelivery(kind, user, advertiserId) {
        return resolveAuthEmailDelivery?.({ kind, user, advertiserId }) ?? {}
    }

    /**
     * Issue + persist + email a new verification token for `user`. Records
     * the attempt for rate-limiting. Send is detached so the route response
     * isn't blocked on SES; failures are logged.
     */
    async function issueAndSendVerifyEmail(user, advertiserId) {
        if (isAgentAccount(user)) {
            return null
        }
        const { plain, hash, expiresAt } = generateToken()
        await authRepository.setEmailVerifyToken(user.id, hash, expiresAt)
        await authRepository.recordAuthEmailAttempt(user.email, 'verify')
        if (sendVerificationEmail) {
            const delivery = resolveDelivery('verify', user, advertiserId)
            Promise.resolve()
                .then(() => sendVerificationEmail(user, plain, advertiserId, delivery))
                .catch((err) => console.error('[verifyEmail] send failed for', user.email, err))
        }
        return plain
    }

    /**
     * Issue + persist + email a new password-reset token. Detached send
     * (failures logged). The token TTL is 1h — shorter than verification
     * because the reset link grants control of the password.
     */
    async function issueAndSendResetEmail(user, advertiserId, returnTo = null) {
        const { plain, hash, expiresAt } = generateToken({ ttlMs: PASSWORD_RESET_TTL_MS })
        await authRepository.setPasswordResetToken(user.id, hash, expiresAt)
        await authRepository.recordAuthEmailAttempt(user.email, 'reset')
        if (sendPasswordResetEmail) {
            const delivery = resolveDelivery('reset', user, advertiserId)
            Promise.resolve()
                .then(() => sendPasswordResetEmail(user, plain, advertiserId, delivery, returnTo))
                .catch((err) => console.error('[resetPassword] send failed for', user.email, err))
        }
        return plain
    }

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

    // Check whether an email belongs to an EACH agent (a_rpNegotiator row).
    // Used by the register form to short-circuit before the user fills
    // out the rest of the fields. Returns { isAgent: true|false }.
    // Note: same information already leaks via /register's 409 response,
    // so this endpoint doesn't expand the existing enumeration surface.
    router.get('/check-agent-email', async (req, res) => {
        try {
            const email = typeof req.query.email === 'string' ? req.query.email.trim() : ''

            if (!email) {
                return res.status(400).json({ error: 'email query parameter is required' })
            }

            if (typeof authRepository.findNegotiatorByEmail !== 'function') {
                // Repo doesn't support the lookup — fail open so registration
                // still works on auth backends that don't implement this.
                return res.json({ isAgent: false })
            }

            const negotiator = await authRepository.findNegotiatorByEmail(email)
            res.json({ isAgent: !!negotiator })
        } catch (error) {
            res.status(500).json({ error: error.message })
        }
    })

    // Email availability — lets the register form fail fast on blur instead of
    // letting the user fill the whole form only to be rejected on submit.
    // Returns { available } where available = no regular account AND no agent
    // record uses this email. Mirrors the duplicate checks inside /register
    // (findUserByEmail + findNegotiatorByEmail) so the two never disagree.
    //
    // Enumeration note: this discloses whether an email has an account — the
    // same trade-off already accepted by /check-agent-email. A light per-IP
    // rate limit blunts bulk probing. Fails OPEN (available: true) on missing
    // repo support or errors so registration is never blocked by this check.
    router.get('/check-email', async (req, res) => {
        try {
            const email = typeof req.query.email === 'string' ? req.query.email.trim() : ''

            if (!email) {
                return res.status(400).json({ error: 'email query parameter is required' })
            }

            assertRateLimit(
                `check-email:ip:${getClientIp(req)}`,
                30,
                60 * 1000,
            )

            const [existingUser, negotiator] = await Promise.all([
                typeof authRepository.findUserByEmail === 'function'
                    ? authRepository.findUserByEmail(email)
                    : null,
                typeof authRepository.findNegotiatorByEmail === 'function'
                    ? authRepository.findNegotiatorByEmail(email)
                    : null,
            ])

            res.json({
                available: !existingUser && !negotiator,
                // Surface the agent case so the form can route to the EACH
                // login flow rather than a generic "already registered".
                isAgent: !!negotiator,
            })
        } catch (error) {
            if (error instanceof RateLimitError) {
                res.setHeader('Retry-After', String(error.retryAfter))
                return res.status(429).json({ error: error.message, retryAfter: error.retryAfter })
            }
            res.status(500).json({ error: error.message })
        }
    })

    // Register
    router.post('/register', async (req, res) => {
        try {
            const { advertiserId } = req.body

            assertRateLimit(
                `register:ip:${getClientIp(req)}`,
                REGISTER_IP_LIMIT,
                REGISTER_IP_WINDOW_MS,
            )

            let signup
            try {
                signup = validateSignupInput(req.body, {
                    minPasswordLength: MIN_PASSWORD_LENGTH,
                })
            } catch (error) {
                if (error instanceof SignupValidationError) {
                    return res.status(400).json({ error: error.message })
                }
                throw error
            }

            assertRateLimit(
                `register:email:${signup.email}`,
                REGISTER_EMAIL_LIMIT,
                REGISTER_EMAIL_WINDOW_MS,
            )

            // advertiserId is required only when verification email sending is
            // wired — the mailer needs it to build the correct verify URL host.
            // Without verification wired we don't care, so registrations still
            // work for any consumer that doesn't configure a sender.
            if (sendVerificationEmail && advertiserId == null) {
                return res.status(400).json({ error: 'advertiserId is required' })
            }

            // If this email belongs to an EACH agent, refuse and tell the
            // frontend to redirect to the login flow with a notice. Avoids
            // creating a duplicate non-agent record for someone who already
            // has agent credentials.
            if (typeof authRepository.findNegotiatorByEmail === 'function') {
                const negotiator = await authRepository.findNegotiatorByEmail(signup.email)
                if (negotiator) {
                    return res.status(409).json({
                        error: 'This email is registered as an EACH agent. Sign in with your EACH credentials instead.',
                        code: 'AGENT_EMAIL_EXISTS',
                        email: signup.email,
                    })
                }
            }

            if (typeof authRepository.findUserByEmail === 'function') {
                const existingUser = await authRepository.findUserByEmail(signup.email)
                if (existingUser) {
                    return res.status(409).json({ error: 'Email already registered' })
                }
            }

            const user = await authRepository.createUser({
                email: signup.email,
                password: signup.password,
                first: signup.first,
                last: signup.last,
                company: signup.company,
            })
            const tokens = jwt.generateTokens(user)
            jwt.setTokenCookies(res, tokens)

            // Soft gate: user is already signed in. The verification email
            // unlocks verify-required capabilities later. Skipped when the
            // consumer didn't wire a sender.
            if (sendVerificationEmail) {
                try {
                    await issueAndSendVerifyEmail(user, advertiserId)
                } catch (err) {
                    // Failure to enqueue the email shouldn't block registration —
                    // the user can request a resend.
                    console.error('[register] issueAndSendVerifyEmail failed:', err.message)
                }
            }

            res.json({ success: true, user: sanitizeUser(user) })
        } catch (error) {
            if (error instanceof RateLimitError) {
                res.setHeader('Retry-After', String(error.retryAfter))
                return res.status(429).json({
                    error: error.message,
                    retryAfter: error.retryAfter,
                })
            }
            res.status(400).json({ error: error.message })
        }
    })

    // Email verification — consume the token from the link in the verification
    // email. Public: the user may or may not be signed in when they click. On
    // success, marks the account verified and clears the token. Unknown /
    // expired / already-consumed tokens all return the same 400 so we don't
    // leak token-status information.
    router.get('/verify-email', async (req, res) => {
        try {
            const { token } = req.query
            if (!token || typeof token !== 'string') {
                return res.status(400).json({ error: 'Missing token' })
            }
            if (typeof authRepository.consumeEmailVerifyToken !== 'function') {
                return res.status(501).json({ error: 'Verification not supported by this auth backend' })
            }
            const tokenHash = hashToken(token)
            const verifiedUser = await authRepository.consumeEmailVerifyToken(tokenHash)
            if (!verifiedUser) {
                return res.status(400).json({ error: 'Invalid or expired token' })
            }
            res.json({ success: true })
        } catch (error) {
            console.error('Email verification error:', error)
            res.status(500).json({ error: 'Verification failed' })
        }
    })

    // Resend the verification email. Requires auth — caller must be signed in
    // (the soft-gate flow gives every registrant a session). Rate-limited:
    //   - reject if last send for this email was < 60s ago (429 with retryAfter)
    //   - reject if >= 5 sends in the last 24h (429 with retryAfter)
    //
    // Requires advertiserId in the body so the resent email is branded to the
    // advertiser site the user is currently looking at.
    router.post('/resend-verification', authenticate, async (req, res) => {
        try {
            if (
                typeof authRepository.getEmailVerifyResendStats !== 'function' ||
                !sendVerificationEmail
            ) {
                return res.status(501).json({ error: 'Verification not supported' })
            }

            const { advertiserId } = req.body || {}
            if (advertiserId == null) {
                return res.status(400).json({ error: 'advertiserId is required' })
            }

            const user = await authRepository.getUserById(req.user.userId)
            if (!user) {
                return res.status(404).json({ error: 'User not found' })
            }
            if (isEmailVerifiedForPolicy(user)) {
                // Already verified (or agent — verification not required).
                return res.status(409).json({ error: 'Email already verified' })
            }

            const { lastSentAt, last24hCount } = await authRepository.getEmailVerifyResendStats(user.email)
            const now = Date.now()

            if (lastSentAt) {
                const since = now - new Date(lastSentAt).getTime()
                if (since < RESEND_COOLDOWN_MS) {
                    const retryAfter = Math.ceil((RESEND_COOLDOWN_MS - since) / 1000)
                    res.setHeader('Retry-After', String(retryAfter))
                    return res.status(429).json({ error: 'Please wait before requesting another email', retryAfter })
                }
            }

            if (last24hCount >= RESEND_MAX_PER_24H) {
                // 24h-cap exceeded. retryAfter is approximate — until the oldest
                // attempt in the window ages out. A generic 1h hint is fine; we
                // don't need the precise oldest_sent_at for UX.
                res.setHeader('Retry-After', '3600')
                return res.status(429).json({
                    error: 'Too many verification emails — try again later',
                    retryAfter: 3600,
                })
            }

            await issueAndSendVerifyEmail(user, advertiserId)
            res.json({ success: true })
        } catch (error) {
            console.error('Resend verification error:', error)
            res.status(500).json({ error: 'Resend failed' })
        }
    })

    // Request a password-reset email. Public — the user has no session yet
    // since they're trying to recover access. Body: { email, advertiserId }.
    //
    // Enumeration-safe: always returns 200 success regardless of whether the
    // email matches a user. Bot can't tell from the response which addresses
    // have accounts. Rate-limiting is keyed on the supplied email, so spamming
    // a single address is bounded even when no account exists.
    router.post('/forgot-password', async (req, res) => {
        try {
            if (
                typeof authRepository.setPasswordResetToken !== 'function' ||
                !sendPasswordResetEmail
            ) {
                return res.status(501).json({ error: 'Password reset not supported' })
            }

            const { email, advertiserId } = req.body || {}
            if (!email || typeof email !== 'string') {
                return res.status(400).json({ error: 'Email is required' })
            }
            if (advertiserId == null) {
                return res.status(400).json({ error: 'advertiserId is required' })
            }

            // Where to send the user back after they save the new password — the
            // page (incl. filters) they were on when they hit "forgot password".
            // Open-redirect guard: accept ONLY a relative same-origin path
            // ("/...", not "//host" or "https://..."). Anything else is dropped.
            const returnTo = sanitizeRelativePath(req.body?.returnTo)

            // Rate-limit BEFORE the user lookup so we don't leak existence via
            // timing differences. Cooldown / cap apply to the supplied email
            // regardless of whether it matches a user.
            const { lastSentAt, last24hCount } =
                await authRepository.getAuthEmailResendStats(email, 'reset')
            const now = Date.now()
            if (lastSentAt) {
                const since = now - new Date(lastSentAt).getTime()
                if (since < RESEND_COOLDOWN_MS) {
                    // Still tell the client "success" — we don't want timing
                    // attacks to reveal account state. The user gets no email
                    // this time; their next request after the cooldown wins.
                    return res.json({ success: true })
                }
            }
            if (last24hCount >= RESEND_MAX_PER_24H) {
                return res.json({ success: true })
            }

            const user = await authRepository.findUserByEmail(email)
            if (user && user.password) {
                // Only password-bearing accounts can be reset. OAuth-only
                // users (no password column) can't recover via this flow —
                // they sign in through their provider.
                await issueAndSendResetEmail(user, advertiserId, returnTo)
            }
            // Always 200, whether we sent or not.
            res.json({ success: true })
        } catch (error) {
            console.error('Forgot-password error:', error)
            // Still pretend success to the client to avoid enumeration; log
            // the real error for ops.
            res.json({ success: true })
        }
    })

    // Consume a reset token + set the new password. Public.
    // Body: { token, password }.
    //
    // On success: signs the user in (sets JWT cookies) AND marks the email
    // verified — clicking the link proves inbox ownership.
    router.post('/reset-password', async (req, res) => {
        try {
            if (typeof authRepository.consumePasswordResetToken !== 'function') {
                return res.status(501).json({ error: 'Password reset not supported' })
            }

            const { token, password } = req.body || {}
            if (!token || typeof token !== 'string') {
                return res.status(400).json({ error: 'Missing token' })
            }
            if (!password || typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
                return res.status(400).json({
                    error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters`,
                })
            }

            const tokenHash = hashToken(token)
            const hashedPassword = phpPassword.hash(password)
            const user = await authRepository.consumePasswordResetToken(tokenHash, hashedPassword)
            if (!user) {
                return res.status(400).json({ error: 'Invalid or expired token' })
            }

            // Sign the user in straight away — same convention as register.
            const tokens = jwt.generateTokens(user)
            jwt.setTokenCookies(res, tokens)

            res.json({ success: true })
        } catch (error) {
            console.error('Reset-password error:', error)
            res.status(500).json({ error: 'Reset failed' })
        }
    })

    // Change password for the signed-in user.
    //
    // Distinct from /reset-password, which is token-driven for someone locked
    // out. This one proves identity with the CURRENT password, so it needs no
    // email round-trip.
    //
    // Agents are refused: their password lives in the EACH `negotiator` table,
    // not here, and 4prop mirrors it. They are directed to each.co.uk.
    router.post('/change-password', authenticate, async (req, res) => {
        try {
            if (typeof authRepository.getUserCredentialsById !== 'function' ||
                typeof authRepository.updatePasswordById !== 'function') {
                return res.status(501).json({ error: 'Password change not supported' })
            }

            // Guessing the current password must not be cheap.
            assertRateLimit(`change-password:user:${req.user.userId}`, 10, 15 * 60 * 1000)

            const { currentPassword, newPassword } = req.body || {}

            if (!currentPassword || typeof currentPassword !== 'string' ||
                !newPassword || typeof newPassword !== 'string') {
                return res.status(400).json({
                    error: 'Missing required fields: currentPassword, newPassword',
                })
            }

            // Stricter than MIN_PASSWORD_LENGTH: a user choosing a NEW password
            // deliberately should not be able to weaken an existing account.
            if (newPassword.length < CHANGE_PASSWORD_MIN_LENGTH) {
                return res.status(400).json({
                    error: `Password must be at least ${CHANGE_PASSWORD_MIN_LENGTH} characters`,
                })
            }

            if (newPassword === currentPassword) {
                return res.status(400).json({
                    error: 'New password must be different from the current password',
                })
            }

            const user = await authRepository.getUserCredentialsById(req.user.userId)
            if (!user) {
                return res.status(404).json({ error: 'User account not found' })
            }

            if (isAgentAccount(user)) {
                return res.status(403).json({
                    error: 'Your password is managed by EACH. Please change it at each.co.uk.',
                    code: 'EACH_MANAGED_PASSWORD',
                })
            }

            if (!user.password) {
                // OAuth-only account: there is no password to verify against.
                return res.status(400).json({
                    error: user.oauth_provider
                        ? `This account signs in with ${user.oauth_provider}. Set a password using the forgot-password email instead.`
                        : 'This account has no password set. Use the forgot-password email to set one.',
                    code: 'NO_PASSWORD_SET',
                })
            }

            if (!phpPassword.verify(currentPassword, user.password)) {
                // 400, NOT 401. Clients treat 401 as "session expired" and will
                // try to refresh (and may sign the user out) — a wrong current
                // password is a form error, not an authentication failure.
                return res.status(400).json({
                    error: 'Current password is incorrect',
                    code: 'INCORRECT_CURRENT_PASSWORD',
                })
            }

            const updated = await authRepository.updatePasswordById(
                req.user.userId,
                phpPassword.hash(newPassword),
            )

            if (!updated) {
                return res.status(404).json({ error: 'User account not found' })
            }

            res.json({ success: true })
        } catch (error) {
            if (error instanceof RateLimitError) {
                return res.status(429).json({ error: error.message, retryAfter: error.resetIn })
            }
            console.error('Change-password error:', error)
            res.status(500).json({ error: 'Password change failed' })
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
            const targetUser = await authRepository.getUserById(decoded.userId)

            if (!targetUser) {
                return res.status(401).json({ error: 'User not found' })
            }

            const impersonationOptions = decoded.impersonating
                ? {
                    impersonationAllowedMutations: Array.isArray(decoded.impersonationAllowedMutations)
                        ? decoded.impersonationAllowedMutations
                        : undefined,
                }
                : {}

            const accessToken = decoded.impersonating
                ? jwt.generateImpersonationAccessToken(
                    targetUser,
                    { id: decoded.adminUserId, email: decoded.adminEmail },
                    impersonationOptions,
                )
                : jwt.generateAccessToken(targetUser)

            jwt.setAccessTokenCookie(res, accessToken)
            res.json({ success: true })
        } catch (error) {
            res.status(401).json({ error: 'Invalid refresh token' })
        }
    })

    // Get current user
    // `optionalAuth` (not `authenticate`) so an anonymous visitor gets a plain
    // 200 { user: null } instead of a 401. `/me` is a "who am I" probe the SPA
    // fires on every page to discover its auth state; for a logged-out visitor a
    // 401 is the *expected* answer, but the browser logs every 401 as a console
    // error (surfaced by Lighthouse's "Browser errors" audit) and that cannot be
    // silenced from JS. Returning "nobody" as a success removes the noise. The
    // frontend treats `user: null` as anonymous, exactly as it treated the 401.
    router.get('/me', optionalAuth, async (req, res) => {
        try {
            // No / invalid token → anonymous. Not an error: the caller just isn't
            // signed in, which is a normal state for a public listing page.
            //
            // `canRefresh` tells the SPA whether a POST /refresh could plausibly
            // recover a session. The refresh cookie is httpOnly, so the client
            // can't check for itself; without this hint it must probe /refresh on
            // every anonymous page load and eat a 401 the browser logs to the
            // console. false ⇒ no cookie at all ⇒ skip the probe entirely.
            if (!req.user) {
                return res.json({ user: null, canRefresh: !!req.cookies?.refresh_token })
            }

            const user = await authRepository.getUserById(req.user.userId)

            // Valid token but the user no longer exists (deleted account with a
            // still-live token). The session is effectively anonymous — report it
            // as such rather than a 404, so the SPA cleanly falls back to logged-out.
            // Refreshing can't conjure the user back, so never suggest a retry.
            if (!user) {
                return res.json({ user: null, canRefresh: false })
            }

            const payload = {
                ...sanitizeUser(user),
                impersonating: !!req.user.impersonating
            }

            if (req.user.impersonating && req.user.adminUserId) {
                const adminUser = await authRepository.getUserById(req.user.adminUserId)
                if (adminUser) {
                    payload.originalUser = {
                        id: adminUser.id,
                        email: adminUser.email,
                        firstname: adminUser.firstname,
                        surname: adminUser.surname,
                        neg_id: adminUser.neg_id ?? null,
                        // Department of the real operator — lets the frontend run
                        // same-department colleague checks against the operator
                        // (not the impersonated user) when offering a nested switch.
                        did: adminUser.did ?? null,
                        avatar: adminUser.avatar ?? null,
                        // Role lets the frontend palette reflect the admin's own
                        // capabilities (not the impersonated user's) while impersonating.
                        role: adminUser.role ?? null
                    }
                }
            }

            if (req.user.impersonating && Array.isArray(req.user.impersonationAllowedMutations)) {
                payload.impersonationAllowedMutations = req.user.impersonationAllowedMutations
            }

            res.json({ user: payload })
        } catch (error) {
            res.status(500).json({ error: 'Failed to fetch user' })
        }
    })

    // Logout
    router.post('/logout', (req, res) => {
        jwt.clearTokenCookies(res)
        if (typeof config.clearExtraAuthCookies === 'function') {
            config.clearExtraAuthCookies(req, res)
        }
        res.json({ success: true })
    })

    // Get access token for cross-domain use
    router.get('/access-token', authenticate, (req, res) => {
        try {
            // Extract the access token from the httpOnly cookie
            const accessToken = req.cookies.access_token

            if (!accessToken) {
                return res.status(401).json({ error: 'No access token available' })
            }

            // Return the token with metadata
            res.json({
                access_token: accessToken,
                token_type: 'Bearer',
                expires_in: 900 // 15 minutes in seconds
            })
        } catch (error) {
            res.status(500).json({ error: 'Failed to retrieve access token' })
        }
    })

    // Start impersonating a target user.
    // Admin: full impersonation (omit allowedMutations) or read-only (allowedMutations: []).
    // Agent (EACH + neg_id): same-DID colleague only with allowedMutations: [].
    router.post('/impersonate', authenticate, async (req, res) => {
        try {
            // Allow switching targets without exiting first: when already
            // impersonating, the real operator is the original admin/agent
            // (adminUserId claim), not the impersonated user. Re-authorize
            // against that operator and issue a fresh token.
            const callerId = req.user.impersonating
                ? req.user.adminUserId
                : req.user.userId

            if (!callerId) {
                return res.status(401).json({ error: 'Caller not identified in token' })
            }

            const caller = await authRepository.getUserById(callerId)
            if (!caller) {
                return res.status(401).json({ error: 'Caller not found' })
            }

            const body = req.body || {}
            const { targetUserId, targetNegId, allowedMutations } = body

            let restrictions = null
            if (allowedMutations !== undefined && allowedMutations !== null) {
                if (!Array.isArray(allowedMutations)) {
                    return res.status(400).json({ error: 'allowedMutations must be an array' })
                }
                restrictions = allowedMutations
            }

            const isAdmin = hasRole(caller.role, ROLES.ADMIN)
            const isAgent = caller.neg_id != null
                && caller.neg_id !== ''
                && hasRole(caller.role, ROLES.EACH)

            if (!isAdmin && !isAgent) {
                return res.status(403).json({ error: 'Not authorized to impersonate' })
            }

            if (isAgent && !isAdmin) {
                if (targetUserId) {
                    return res.status(403).json({ error: 'Agents must impersonate colleagues via targetNegId' })
                }
                if (!targetNegId) {
                    return res.status(400).json({ error: 'targetNegId is required' })
                }
                if (!Array.isArray(restrictions) || restrictions.length !== 0) {
                    return res.status(403).json({
                        error: 'Colleague impersonation requires allowedMutations: []',
                    })
                }
            }

            if (!targetUserId && !targetNegId) {
                return res.status(400).json({ error: 'targetUserId or targetNegId is required' })
            }

            const targetUser = targetNegId
                ? await authRepository.getOrCreateUserByNegId(targetNegId)
                : await authRepository.getUserById(targetUserId)

            if (!targetUser) {
                return res.status(404).json({ error: 'Target user not found' })
            }

            if (hasRole(targetUser.role, ROLES.ADMIN)) {
                return res.status(403).json({ error: 'Cannot impersonate admin users' })
            }

            if (isAgent && !isAdmin) {
                if (!targetUser.neg_id) {
                    return res.status(403).json({ error: 'Target is not an agent account' })
                }
                if (
                    caller.did == null
                    || targetUser.did == null
                    || String(caller.did) !== String(targetUser.did)
                ) {
                    return res.status(403).json({ error: 'Target must be in your department' })
                }
                if (String(caller.neg_id) === String(targetUser.neg_id)) {
                    return res.status(403).json({ error: 'Cannot impersonate yourself' })
                }
            }

            const impersonationOptions = Array.isArray(restrictions)
                ? { impersonationAllowedMutations: restrictions }
                : {}

            const tokens = jwt.generateImpersonationTokens(targetUser, caller, impersonationOptions)
            jwt.setTokenCookies(res, tokens)

            const responsePayload = {
                token: tokens.accessToken,
                impersonating: true,
                targetUser: sanitizeUser(targetUser),
                originalUser: {
                    id: caller.id,
                    email: caller.email,
                    firstname: caller.firstname,
                    surname: caller.surname,
                    neg_id: caller.neg_id ?? null,
                    avatar: caller.avatar ?? null,
                    role: caller.role ?? null,
                },
            }

            if (Array.isArray(restrictions)) {
                responsePayload.impersonationAllowedMutations = restrictions
            }

            res.json(responsePayload)
        } catch (error) {
            res.status(500).json({ error: error.message || 'Failed to impersonate' })
        }
    })

    // Exit impersonation, restoring the admin's normal session.
    router.post('/impersonate/exit', authenticate, async (req, res) => {
        try {
            if (!req.user.impersonating) {
                return res.status(400).json({ error: 'Not currently impersonating' })
            }

            const adminUserId = req.user.adminUserId
            if (!adminUserId) {
                return res.status(400).json({ error: 'Admin user ID not found in token' })
            }

            const adminUser = await authRepository.getUserById(adminUserId)
            if (!adminUser) {
                return res.status(404).json({ error: 'Admin user not found' })
            }

            const tokens = jwt.generateTokens(adminUser)
            jwt.setTokenCookies(res, tokens)

            res.json({
                token: tokens.accessToken,
                impersonating: false,
                user: sanitizeUser(adminUser)
            })
        } catch (error) {
            res.status(500).json({ error: error.message || 'Failed to exit impersonation' })
        }
    })

    // Admin-only "full login as": mint the target's NORMAL session (no
    // impersonation wrapper, no adminUserId, no return-to-admin). The caller
    // becomes the target exactly as if they had logged in with the target's
    // password — so the target's own features (e.g. an agent's colleague
    // switch) work, since there is no impersonation layer to block them.
    //
    // This is NOT a password bypass: the caller is already authenticated and
    // must be an admin. /login and verifyPassword are untouched.
    router.post('/login-as', authenticate, async (req, res) => {
        try {
            // When already impersonating, authorize against the real admin
            // (adminUserId), not the impersonated account — same as /impersonate.
            const callerId = req.user.impersonating
                ? req.user.adminUserId
                : req.user.userId

            if (!callerId) {
                return res.status(401).json({ error: 'Caller not identified in token' })
            }

            const caller = await authRepository.getUserById(callerId)
            if (!caller) {
                return res.status(401).json({ error: 'Caller not found' })
            }

            // Admin only — this is the privileged "real login" door. No agent
            // path: agents use /impersonate for read-only colleague access.
            if (!hasRole(caller.role, ROLES.ADMIN)) {
                return res.status(403).json({ error: 'Not authorized' })
            }

            const { targetUserId, targetNegId } = req.body || {}

            if (!targetUserId && !targetNegId) {
                return res.status(400).json({ error: 'targetUserId or targetNegId is required' })
            }

            const targetUser = targetNegId
                ? await authRepository.getOrCreateUserByNegId(targetNegId)
                : await authRepository.getUserById(targetUserId)

            if (!targetUser) {
                return res.status(404).json({ error: 'Target user not found' })
            }

            // An admin must not be able to mint another admin's real session.
            if (hasRole(targetUser.role, ROLES.ADMIN)) {
                return res.status(403).json({ error: 'Cannot log in as admin users' })
            }

            // Audit: the issued session is no longer self-attributing, so log
            // who minted it.
            console.warn(
                `[login-as] admin ${caller.id} <${caller.email}> minted full session for target ${targetUser.id} <${targetUser.email}>`
            )

            // Normal (non-impersonation) tokens — same as /login.
            const tokens = jwt.generateTokens(targetUser)
            jwt.setTokenCookies(res, tokens)

            res.json({ success: true, user: sanitizeUser(targetUser) })
        } catch (error) {
            res.status(500).json({ error: error.message || 'Failed to log in as target' })
        }
    })

    return router
}

function sanitizeUser(user) {
    const {
        password,
        email_verified_at,
        email_verify_token_hash,
        email_verify_token_expires_at,
        ...sanitized
    } = user
    return {
        ...sanitized,
        // Agents (neg_id) are exempt from the seeker verification flow.
        emailVerified: isEmailVerifiedForPolicy(user),
    }
}

/**
 * Accept ONLY a safe relative router path for redirect-after-action use
 * (e.g. the password-reset returnTo). Returns the cleaned path or null.
 *
 * Rejects anything that could redirect off-site:
 *   - non-strings / empty
 *   - absolute URLs ("https://evil.com", "javascript:…")
 *   - protocol-relative ("//evil.com")
 *   - paths not starting with a single "/"
 * Caps length to keep the reset-email URL sane.
 */
function sanitizeRelativePath(value) {
    if (typeof value !== 'string') return null
    const v = value.trim()
    if (!v) return null
    if (v.length > 2048) return null
    // Must be a single-slash-rooted path. "//x" (protocol-relative) and any
    // "scheme:" prefix are rejected.
    if (!v.startsWith('/') || v.startsWith('//')) return null
    if (/^[a-z][a-z0-9+.-]*:/i.test(v)) return null
    // Backslashes are normalised to "/" by some browsers → treat as off-site.
    if (v.includes('\\')) return null
    return v
}

/** Configure passport strategies - call once during app initialization */
export function configurePassport(authRepository, oauth = {}) {
    // Google OAuth
    const googleConfig = oauth.google

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
    const microsoftConfig = oauth.microsoft

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
    const linkedinConfig = oauth.linkedin

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
