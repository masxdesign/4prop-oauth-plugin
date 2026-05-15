import { getPool, setPoolConfig } from './pool.js'
import phpPassword from 'node-php-password'
import sql from 'mssql'
import crc32 from 'crc-32'

/** Reference MSSQL implementation of auth repository */
export default class MSSQLAuthRepository {
    constructor(dbConfig = null) {
        if (dbConfig) {
            setPoolConfig(dbConfig)
        }
    }

    /**
     * Generate CRC32 hash from email (PHP-compatible)
     * @param {string} email
     * @returns {number} CRC32 hash
     */
    generateHash(email) {
        return crc32.str(email) >>> 0 // Convert to unsigned 32-bit integer
    }

    /**
     * Look up an a_rpNegotiator row by email. Returns null if no agent
     * has registered this address. Used by /register to redirect agents
     * to the login flow instead of creating a duplicate user.
     */
    async findNegotiatorByEmail(email) {
        const pool = await getPool()
        const result = await pool.request()
            .input('email', sql.VarChar(75), email)
            .query(`
                SELECT TOP 1 [NID], [firstname], [surname], [email]
                FROM a_rpNegotiator
                WHERE [email] = @email
            `)

        return result.recordset[0] || null
    }

    async findUserByEmail(email) {
        const pool = await getPool()
        const result = await pool.request()
            .input('email', email)
            .query(`
                SELECT
                    [id],
                    [first] [firstname],
                    [last] [surname],
                    [email],
                    [password],
                    [oauth_provider],
                    [oauth_id],
                    [avatar],
                    [last_login],
                    [neg_id],
                    [role],
                    [email_verified_at]
                FROM a_rcUsers WHERE email = @email
            `)

        return result.recordset[0] || null
    }

    async findUserByOAuth(provider, oauthId) {
        const pool = await getPool()
        const result = await pool.request()
            .input('provider', provider)
            .input('oauthId', oauthId)
            .query(`
                SELECT
                    [id],
                    [first] [firstname],
                    [last] [surname],
                    [email],
                    [oauth_provider],
                    [oauth_id],
                    [avatar],
                    [last_login],
                    [neg_id],
                    [role],
                    [email_verified_at]
                FROM a_rcUsers WHERE oauth_provider = @provider AND oauth_id = @oauthId
            `)

        return result.recordset[0] || null
    }

    async createUser(userData) {
        const pool = await getPool()

        // Hash password using PHP-compatible method if provided
        const password = userData.password
            ? phpPassword.hash(userData.password)
            : null

        // Generate hash field using CRC32 of email (same as PHP)
        const emailHash = this.generateHash(userData.email)

        // For OAuth signups (no password), auto-link to a negotiator if the
        // OAuth email matches one — preserves existing single-sign-on behavior
        // for agents. Password /register short-circuits agent emails upstream
        // in the route handler, so this branch only matters for OAuth.
        let negotiatorId = null
        if (!password) {
            const negotiator = await this.findNegotiatorByEmail(userData.email)
            negotiatorId = negotiator ? negotiator.NID : null
        }

        // OAuth signups (provider set, no password) inherit the provider's
        // email verification — write email_verified_at at insert time so
        // verify-required capabilities work immediately. Email/password
        // signups leave the column NULL; they must complete the verify flow.
        const isOAuthSignup = !!userData.provider && !password

        const result = await pool.request()
            .input('email', userData.email)
            .input('password', password)
            .input('first', userData.first || null)
            .input('last', userData.last || null)
            .input('company', userData.company || null)
            .input('provider', userData.provider || null)
            .input('oauthId', userData.oauthId || null)
            .input('avatar', userData.avatar || null)
            .input('hash', emailHash)
            .input('negId', negotiatorId)
            .query(`
                INSERT INTO a_rcUsers (email, password, first, last, company, oauth_provider, oauth_id, avatar, hash, neg_id, email_verified_at)
                OUTPUT
                    INSERTED.id,
                    INSERTED.email,
                    INSERTED.first AS firstname,
                    INSERTED.last  AS surname,
                    INSERTED.company,
                    INSERTED.oauth_provider,
                    INSERTED.oauth_id,
                    INSERTED.avatar,
                    INSERTED.hash,
                    INSERTED.neg_id,
                    INSERTED.role,
                    INSERTED.email_verified_at
                VALUES (@email, @password, @first, @last, @company, @provider, @oauthId, @avatar, @hash, @negId, ${isOAuthSignup ? "SYSUTCDATETIME()" : "NULL"})
            `)

        return result.recordset[0]
    }

    async updateUser(userId, updates) {
        const pool = await getPool()
        const request = pool.request().input('userId', userId)

        const setClauses = []
        if (updates.last_login) {
            request.input('lastLogin', updates.last_login)
            setClauses.push('last_login = @lastLogin')
        }
        if (updates.avatar) {
            request.input('avatar', updates.avatar)
            setClauses.push('avatar = @avatar')
        }

        if (setClauses.length === 0) return null

        const result = await request.query(`
            UPDATE a_rcUsers
            SET ${setClauses.join(', ')}
            OUTPUT INSERTED.*
            WHERE id = @userId
        `)

        return result.recordset[0]
    }

    async verifyPassword(email, password) {
        const user = await this.findUserByEmail(email)

        if (!user || !user.password) {
            throw new Error('Invalid credentials')
        }

        // Use PHP-compatible password verification
        const isValid = phpPassword.verify(password, user.password)
        if (!isValid) {
            throw new Error('Invalid credentials')
        }

        return user
    }

    async getUserById(userId) {
        const pool = await getPool()
        const result = await pool.request()
            .input('userId', userId)
            .query(`
                SELECT
                    u.[id],
                    COALESCE(u.[first], n.[firstname]) [firstname],
                    COALESCE(u.[last], n.[surname]) [surname],
                    COALESCE(u.[email], n.[email]) [email],
                    u.[oauth_provider],
                    u.[oauth_id],
                    COALESCE(u.[avatar], n.[picture]) [avatar],
                    u.[last_login],
                    u.[neg_id],
                    u.[role],
                    u.[email_verified_at],
                    n.[phone],
                    COALESCE(c.[name], u.[company]) [company]
                FROM a_rcUsers u
                LEFT JOIN a_rpNegotiator n ON n.[NID] = u.[neg_id]
                LEFT JOIN a_rcCompany c ON c.[cid] = n.[cid]
                WHERE u.[id] = @userId
            `)

        return result.recordset[0] || null
    }

    async getUserByNegId(negId) {
        const pool = await getPool()
        const result = await pool.request()
            .input('negId', sql.VarChar(20), negId)
            .query(`
                SELECT
                    u.[id],
                    COALESCE(u.[first], n.[firstname]) [firstname],
                    COALESCE(u.[last], n.[surname]) [surname],
                    COALESCE(u.[email], n.[email]) [email],
                    u.[oauth_provider],
                    u.[oauth_id],
                    COALESCE(u.[avatar], n.[picture]) [avatar],
                    u.[last_login],
                    u.[neg_id],
                    u.[role],
                    u.[email_verified_at],
                    n.[phone],
                    COALESCE(c.[name], u.[company]) [company]
                FROM a_rcUsers u
                LEFT JOIN a_rpNegotiator n ON n.[NID] = u.[neg_id]
                LEFT JOIN a_rcCompany c ON c.[cid] = n.[cid]
                WHERE u.[neg_id] = @negId
            `)

        return result.recordset[0] || null
    }

    /**
     * Get an a_rcUsers row by neg_id, provisioning one with role=ROLE_EACH (32) if absent.
     * Mirrors the bizchat enquiry provisioning pattern (see resolveAgentUserIds.js)
     * and the PHP getUserInsertEACHAgent equivalent.
     */
    async getOrCreateUserByNegId(negId) {
        const existing = await this.getUserByNegId(negId)
        if (existing) return existing

        const pool = await getPool()
        const insertResult = await pool.request()
            .input('negId', sql.VarChar(20), negId)
            .query(`
                INSERT INTO a_rcUsers (neg_id, role)
                OUTPUT CAST(INSERTED.id AS BIGINT) AS id
                VALUES (@negId, 32)
            `)

        const newId = insertResult.recordset[0]?.id
        if (!newId) {
            throw new Error(`Failed to provision a_rcUsers row for neg_id=${negId}`)
        }

        return this.getUserById(newId)
    }

    async findOrCreateUser(profile) {
        let user = await this.findUserByOAuth(profile.provider, profile.id)

        if (!user) {
            user = await this.createUser({
                email: profile.email,
                first: profile.firstname,
                last: profile.surname,
                avatar: profile.avatar,
                provider: profile.provider,
                oauthId: profile.id
            })
        } else {
            // Update last login
            user = await this.updateUser(user.id, {
                last_login: new Date()
            })
        }

        return user
    }

    // ── Email verification ──────────────────────────────────────────────────

    /**
     * Write a verification token (hash + expiry) onto the user row. The plain
     * token is never stored; the caller emails it. Overwrites any outstanding
     * token — resend issues a fresh one and invalidates the previous link.
     */
    async setEmailVerifyToken(userId, tokenHash, expiresAt) {
        const pool = await getPool()
        await pool.request()
            .input('userId', userId)
            .input('tokenHash', sql.VarChar(64), tokenHash)
            .input('expiresAt', sql.DateTime, expiresAt)
            .query(`
                UPDATE a_rcUsers
                SET [email_verify_token_hash] = @tokenHash,
                    [email_verify_token_expires_at] = @expiresAt
                WHERE [id] = @userId
            `)
    }

    /**
     * Consume a verification token: find by hash, check unexpired and not
     * already verified, mark verified and clear the token columns — all in a
     * single atomic UPDATE. Returns { id, email } on success, or null if the
     * hash is unknown, expired, or the account was already verified.
     *
     * Callers should treat all the null cases as the same 400 — we don't leak
     * the "already verified" state to avoid token-status enumeration.
     */
    async consumeEmailVerifyToken(tokenHash) {
        const pool = await getPool()
        const result = await pool.request()
            .input('tokenHash', sql.VarChar(64), tokenHash)
            .query(`
                UPDATE a_rcUsers
                SET [email_verified_at] = SYSUTCDATETIME(),
                    [email_verify_token_hash] = NULL,
                    [email_verify_token_expires_at] = NULL
                OUTPUT INSERTED.id, INSERTED.email
                WHERE [email_verify_token_hash] = @tokenHash
                  AND [email_verify_token_expires_at] IS NOT NULL
                  AND [email_verify_token_expires_at] > SYSUTCDATETIME()
                  AND [email_verified_at] IS NULL
            `)

        return result.recordset[0] || null
    }

    /**
     * Resend rate-limit lookup. Returns the most recent attempt timestamp and
     * count of attempts in the last 24h for this email. The caller decides
     * whether the 60s cooldown / 5-per-24h cap is exceeded.
     */
    async getEmailVerifyResendStats(email) {
        const pool = await getPool()
        const result = await pool.request()
            .input('email', sql.VarChar(75), email)
            .query(`
                SELECT
                    MAX([sent_at]) AS lastSentAt,
                    COUNT(*)       AS last24hCount
                FROM a_rcEmailVerifyAttempts
                WHERE [email] = @email
                  AND [sent_at] > DATEADD(HOUR, -24, SYSUTCDATETIME())
            `)

        const row = result.recordset[0] || {}
        return {
            lastSentAt: row.lastSentAt || null,
            last24hCount: row.last24hCount || 0,
        }
    }

    /**
     * Record a verification-email send. Append-only; older rows can be pruned
     * by a separate maintenance job (not in this code path).
     */
    async recordEmailVerifyAttempt(email) {
        const pool = await getPool()
        await pool.request()
            .input('email', sql.VarChar(75), email)
            .query(`
                INSERT INTO a_rcEmailVerifyAttempts ([email], [sent_at])
                VALUES (@email, SYSUTCDATETIME())
            `)
    }
}
