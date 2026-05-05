import { getPool, setPoolConfig } from './pool.js'
import phpPassword from 'node-php-password'
import sql from 'mssql'

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
        const crc32 = require('crc-32')
        return crc32.str(email) >>> 0 // Convert to unsigned 32-bit integer
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
                    [role]
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
                    [role]
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

        // Check if negotiator exists with this email
        const negotiatorResult = await pool.request()
            .input('email', sql.VarChar(75), userData.email)
            .query(`
                SELECT TOP 1 [NID]
                FROM a_rpNegotiator
                WHERE [email] = @email
            `)

        const negotiatorId = negotiatorResult.recordset.length > 0
            ? negotiatorResult.recordset[0].NID
            : null

        const result = await pool.request()
            .input('email', userData.email)
            .input('password', password)
            .input('first', userData.first || null)
            .input('last', userData.last || null)
            .input('provider', userData.provider || null)
            .input('oauthId', userData.oauthId || null)
            .input('avatar', userData.avatar || null)
            .input('hash', emailHash)
            .input('negId', negotiatorId)
            .query(`
                INSERT INTO a_rcUsers (email, password, first, last, oauth_provider, oauth_id, avatar, hash, neg_id)
                OUTPUT INSERTED.*
                VALUES (@email, @password, @first, @last, @provider, @oauthId, @avatar, @hash, @negId)
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
                    n.[phone],
                    c.[name] [company]
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
                    n.[phone],
                    c.[name] [company]
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
}
