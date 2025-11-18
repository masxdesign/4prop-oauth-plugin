import { getPool } from './pool.js'
import bcrypt from 'bcryptjs'

/** Reference MSSQL implementation of auth repository */
export default class MSSQLAuthRepository {

    async findUserByEmail(email) {
        const pool = await getPool()
        const result = await pool.request()
            .input('email', email)
            .query('SELECT * FROM a_rcUsers WHERE email = @email')

        return result.recordset[0] || null
    }

    async findUserByOAuth(provider, oauthId) {
        const pool = await getPool()
        const result = await pool.request()
            .input('provider', provider)
            .input('oauthId', oauthId)
            .query('SELECT * FROM a_rcUsers WHERE oauth_provider = @provider AND oauth_id = @oauthId')

        return result.recordset[0] || null
    }

    async createUser(userData) {
        const pool = await getPool()

        // Hash password if provided
        const password = userData.password
            ? await bcrypt.hash(userData.password, 10)
            : null

        const result = await pool.request()
            .input('email', userData.email)
            .input('password', password)
            .input('first', userData.first || null)
            .input('last', userData.last || null)
            .input('provider', userData.provider || null)
            .input('oauthId', userData.oauthId || null)
            .input('avatar', userData.avatar || null)
            .query(`
                INSERT INTO a_rcUsers (email, password, first, last, oauth_provider, oauth_id, avatar)
                OUTPUT INSERTED.*
                VALUES (@email, @password, @first, @last, @provider, @oauthId, @avatar)
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

        const isValid = await bcrypt.compare(password, user.password)
        if (!isValid) {
            throw new Error('Invalid credentials')
        }

        return user
    }

    async getUserById(userId) {
        const pool = await getPool()
        const result = await pool.request()
            .input('userId', userId)
            .query('SELECT * FROM a_rcUsers WHERE id = @userId')

        return result.recordset[0] || null
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
