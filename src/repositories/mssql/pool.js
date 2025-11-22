import sql from 'mssql'

let pool = null
let poolConfig = null

export function setPoolConfig(config) {
    const fullConfig = {
        server: config.server || config.host,
        port: config.port || 1433,
        user: config.user || config.username,
        password: config.password,
        database: config.database,
        options: {
            encrypt: config.encrypt ?? true,
            trustServerCertificate: config.trustServerCertificate ?? true,
            ...config.options
        },
        pool: {
            max: 10,
            min: 0,
            idleTimeoutMillis: 30000,
            ...config.pool
        }
    }
    poolConfig = fullConfig
}

export async function getPool() {
    if (!pool) {
        // Fallback to env vars if config not set
        if (!poolConfig) {
            poolConfig = {
                server: process.env.DB_HOST,
                port: parseInt(process.env.DB_PORT || '1433'),
                user: process.env.DB_USER,
                password: process.env.DB_PASSWORD,
                database: process.env.DB_NAME,
                options: {
                    encrypt: true,
                    trustServerCertificate: true
                },
                pool: {
                    max: 10,
                    min: 0,
                    idleTimeoutMillis: 30000
                }
            }
        }
        pool = await sql.connect(poolConfig)
    }
    return pool
}

export async function closePool() {
    if (pool) {
        await pool.close()
        pool = null
        poolConfig = null
    }
}
