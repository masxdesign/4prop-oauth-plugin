import sql from 'mssql'

let pool = null

const config = {
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

export async function getPool() {
    if (!pool) {
        pool = await sql.connect(config)
    }
    return pool
}

export async function closePool() {
    if (pool) {
        await pool.close()
        pool = null
    }
}
