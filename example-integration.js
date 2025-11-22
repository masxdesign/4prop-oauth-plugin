import express from 'express'
import session from 'express-session'
import passport from 'passport'

// Import auth plugin (when installed as npm package)
import createAuthRouter from '@4prop/oauth'
import { authenticate } from '@4prop/oauth/middleware'

// Import MSSQL repository or use your custom one
import MSSQLAuthRepository from '@4prop/oauth/mssql'

const app = express()

// Configuration (can come from config file, env vars, etc.)
const config = {
    database: {
        server: 'localhost',
        database: 'mydb',
        user: 'sa',
        password: 'password'
    },
    jwt: {
        accessSecret: 'your-access-secret',
        refreshSecret: 'your-refresh-secret'
    },
    session: {
        secret: 'your-session-secret'
    },
    oauth: {
        google: {
            clientId: 'your-google-client-id',
            clientSecret: 'your-google-client-secret'
        }
    }
}

// Middleware
app.use(express.json())
app.use(session({
    secret: config.session.secret,
    resave: false,
    saveUninitialized: false
})) // Required for OAuth returnTo functionality
app.use(passport.initialize())

// Initialize auth with config
const authRepo = new MSSQLAuthRepository(config.database)
const authRouter = createAuthRouter(authRepo, {
    jwt: config.jwt,
    oauth: config.oauth
})

// Mount auth routes
app.use('/api/auth', authRouter)

// Example protected route
app.get('/api/profile', authenticate, async (req, res) => {
    // req.user contains { userId, email } from JWT
    res.json({
        message: 'Protected route',
        user: req.user
    })
})

// Example public route
app.get('/api/public', (req, res) => {
    res.json({ message: 'Public route' })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})
