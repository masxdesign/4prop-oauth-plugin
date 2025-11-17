import express from 'express'
import cookieParser from 'cookie-parser'
import passport from 'passport'

// Import auth plugin (when installed as npm package)
import createAuthRouter from '@each/auth-plugin'
import { authenticate } from '@each/auth-plugin/middleware'

// Import MSSQL repository or use your custom one
import MSSQLAuthRepository from '@each/auth-plugin/mssql'

const app = express()

// Middleware
app.use(express.json())
app.use(cookieParser())
app.use(passport.initialize())

// Initialize auth with your repository (passport auto-configures on first call)
const authRepo = new MSSQLAuthRepository()
const authRouter = createAuthRouter(authRepo)

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
