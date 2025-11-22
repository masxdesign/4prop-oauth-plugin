# OAuth Shared Package Guide

Setup the OAuth package as a shared package using npm workspaces.

## Setup

### 1. Configure Root package.json

In your root `EACH/package.json`:

```json
{
  "name": "each-monorepo",
  "private": true,
  "workspaces": [
    "packages/backend-shared/oauth",
    "packages/bizchat/code",
    "packages/property-pub/code"
  ]
}
```

### 2. Install Dependencies

```bash
# From EACH root directory
npm install
```

This automatically links all workspace packages. The OAuth package is now available as `@4prop/oauth` in all workspace projects.

## Usage

```javascript
import express from 'express'
import session from 'express-session'
import passport from 'passport'
import createAuthRouter from '@4prop/oauth'
import { authenticate } from '@4prop/oauth/middleware'
import MSSQLAuthRepository from '@4prop/oauth/mssql'
import config from './config.js'

const app = express()

app.use(express.json())
app.use(session({
  secret: config.session.secret,
  resave: false,
  saveUninitialized: false
}))
app.use(passport.initialize())

// Pass config to repository and router
const authRepo = new MSSQLAuthRepository(config.database)
const authRouter = createAuthRouter(authRepo, {
  jwt: config.jwt,
  oauth: config.oauth
})
app.use('/api/auth', authRouter)
```

**Example config.js:**
```javascript
export default {
  database: {
    server: 'localhost',
    port: 1433,
    user: 'sa',
    password: 'yourpassword',
    database: 'yourdatabase'
  },
  jwt: {
    accessSecret: 'your-access-secret',
    refreshSecret: 'your-refresh-secret',
    accessExpiry: '15m',
    refreshExpiry: '7d',
    production: false
  },
  session: {
    secret: 'your-session-secret'
  },
  oauth: {
    google: {
      clientId: 'your-client-id',
      clientSecret: 'your-client-secret'
    }
  }
}
```

**Available imports:**
- `@4prop/oauth` - `createAuthRouter()`
- `@4prop/oauth/middleware` - `authenticate`, `authenticateWithUser`, `optionalAuth`
- `@4prop/oauth/jwt` - JWT service
- `@4prop/oauth/mssql` - `MSSQLAuthRepository`

## Updates

Changes to the OAuth package are **live immediately** across all workspace projects.

**Version bumps:**
```bash
# Update version in packages/backend-shared/oauth/package.json
# 1.0.0 → 1.0.1 (patch), 1.1.0 (minor), 2.0.0 (major)

# From root
npm install
```

## Troubleshooting

**Module not found:**
```bash
# From EACH root
npm install --force
```

**Changes not reflecting:**
```bash
# Clear and reinstall from root
rm -rf node_modules package-lock.json
npm install
```
