# Auth Plugin

Drop-in authentication for Express.js with OAuth + email/password support.

## Features

- OAuth 2.0 (Google, Microsoft, LinkedIn)
- Email/Password authentication
- JWT tokens (access + refresh)
- HTTP-only cookies
- Database agnostic (bring your own)

---

## Installation

### Option 1: Install as NPM Package (Recommended)

```bash
# From your project directory
npm install file:../../shared-packages/auth-plugin

# Also install peer dependencies
npm install express passport passport-google-oauth20 passport-microsoft \
            passport-linkedin-oauth2 jsonwebtoken cookie-parser

# If using MSSQL repository
npm install mssql bcryptjs
```

### Option 2: Copy Folder Directly

```bash
# Copy the entire folder to your project
cp -r auth-plugin ./plugins/
```

---

## Quick Start

### With NPM Package Install

```javascript
import createAuthRouter from '@each/auth-plugin'
import { authenticate } from '@each/auth-plugin/middleware'
import MSSQLAuthRepository from '@each/auth-plugin/mssql'
```

### With Direct Folder Copy

```javascript
import createAuthRouter from './plugins/auth-plugin/routes/auth.js'
import { authenticate } from './plugins/auth-plugin/middleware/authenticate.js'
import MSSQLAuthRepository from './plugins/auth-plugin/repositories/mssql/auth-repository.js'
```

---

## Setup

### 1. Implement Auth Repository

**Option A: Use MSSQL implementation** (included)

```javascript
import MSSQLAuthRepository from '@each/auth-plugin/mssql'
const authRepo = new MSSQLAuthRepository()
```

**Option B: Create your own**

See `services/auth-repository.interface.md` for required methods (6 methods).

### 2. Setup Environment

```env
# Required
JWT_ACCESS_SECRET=your-secret
JWT_REFRESH_SECRET=your-refresh-secret
CLIENT_URL=http://localhost:3000

# Optional OAuth
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

### 3. Integrate in Express

```javascript
import express from 'express'
import cookieParser from 'cookie-parser'
import passport from 'passport'
import createAuthRouter from '@each/auth-plugin'
import MSSQLAuthRepository from '@each/auth-plugin/mssql'

const app = express()

app.use(express.json())
app.use(cookieParser())
app.use(passport.initialize())

// Create and mount auth routes (passport auto-configures on first call)
const authRepo = new MSSQLAuthRepository()
const authRouter = createAuthRouter(authRepo)
app.use('/api/auth', authRouter)

app.listen(3000)
```

---

## API Endpoints

```
POST   /api/auth/register          - Register with email/password
POST   /api/auth/login             - Login with email/password
POST   /api/auth/logout            - Logout (clear cookies)
POST   /api/auth/refresh           - Refresh access token
GET    /api/auth/me                - Get current user (requires auth)

GET    /api/auth/google            - OAuth with Google
GET    /api/auth/google/callback
GET    /api/auth/microsoft         - OAuth with Microsoft
GET    /api/auth/microsoft/callback
GET    /api/auth/linkedin          - OAuth with LinkedIn
GET    /api/auth/linkedin/callback
```

---

## Protecting Routes

```javascript
import { authenticate } from '@each/auth-plugin/middleware'

app.get('/api/protected', authenticate, (req, res) => {
    res.json({ user: req.user })
})
```

---

## Advanced: Manual Passport Configuration

Passport is auto-configured on first `createAuthRouter` call. For manual control:

```javascript
import createAuthRouter, { configurePassport } from '@each/auth-plugin'

// Configure passport manually before creating router
configurePassport(authRepo)
const authRouter = createAuthRouter(authRepo)
```

---

## Environment Variables

### Required

```env
JWT_ACCESS_SECRET=your-secret
JWT_REFRESH_SECRET=your-refresh-secret
CLIENT_URL=http://localhost:3000
```

### Optional

```env
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d
NODE_ENV=development

# OAuth providers
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
MICROSOFT_CLIENT_ID=...
MICROSOFT_CLIENT_SECRET=...
LINKEDIN_CLIENT_ID=...
LINKEDIN_CLIENT_SECRET=...
```

### Database (for MSSQL implementation)

```env
DB_HOST=localhost
DB_PORT=1433
DB_USER=sa
DB_PASSWORD=yourpassword
DB_NAME=yourdatabase
```

---

## Custom Database

Implement 6 methods:

1. `async findUserByEmail(email)`
2. `async findUserByOAuth(provider, oauthId)`
3. `async createUser(userData)`
4. `async verifyPassword(email, password)`
5. `async getUserById(userId)`
6. `async findOrCreateUser(profile)`

See `services/auth-repository.interface.md` for details.

---

## Folder Structure

```
auth-plugin/
├── routes/auth.js              - Express routes
├── services/
│   ├── jwt.js                  - JWT service
│   └── auth-repository.interface.md
├── middleware/authenticate.js  - Auth middleware
└── repositories/
    └── mssql/                  - Reference MSSQL impl
```
