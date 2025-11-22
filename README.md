# OAuth Authentication Package

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
npm install file:../../shared-packages/oauth

# Also install peer dependencies
npm install express express-session passport passport-google-oauth20 \
            passport-microsoft passport-linkedin-oauth2 jsonwebtoken

# If using MSSQL repository
npm install mssql bcryptjs
```

### Option 2: Copy Folder Directly

```bash
# Copy the entire folder to your project
cp -r oauth ./plugins/
```

---

## Quick Start

### With NPM Package Install

```javascript
import createAuthRouter from '@4prop/oauth'
import { authenticate } from '@4prop/oauth/middleware'
import MSSQLAuthRepository from '@4prop/oauth/mssql'
```

### With Direct Folder Copy

```javascript
import createAuthRouter from './plugins/oauth/routes/auth.js'
import { authenticate } from './plugins/oauth/middleware/authenticate.js'
import MSSQLAuthRepository from './plugins/oauth/repositories/mssql/auth-repository.js'
```

---

## Setup

### 1. Implement Auth Repository

**Option A: Use MSSQL implementation** (included)

```javascript
import MSSQLAuthRepository from '@4prop/oauth/mssql'
const authRepo = new MSSQLAuthRepository()
```

**Option B: Create your own**

See `services/auth-repository.interface.md` for required methods (6 methods).

### 2. Setup Configuration

```javascript
// config.js
export default {
  database: {
    server: 'localhost',
    database: 'mydb',
    user: 'sa',
    password: 'password'
  },
  jwt: {
    accessSecret: 'your-access-secret',
    refreshSecret: 'your-refresh-secret',
    accessExpiry: '15m',      // optional
    refreshExpiry: '7d',      // optional
    production: false         // optional
  },
  session: {
    secret: 'your-session-secret'
  },
  oauth: {                    // optional
    google: {
      clientId: 'your-google-client-id',
      clientSecret: 'your-google-client-secret'
    }
  }
}
```

### 3. Integrate in Express

```javascript
import express from 'express'
import session from 'express-session'
import passport from 'passport'
import createAuthRouter from '@4prop/oauth'
import MSSQLAuthRepository from '@4prop/oauth/mssql'
import config from './config.js'

const app = express()

app.use(express.json())
app.use(session({
    secret: config.session.secret,
    resave: false,
    saveUninitialized: false
})) // Required for OAuth returnTo functionality
app.use(passport.initialize())

// Pass config to repository and router
const authRepo = new MSSQLAuthRepository(config.database)
const authRouter = createAuthRouter(authRepo, {
    jwt: config.jwt,
    oauth: config.oauth
})
app.use('/api/auth', authRouter)

app.listen(3000)
```

**Note:** Environment variables are still supported as fallback if no config is provided.

---

## API Endpoints

```
POST   /api/auth/register                   - Register with email/password
POST   /api/auth/login                      - Login with email/password
POST   /api/auth/logout                     - Logout (clear cookies)
POST   /api/auth/refresh                    - Refresh access token
GET    /api/auth/me                         - Get current user (requires auth)

GET    /api/auth/google?returnTo=/path      - OAuth with Google (optional returnTo)
GET    /api/auth/google/callback
GET    /api/auth/microsoft?returnTo=/path   - OAuth with Microsoft (optional returnTo)
GET    /api/auth/microsoft/callback
GET    /api/auth/linkedin?returnTo=/path    - OAuth with LinkedIn (optional returnTo)
GET    /api/auth/linkedin/callback
```

### OAuth returnTo Parameter

All OAuth endpoints support an optional `returnTo` query parameter. After successful authentication, the user will be redirected to this URL instead of the default `/auth/callback`.

**Example:**
```
/api/auth/google?returnTo=/dashboard
/api/auth/microsoft?returnTo=/profile
```

**Note:** Requires session middleware to be configured (see setup above).

---

## Protecting Routes

```javascript
import { authenticate } from '@4prop/oauth/middleware'

app.get('/api/protected', authenticate, (req, res) => {
    res.json({ user: req.user })
})
```

---

## Configuration Options

### Database Config (for MSSQLAuthRepository)

```javascript
{
  server: 'localhost',       // or 'host'
  port: 1433,                // optional, default: 1433
  user: 'sa',                // or 'username'
  password: 'yourpassword',
  database: 'yourdatabase',
  encrypt: true,             // optional, default: true
  trustServerCertificate: true, // optional, default: true
  options: { },              // optional MSSQL options
  pool: { }                  // optional pool config
}
```

### JWT Config

```javascript
{
  accessSecret: 'your-access-secret',   // required
  refreshSecret: 'your-refresh-secret', // required
  accessExpiry: '15m',                  // optional, default: '15m'
  refreshExpiry: '7d',                  // optional, default: '7d'
  production: false                     // optional, affects secure cookie flag
}
```

### OAuth Config

```javascript
{
  google: {
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    callbackURL: '/api/auth/google/callback'  // optional
  },
  microsoft: {
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    callbackURL: '/api/auth/microsoft/callback'  // optional
  },
  linkedin: {
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    callbackURL: '/api/auth/linkedin/callback'  // optional
  }
}
```

### Environment Variables (Fallback)

If no config is provided, the package falls back to environment variables:

```env
# JWT
JWT_ACCESS_SECRET=your-secret
JWT_REFRESH_SECRET=your-refresh-secret
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d
NODE_ENV=production

# Database
DB_HOST=localhost
DB_PORT=1433
DB_USER=sa
DB_PASSWORD=yourpassword
DB_NAME=yourdatabase

# OAuth
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
MICROSOFT_CLIENT_ID=...
MICROSOFT_CLIENT_SECRET=...
LINKEDIN_CLIENT_ID=...
LINKEDIN_CLIENT_SECRET=...
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
oauth/
├── routes/auth.js              - Express routes
├── services/
│   ├── jwt.js                  - JWT service
│   └── auth-repository.interface.md
├── middleware/authenticate.js  - Auth middleware
└── repositories/
    └── mssql/                  - Reference MSSQL impl
```
