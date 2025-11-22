# OAuth Shared Package Guide

Setup the OAuth package as a shared local package across multiple projects.

## Setup

### 1. Create Structure

```bash
# Navigate to EACH directory
cd ~/EACH                # macOS/Linux
cd C:\Users\salga\EACH   # Windows

# Create and move package
mkdir shared-packages
mv oauth shared-packages/oauth   # macOS/Linux
move oauth shared-packages\oauth # Windows
```

Expected structure:
```
EACH/
├── shared-packages/oauth/    ← Package
├── bizchat/code/
└── property-pub/code/
```

### 2. Install in Projects

```bash
# From project directory (bizchat/code or property-pub/code)
npm install file:../../shared-packages/oauth
```

Creates symlink in `node_modules/@4prop/oauth` with live updates

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

Changes are **live immediately** via symlink. For version bumps:

```bash
# In shared-packages/oauth/package.json
# Update version: 1.0.0 → 1.0.1 (patch), 1.1.0 (minor), 2.0.0 (major)

# In projects
npm update @4prop/oauth
```

## Troubleshooting

**Module not found:**
```bash
npm install file:../../shared-packages/oauth --force
```

**Changes not reflecting:**
```bash
npm ci
```

**ESM import errors:**
Add `"type": "module"` to `package.json`
