# Using OAuth Package as a Shared Package

This guide shows how to set up the OAuth authentication package as a shared local package that can be installed across multiple projects.

## Platform Notes

This guide includes commands for both **macOS/Linux** and **Windows**. Use the commands that match your operating system.

- **macOS/Linux**: Use `~/EACH` for paths and forward slashes `/`
- **Windows**: Use `C:\Users\salga\EACH` for paths and backslashes `\`

---

## Setup (One Time)

### 1. Create Shared Packages Directory

```bash
# Navigate to your projects root
cd ~/EACH              # macOS/Linux
# or
cd C:\Users\salga\EACH # Windows

# Create shared packages directory
mkdir shared-packages
```

### 2. Move OAuth Package

**macOS/Linux:**
```bash
cd ~/EACH/bizchat
mv oauth ../shared-packages/oauth
```

**Windows:**
```bash
cd C:\Users\salga\EACH\bizchat
move oauth ..\shared-packages\oauth
```

Your folder structure should now be:
```
~/EACH/                          (or C:\Users\salga\EACH\ on Windows)
├── shared-packages/
│   └── oauth/                   ← Package lives here
│       ├── package.json
│       ├── routes/
│       └── ...
│
├── bizchat/
│   └── code/
│       └── package.json
│
└── property-pub/
    └── code/
        └── package.json
```

---

## Installing in Projects

### In bizchat project:

**macOS/Linux:**
```bash
cd ~/EACH/bizchat/code
npm install file:../../shared-packages/oauth
```

**Windows:**
```bash
cd C:\Users\salga\EACH\bizchat\code
npm install file:../../shared-packages/oauth
```

### In property-pub project:

**macOS/Linux:**
```bash
cd ~/EACH/property-pub/code
npm install file:../../shared-packages/oauth
```

**Windows:**
```bash
cd C:\Users\salga\EACH\property-pub\code
npm install file:../../shared-packages/oauth
```

### What happens:

- NPM creates a symlink in `node_modules/@4prop/oauth` → `shared-packages/oauth`
- Changes to the source are **immediately reflected** in all projects
- Your `package.json` will have:
  ```json
  {
    "dependencies": {
      "@4prop/oauth": "file:../../shared-packages/oauth"
    }
  }
  ```

---

## Using in Your Code

```javascript
import express from 'express'
import passport from 'passport'

// Import from the package
import createAuthRouter from '@4prop/oauth'
import { authenticate } from '@4prop/oauth/middleware'
import { createSessionMiddleware } from '@4prop/oauth/session'
import MSSQLAuthRepository from '@4prop/oauth/mssql'

const app = express()

// Middleware setup
app.use(express.json())
app.use(createSessionMiddleware()) // Required for OAuth returnTo functionality
app.use(passport.initialize())

// Use it
const authRepo = new MSSQLAuthRepository()
const authRouter = createAuthRouter(authRepo)
app.use('/api/auth', authRouter)
```

---

## Available Imports

| Import | Path | What it is |
|--------|------|------------|
| `@4prop/oauth` | Default export | `createAuthRouter()` function |
| `@4prop/oauth/middleware` | Named exports | `authenticate`, `authenticateWithUser`, `optionalAuth` |
| `@4prop/oauth/jwt` | Default export | JWT service functions |
| `@4prop/oauth/mssql` | Default export | `MSSQLAuthRepository` class |
| `@4prop/oauth/session` | Named export | `createSessionMiddleware()` function |

---

## Updating the Package

### When you make changes to the shared package:

**macOS/Linux:**
```bash
cd ~/EACH/shared-packages/oauth

# Edit files...

# Bump version (optional but recommended)
# Edit package.json, change version: "1.0.0" → "1.0.1"
```

**Windows:**
```bash
cd C:\Users\salga\EACH\shared-packages\oauth

# Edit files...

# Bump version (optional but recommended)
# Edit package.json, change version: "1.0.0" → "1.0.1"
```

### Update projects:

Since it's a symlink, **changes are live immediately**. But to ensure cache is cleared:

**macOS/Linux:**
```bash
cd ~/EACH/bizchat/code  # or property-pub/code
npm install
```

**Windows:**
```bash
cd C:\Users\salga\EACH\bizchat\code  # or property-pub\code
npm install
```

Or for version bumps:

```bash
npm update @4prop/oauth
```

---

## Version Management

### Semantic Versioning

Update `version` in `shared-packages/oauth/package.json`:

- **1.0.0** → **1.0.1**: Bug fixes (patch)
- **1.0.0** → **1.1.0**: New features, backward compatible (minor)
- **1.0.0** → **2.0.0**: Breaking changes (major)

### Lock to Specific Version (Optional)

If you want a project to stay on a specific version:

```bash
# In the project
npm install file:../shared-packages/oauth@1.0.0
```

---

## Advantages of This Approach

✅ **Single source of truth** - One codebase, multiple projects
✅ **Live updates** - Changes reflect immediately via symlinks
✅ **No npm registry** - No need to publish to npm
✅ **Version control** - Track changes in git
✅ **Easy debugging** - Source code is local and editable

---

## Alternative: npm link (More Complex)

If you want more control, use `npm link`:

**macOS/Linux:**
```bash
# In the package
cd ~/EACH/shared-packages/oauth
npm link

# In each project
cd ~/EACH/bizchat/code  # or property-pub/code
npm link @4prop/oauth
```

**Windows:**
```bash
# In the package
cd C:\Users\salga\EACH\shared-packages\oauth
npm link

# In each project
cd C:\Users\salga\EACH\bizchat\code  # or property-pub\code
npm link @4prop/oauth
```

**Note:** `npm link` creates global symlinks, which can cause issues. The `file://` approach is simpler.

---

## Troubleshooting

### "Cannot find module '@4prop/oauth'"

Reinstall the package with the correct relative path:

```bash
# From bizchat/code or property-pub/code
npm install file:../../shared-packages/oauth --force
```

### Changes not reflecting

**macOS/Linux:**
```bash
# Clear node_modules and reinstall
rm -rf node_modules
npm install
```

**Windows:**
```bash
# Clear node_modules and reinstall
rmdir /s /q node_modules
npm install
```

Or use cross-platform:
```bash
# Works on both platforms
npm ci
```

### ESM import errors

Make sure your project has `"type": "module"` in `package.json`.
