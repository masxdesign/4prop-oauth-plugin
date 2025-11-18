# MSSQL Auth Repository

Reference implementation for SQL Server databases.

## Setup

### 1. Run Schema

```sql
-- Execute schema.sql on your SQL Server database
```

### 2. Environment Variables

```env
DB_HOST=localhost
DB_PORT=1433
DB_USER=sa
DB_PASSWORD=yourpassword
DB_NAME=yourdatabase
```

### 3. Install Dependencies

```bash
npm install mssql bcryptjs
```

### 4. Use in Your App

```javascript
import MSSQLAuthRepository from './auth-plugin/repositories/mssql/auth-repository.js'
import createAuthRouter from './auth-plugin/routes/auth.js'

const authRepo = new MSSQLAuthRepository()
const authRouter = createAuthRouter(authRepo)

app.use('/api/auth', authRouter)
```

## Table Structure

- `a_rcUsers` - Main user table
- Supports both OAuth and email/password authentication
- Passwords stored using bcrypt (10 rounds)
