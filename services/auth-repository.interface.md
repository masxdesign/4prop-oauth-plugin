# Auth Repository Interface

Implement these 6 methods in your auth repository class:

## Required Methods

### `async findUserByEmail(email)`
Find user by email.
- **Returns:** `User | null`

### `async findUserByOAuth(provider, oauthId)`
Find user by OAuth provider and ID.
- **Parameters:** provider ('google', 'microsoft', 'linkedin'), oauthId
- **Returns:** `User | null`

### `async createUser(userData)`
Create new user. **Must hash password if provided.**
- **Parameters:** `{ email, password?, first?, last?, provider?, oauthId?, avatar? }`
- **Returns:** `User`

### `async verifyPassword(email, password)`
Verify email/password credentials.
- **Returns:** `User`
- **Throws:** Error if invalid

### `async getUserById(userId)`
Get user by ID.
- **Returns:** `User | null`

### `async findOrCreateUser(profile)`
Find or create user for OAuth flow.
- **Parameters:** `{ provider, id, email, firstname, surname, avatar? }`
- **Returns:** `User`

---

## User Object

All methods return/accept user objects with:

```javascript
{
    id: string | number,       // Required
    email: string,              // Required
    first?: string,
    last?: string,
    avatar?: string,
    oauth_provider?: string,
    oauth_id?: string,
    password?: string,          // Hashed, never sent to client
    created_at?: Date,
    last_login?: Date
}
```

---

## Example Implementation

```javascript
export default class MyAuthRepository {
    async findUserByEmail(email) {
        return await db.users.findOne({ email })
    }

    async findUserByOAuth(provider, oauthId) {
        return await db.users.findOne({ oauth_provider: provider, oauth_id: oauthId })
    }

    async createUser(userData) {
        if (userData.password) {
            userData.password = await bcrypt.hash(userData.password, 10)
        }
        return await db.users.insert(userData)
    }

    async verifyPassword(email, password) {
        const user = await this.findUserByEmail(email)
        if (!user?.password) throw new Error('Invalid credentials')

        const isValid = await bcrypt.compare(password, user.password)
        if (!isValid) throw new Error('Invalid credentials')

        return user
    }

    async getUserById(userId) {
        return await db.users.findOne({ id: userId })
    }

    async findOrCreateUser(profile) {
        let user = await this.findUserByOAuth(profile.provider, profile.id)
        if (!user) {
            user = await this.createUser({
                email: profile.email,
                first: profile.firstname,
                last: profile.surname,
                avatar: profile.avatar,
                provider: profile.provider,
                oauthId: profile.id
            })
        }
        return user
    }
}
```
