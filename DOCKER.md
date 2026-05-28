# @4prop/oauth in Docker / Kubernetes

This package lives at `packages/backend-shared/oauth` in the monorepo. Locally, Yarn workspaces link it:

```
node_modules/@4prop/oauth → packages/backend-shared/oauth
```

Container builds **fail** when they only copy `apps/backend/<service>/code` and run `npm install` there: npm cannot resolve `"@4prop/oauth": "*"` from the registry (or installs an old published version).

## Fix: install from the monorepo root

In your Dockerfile (or `4prop-container` project), copy workspace roots and install once:

```dockerfile
WORKDIR /app

# Root workspace
COPY package.json yarn.lock ./
COPY packages/backend-shared/oauth/package.json packages/backend-shared/oauth/
COPY packages/backend-shared/db-utils/package.json packages/backend-shared/db-utils/
COPY packages/backend-shared/mailer/package.json packages/backend-shared/mailer/
# …other workspace packages your app depends on

COPY packages/backend-shared/oauth packages/backend-shared/oauth
COPY packages/backend-shared/db-utils packages/backend-shared/db-utils
COPY packages/backend-shared/mailer packages/backend-shared/mailer

COPY apps/backend/property-pub/code/package.json apps/backend/property-pub/code/
# or apps/backend/bizchat/code/package.json

RUN yarn install --frozen-lockfile

WORKDIR /app/apps/backend/property-pub/code
COPY apps/backend/property-pub/code .
# …
```

Same pattern for **bizchat** — only the final `WORKDIR` and `COPY` path change.

## Verify the image has current oauth

After build, in a throwaway container:

```bash
node -e "
import { readFileSync } from 'fs';
const p = 'node_modules/@4prop/oauth/package.json';
const v = JSON.parse(readFileSync(p)).version;
const src = readFileSync('node_modules/@4prop/oauth/src/repositories/mssql/auth-repository.js','utf8');
console.log('oauth version', v);
console.log('has varchar DID fix', src.includes('CAST(n.[NID] AS VARCHAR(32))'));
"
```

Expect **version ≥ 1.7.0** and `has varchar DID fix true`.

## Alternative: publish to your registry

If images must stay “app folder only”:

1. Bump `version` in this `package.json` (e.g. 1.7.0).
2. `npm publish` to your private registry from `packages/backend-shared/oauth`.
3. Pin `"@4prop/oauth": "1.7.0"` in property-pub and bizchat `package.json` (not `"*"`).

That avoids monorepo COPY but requires a publish step on every oauth change.
