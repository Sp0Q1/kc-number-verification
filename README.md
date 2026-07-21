# Keycloak Number Verification Required Action

A Keycloak provider that forces every new account to submit a number at first login,
validates it against your backend REST API, and only lets the user in if the API
answers `true`.

Implemented as a **required action** (`verify-number`) rather than an authenticator,
because required actions can be flagged as *default* — Keycloak then attaches them
automatically to every newly created user, whether created via self-registration,
the admin console, the Admin REST API, or identity-brokered first login.

Requires **Keycloak 25 or newer** (it uses the configurable-required-action API).

## Installation vs. administration

Installing the provider needs filesystem access and a restart — Keycloak has no
"upload a JAR" screen. Everything after that is admin-console work:

| Task | Who | Restart? |
|---|---|---|
| Put the JAR on the server, run `kc.sh build` | ops, once | yes |
| Enable the action, make it mandatory | realm admin | no |
| Set the endpoint, field mappings, attempt limit | realm admin | no |

## Build

```bash
mvn clean package
```

Produces `target/number-verification.jar`.

### Build on GitHub instead (no local toolchain)

`.github/workflows/build.yml` compiles the JAR on GitHub's runners, so you never
need Maven or a JDK installed locally.

1. Push this project to a GitHub repository.
2. The workflow runs automatically on every push to `main`/`master` (and on pull
   requests). You can also trigger it by hand: **Actions → Build JAR → Run workflow**.
3. Open the finished run, scroll to **Artifacts**, and download
   `number-verification-jar` — the `.jar` inside is what you upload to Phase Two.

For a versioned build, push a tag beginning with `v` (for example `git tag v1.0.0 &&
git push --tags`). In addition to the build artifact, the JAR is attached to a GitHub
Release, giving you a stable download URL to reference from change tickets.

Build artifacts are retained by GitHub for 90 days by default; release assets are kept
until you delete them.

## Deploy

```bash
cp target/number-verification.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start
```

Docker:

```dockerfile
FROM quay.io/keycloak/keycloak:26.0.7 AS builder
COPY target/number-verification.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.0.7
COPY --from=builder /opt/keycloak/ /opt/keycloak/
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
```

## Configuration

Every setting exists at two levels:

1. **Server-wide defaults** — environment variables (or SPI options), read at startup.
   Optional; useful for baking a sensible default into the image.
2. **Per-realm overrides** — the admin console, editable at runtime with no restart.

A blank console field falls back to the server default, so an existing
environment-variable deployment keeps working unchanged after upgrading.

### In the admin console

**Authentication → Required actions → Verify Number → ⚙ (gear icon)**

| Setting | Default | Purpose |
|---|---|---|
| Verification endpoint | – | Full URL of the REST API |
| HTTP method | `POST` | `POST` (JSON body) or `GET` (query parameters) |
| API key | – | Optional credential, masked in the UI |
| API key header | `Authorization` | Header the key is sent in |
| Account identifier source | `id` | Which user property identifies the account |
| Account identifier field name | derived | JSON/query field it is sent under |
| Number field name | `number` | Field the submitted number is sent under |
| Additional fields | – | Extra fields to include |
| Response field | auto-detect | Field or JSON pointer holding the boolean |
| Max attempts | `5` | Failed tries before the login aborts; `0` = unlimited |
| Store number as attribute | – | Save the verified number under this attribute |
| Enforce local uniqueness | `false` | Reject a number already bound to another account |

Values are validated on save: a malformed URL, an unknown identifier source, or
uniqueness enforcement without a storage attribute are all rejected with an inline
error rather than failing silently at login time.

### Server-wide defaults

Same settings, prefixed with `NUMBER_VERIFICATION_` and upper-snake-cased:

```bash
NUMBER_VERIFICATION_ENDPOINT=https://api.internal/accounts/verify-number
NUMBER_VERIFICATION_METHOD=POST
NUMBER_VERIFICATION_API_KEY=...
NUMBER_VERIFICATION_API_KEY_HEADER=X-Api-Key
NUMBER_VERIFICATION_IDENTIFIER_SOURCE=attr:employeeNumber
NUMBER_VERIFICATION_IDENTIFIER_FIELD=employee_id
NUMBER_VERIFICATION_NUMBER_FIELD=code
NUMBER_VERIFICATION_EXTRA_FIELDS=email
NUMBER_VERIFICATION_RESPONSE_FIELD=/data/verified
NUMBER_VERIFICATION_MAX_ATTEMPTS=5
NUMBER_VERIFICATION_STORE_ATTRIBUTE=verifiedNumber
NUMBER_VERIFICATION_ENFORCE_UNIQUE=true
```

Secrets are better placed here than in the console: realm config is readable by any
admin with realm-management rights and is included in realm exports.

### Identifying the account

Because the number is unique per account, the backend needs to know *which* account is
asking. Valid identifier sources: `id` (Keycloak user UUID — stable, never reused, the
safest default), `username`, `email`, `firstName`, `lastName`, `realm`, or `attr:<name>`
for any custom user attribute.

**Additional fields** is a comma-separated list. Each entry is either a bare source
spec, or `jsonFieldName=source` when the backend wants a different name:

```
username,email,tenant=attr:tenantId
```

If the resolved identifier is empty for a user, verification is refused rather than
sending an anonymous request.

`Enforce local uniqueness` requires a storage attribute and is only a local backstop —
the backend stays the authority. Note that storing the number puts it in the user
database in clear text.

## Make it mandatory

**Authentication → Required actions → Verify Number**:

- **Enabled** → on
- **Set as default action** → on ← this is what makes it mandatory for new accounts

Or via the Admin REST API, config included:

```bash
# enable + make default
curl -X PUT "$KC/admin/realms/$REALM/authentication/required-actions/verify-number" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"alias":"verify-number","name":"Verify Number",
       "enabled":true,"defaultAction":true,"priority":10}'

# set its configuration
curl -X PUT "$KC/admin/realms/$REALM/authentication/required-actions/verify-number/config" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"config":{"endpoint":"https://api.internal/verify","identifierSource":"id",
       "maxAttempts":"5"}}'
```

Existing users are covered too: `evaluateTriggers` re-adds the action on any login
where the user lacks the `numberVerified` attribute. If you only want it for *new*
accounts, delete the `evaluateTriggers` body and rely on the default-action flag alone.

## Backend API contract

With default settings, Keycloak sends `POST <endpoint>` with
`Content-Type: application/json`:

```json
{
  "number": "123456",
  "userId": "8f3c1e2a-...",
  "username": "alice",
  "email": "alice@example.com",
  "realm": "myrealm"
}
```

With `METHOD=GET` the same fields become query parameters:

```
GET /verify?number=123456&userId=8f3c1e2a-...&username=alice
```

Your endpoint should answer whether *this* number belongs to *this* account. Any of
these bodies is accepted on HTTP 2xx:

```json
true
{"verified": true}
{"valid": false}
{"result": true}
```

A `404` is treated as a clean "not verified". Other non-2xx responses, unreachable
services, or unparseable bodies **fail closed** — the user sees a "temporarily
unavailable" message and cannot proceed. Change the `catch` block in `processAction`
if you would rather fail open.

## Development and CI

The repository ships with a full quality pipeline. None of it blocks the JAR
build — `build.yml` runs `mvn package`, which never triggers the format check — so
you always get a usable artifact even while cleaning up lint.

| Tool | File | What it does |
|---|---|---|
| Build | `.github/workflows/build.yml` | Compiles the JAR, uploads it as an artifact / release asset |
| Lint | `.github/workflows/lint.yml` | Spotless formatting + Enforcer hygiene checks |
| CodeQL | `.github/workflows/codeql.yml` | GitHub-native SAST for Java (security + quality queries) |
| Semgrep | `.github/workflows/semgrep.yml` | Rule-pack SAST (java, security-audit, secrets, OWASP Top Ten) |
| Dependabot | `.github/dependabot.yml` | Weekly Maven + Actions dependency PRs, grouped |

Both CodeQL and Semgrep publish to **Security → Code scanning**, so findings land in
one place. Semgrep needs no token — it uses public rule packs. Prefer **OpenGrep**
(the Apache-2.0 fork)? It is a drop-in swap; the comment at the top of `semgrep.yml`
shows the one-line change.

### Formatting

Code style is enforced with Spotless using Google Java Format in AOSP profile
(4-space indent). To format locally:

```bash
mvn spotless:apply     # rewrite files to the canonical style
mvn spotless:check     # verify without changing (what CI runs)
```

The very first `spotless:check` on your machine may fail if your editor introduced
differences — run `spotless:apply` once, commit, and it stays green. Formatting is
bound to the `verify` phase, not `package`, so it never interferes with building the
JAR.

### Build hygiene

Maven Enforcer runs during every build and fails fast on an unsupported JDK/Maven
version or duplicate dependency declarations. Adjust the rules in `pom.xml` under the
`maven-enforcer-plugin` block.



- On success the user gets the attribute `numberVerified=true` and the action is
  removed (`isOneTimeAction()` returns `true`), so it never runs again.
- Failed attempts are counted on the authentication session; exceeding
  `MAX_ATTEMPTS` calls `context.failure()`, ending that login attempt.
- Custom events are emitted as `CUSTOM_REQUIRED_ACTION` with error codes
  `number_verification_rejected`, `number_verification_unavailable` and
  `number_verification_already_used`.
- Configuration is re-read from the realm on every attempt, so console changes take
  effect on the next login with no restart and no cache flush.
- The identifier is resolved fresh on every attempt, so it always matches the account
  currently authenticating — there is no way to verify a number against one account and
  have it apply to another.
- The form template lives in `theme-resources/templates` and inherits whatever login
  theme the realm uses, so it picks up your branding automatically. Override it by
  placing `number-verification.ftl` in your own theme's `login/` folder.

## Testing locally

```bash
# stub backend
python3 -c "
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        # number is unique per account, so check the pair
        VALID = {'alice-user-id': '123456', 'bob-user-id': '654321'}
        ok = VALID.get(body.get('userId')) == body.get('number')
        self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
        self.wfile.write(json.dumps({'verified': ok}).encode())
HTTPServer(('0.0.0.0', 9000), H).serve_forever()"
```

Then set `NUMBER_VERIFICATION_ENDPOINT=http://localhost:9000/verify`, register a new
user, look up its id in the admin console, add it to `VALID`, and confirm the number
is accepted for that account and rejected for any other.
