# imslpcli

A Cobra-based command-line client and Go library for IMSLP (imslp.org) using its private client-side sync API. It also ships a complete, self-contained **MCP server** (Model Context Protocol over HTTP Streaming) with built-in OAuth2 Authorization Server + Resource Server support — perfect for connecting Claude Desktop, Grok, Cursor, or other AI agents directly to your personal IMSLP library and setlists.

## Features

- **CLI for everyday use**
  - Login with username/password (persists token)
  - Full state sync to local JSON files
  - Full setlist management (create, clone, rename, reorder, delete, append/prepend/insert/reorder items)
  - Score search, metadata display, and download (including public stor.imslp.org links for mylib-only scores)
  - Nice columnized table output (using `github.com/ryanuber/columnize`)

- **Library** (`client.go`)
  - `Client` type wrapping the private `app0.imslp.org` sync API (`sync.get` / `sync.put`)
  - High-level helpers for setlist mutations and searching
  - Token management and auto-login from env

- **MCP Server** (`imslpcli mcp`)
  - Single binary that is both OAuth2 AS + MCP RS (no separate services)
  - Dynamic Client Registration (DCR), PKCE S256, public clients (`token_endpoint_auth_method=none`)
  - Self-contained HTML login form at `/authorize` that performs a **real** IMSLP `user.login`
  - Short codes → JWT access tokens (HS256) that embed your IMSLP `loginToken` (30-day expiry)
  - Per-user isolation: every MCP tool call uses the caller's IMSLP credentials
  - Full OAuth discovery (`/.well-known/...`)
  - Streamable HTTP transport (with `DisableLocalhostProtection` for public hosting)
  - Persistent state: clients, MCP sessions (`Mcp-Session-Id` → user bindings), and JWT signing secret survive reboots
  - Tool annotations (`ReadOnlyHint`, `DestructiveHint`)
  - Structured + human-friendly output (tables for lists, slim objects for search results)
  - Detailed logging for debugging hosted setups (real IP via X-Forwarded-For, UA, auth steps, session IDs, etc.)

## Installation

```bash
# Latest release
go install github.com/abourget/imslpcli@latest

# Or from source
git clone https://github.com/abourget/imslpcli
cd imslpcli
go build -o imslpcli .
```

The binary is `imslpcli`.

## Quick Start (CLI)

1. Create a `.env` file (the tool loads it automatically via `godotenv`):

   ```env
   IMSLP_USERNAME=your@email.com
   IMSLP_PASSWORD=secret
   # After first login you can remove the password:
   # IMSLP_LOGIN_TOKEN=...
   ```

2. Log in (saves a long-lived token to `.env`):

   ```bash
   imslpcli login
   ```

3. Check identity:

   ```bash
   imslpcli whoami
   ```

4. Sync your library:

   ```bash
   imslpcli sync
   # Produces scores.json, setlists.json, sync_meta.json
   ```

5. Work with setlists:

   ```bash
   imslpcli setlist list
   imslpcli setlist search "Beethoven"
   imslpcli setlist show "My Playlist"
   imslpcli setlist append "My Playlist" "1715476664618-..."
   ```

6. Search and download scores:

   ```bash
   imslpcli scores search "moonlight"
   imslpcli scores show "Moonlight Sonata"
   imslpcli scores download "Moonlight Sonata" -d ~/Music
   ```

## Authentication & Environment Variables

All commands that need auth use `NewClient()` + `EnsureAuth()`.

Supported variables (in `.env` or the environment):

| Variable                | Purpose                                      | Notes |
|-------------------------|----------------------------------------------|-------|
| `IMSLP_USERNAME`        | Username or email for login                  | Used by `login` and auto-login |
| `IMSLP_PASSWORD`        | Password                                     | Only needed for initial login; token is preferred |
| `IMSLP_LOGIN_TOKEN`     | Long-lived token from IMSLP                  | Preferred; obtained via `login` command |
| `APP_BASE_URL`          | Public base for the MCP server               | Used when `--base-url` is not passed |
| `IMSLP_MCP_JWT_SECRET`  | Override for MCP JWT signing key             | For the `mcp` command |

The `login` command writes/updates `IMSLP_LOGIN_TOKEN` in `.env` (file mode 0600).

## Command Reference

```
imslpcli
├── login                  Log in and save token to .env
├── whoami                 Show current user (from token)
├── sync                   Full sync → scores.json + setlists.json
├── setlist
│   ├── list               Table of all setlists (ID | NAME | ITEMS)
│   ├── create <name> [scoreIDs...]
│   ├── clone <source> <newName>
│   ├── rename <id-or-name> <newName>
│   ├── delete <id-or-name>
│   ├── search <query>
│   ├── show <id-or-name>  Lists scores with Work Titles
│   ├── append/prepend/insert/reorder ...
└── scores
    ├── search <query>     ID | WORK TITLE | COMPOSER | TITLE
    ├── show <id-or-name>  Detailed key/value dump (multi-line safe)
    └── download <id-or-name> [-d dir] [-o file.pdf]
```

Run any command with `--help` for exact usage and flags (e.g. `imslpcli setlist reorder --help`).

The `sync` command always does a full history replay for correctness (the private API does not expose a simple "current snapshot" endpoint).

## The MCP Server (`imslpcli mcp`)

This is the killer feature for AI workflows.

```bash
# Local (for testing with MCP Inspector or local Claude)
imslpcli mcp --port 8080

# Public / hosted (recommended for Claude Desktop etc.)
imslpcli mcp \
  --port 8080 \
  --host 0.0.0.0 \
  --base-url https://imslp-mcp.example.com
```

Point your MCP client at `https://imslp-mcp.example.com/mcp` (or just the base URL — the server also answers MCP protocol requests at `/`).

### How auth works (zero config for the user)

1. Client discovers the protected resource + authorization server metadata.
2. Performs Dynamic Client Registration (`POST /register`).
3. Redirects user to `/authorize` → nice self-hosted login form.
4. The form calls real IMSLP `user.login`, mints a short-lived code bound to your `loginToken` + PKCE.
5. Client exchanges the code (with PKCE verifier) for a JWT.
6. All subsequent MCP calls carry the JWT as Bearer token.
7. The server extracts the embedded IMSLP token and uses it for that user's `Client`.

The JWT secret, registered clients, and active MCP sessions (`Mcp-Session-Id` → userID) are persisted so a server restart does not break in-progress conversations.

### Important MCP flags

- `--base-url` / `APP_BASE_URL` — **critical** for public deployments (affects all metadata, redirects, JWT `iss`/`aud`, and what clients are told to connect to).
- `--jwt-secret-file` (default `mcp-jwt-secret.key`) — persistent HMAC key (generated on first run if missing).
- `--clients-file`, `--sessions-file` — for the on-disk "databases".
- `--jwt-secret` / `IMSLP_MCP_JWT_SECRET` — one-shot override (useful in containers).

See the full Long description in `imslpcli mcp --help`.

### Exposed MCP Tools

All tools are prefixed `imslp_`:

**Read-only**
- `imslp_whoami`
- `imslp_list_setlists` (nice table + slim structured `{count, setlists}`)
- `imslp_search_setlists`
- `imslp_show_setlist`
- `imslp_search_scores`
- `imslp_show_score`
- `imslp_get_score_download`

**Mutating** (some marked `DestructiveHint`)
- `imslp_create_setlist`
- `imslp_clone_setlist`
- `imslp_rename_setlist`
- `imslp_delete_setlist`
- `imslp_append_to_setlist` / `prepend_to_setlist` / `insert_in_setlist`
- `imslp_reorder_setlist`

List/setlist tools return human-readable tables in the `content` field plus compact structured data (when useful).

## Local Data Files

- `.env` — credentials / token (never commit)
- `scores.json`, `setlists.json`, `sync_meta.json` — materialized views from `sync`
- `mcp-clients.json`, `mcp-sessions.json`, `mcp-jwt-secret.key` — MCP server state (0600 for the key)

## Development & Hacking

```bash
go run . --help
go build
./build.sh   # example deployment script (plain go + scp + systemctl user service)
```

The original reverse-engineering material lives in `imslp.org.har`.

The project uses Go 1.25+, Cobra, Resty v3, and the official `modelcontextprotocol/go-sdk`.

**Note on package structure**: Everything is currently in `package main` for simplicity (CLI + library + MCP server in one binary). The reusable parts live in `client.go`.

## Disclaimer

This is an **unofficial** tool that talks to IMSLP's private (undocumented) sync protocol. It was built by studying network traffic. Use responsibly and respect imslp.org's terms of service and rate limits. The authors are not affiliated with IMSLP.

## License

See the source repository for licensing details.

---

Made with ❤️ for musicians and power users who want their IMSLP library in their CLI and AI tools.
