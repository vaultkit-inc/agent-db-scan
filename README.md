# agent-db-scan

**What can this Postgres login actually see and do?**

## Why

When you give an AI agent a database connection string, it inherits every
privilege that login has: whatever the role owns, whatever it can reach through
group roles, whatever `PUBLIC` was granted, and whatever default privileges will
grant on tables that don't exist yet. Most people never check what that adds up
to. `agent-db-scan` resolves it for you, so you can look before you hand the
credential over.

## Install

```sh
go install github.com/vaultkit-inc/agent-db-scan/cmd/agent-db-scan@latest
```

Or from source:

```sh
git clone https://github.com/vaultkit-inc/agent-db-scan.git
cd agent-db-scan
make build   # writes bin/agent-db-scan
```

## Usage

```sh
export DATABASE_URL="postgres://app_service@localhost:5432/app"

agent-db-scan                          # reads $DATABASE_URL
agent-db-scan --dsn "$DATABASE_URL" --schema app
agent-db-scan --format json > report.json
```

Prefer the `DATABASE_URL` environment variable over `--dsn`: a password passed
as a flag lands in your shell history and the process list.

### Flags

| Flag | Purpose |
|---|---|
| `--dsn STRING` | Postgres connection string. Defaults to `$DATABASE_URL`. |
| `--format table\|json` | Human-readable report (default) or the full machine-readable report. |
| `--schema NAME` | Restrict the scan to a single schema. |
| `--include-system` | Include `pg_catalog` / `information_schema` objects. Off by default: Postgres grants `PUBLIC` read on nearly all of them, which buries real findings. |
| `-v`, `--verbose` | Table output only: add `PRIVILEGES` and the complete `SOURCES` list. |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed. |
| 1 | The scan failed (bad flags, no connection string, could not connect or query). |

There is no severity threshold yet, so the exit code does not reflect what the
scan found.

## Sample output

Scanning a fixture login named `app_service` that inherits read and write from
two group roles (`agent-db-scan --schema app`):

```
agent-db-scan

TARGET
  Login       app_service
  Scanned     2026-09-21 16:26:42 UTC

SUMMARY
  Objects        1
  Tables         1
  Can read       yes
  Can write      yes
  Admin access   no
  Ownership      none
  Future access  2 rules

CURRENT ACCESS
  OBJECT       KIND   LEVEL  VIA
  app.widgets  table  write  app_reader (inherited), app_writer (inherited), +1 more

FUTURE ACCESS
  New objects created by app_admin database-wide:
    table  SELECT  via app_reader (inherited)

  New objects created by app_admin in app:
    table  SELECT  via app_reader (inherited)
```

The table view is a summary: at most two sources per row, sorted most
privileged first, and colored only when writing to a terminal (respects
`NO_COLOR`). Use `--verbose` for full detail or `--format json` for everything.

## Safety

- Every query runs in a read-only transaction with a statement timeout, and the
  transaction is always rolled back, never committed.
- It reads catalog metadata only (roles, memberships, ACLs, default privileges,
  RLS state). It never reads table contents.
- Its only network connection is the database you point it at.

## What it cannot check

- **Row-level security.** It reports that a table has RLS enabled or forced and
  which policies exist, but it does not evaluate policy expressions, so it can't
  tell you which rows are actually visible. Treat access on an RLS table as an
  upper bound.
- **`SECURITY DEFINER` functions.** It does not analyze what functions run as,
  so privilege escalation through them is invisible. Functions are not scanned
  as objects yet.
- **View owner rights.** A view runs with its owner's privileges; that
  indirection is not traced.
- **Column-level privileges.** Only object-level ACLs are read.

An absence of findings is not proof of safety.

## Development

```sh
docker compose up -d   # integration fixture, see testdata/schema.sql
make test
```

## License

MIT. See [LICENSE](LICENSE).

Built by the team at VaultKit.
