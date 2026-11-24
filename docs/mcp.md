# Skyfarer MCP server

`skyfarer-mcp` exposes the Skyfarer JSON API to agents over [Model Context
Protocol](https://modelcontextprotocol.io/) on **stdio**: the agent starts it
as a subprocess and exchanges one newline-delimited JSON-RPC 2.0 message per
line. It reuses the same `cli.Client` as the `skyfarer` command, so there's no
second implementation of the API and no extra dependencies.

## Install and configure

The server is installed alongside the CLI, from the container image or with
`pipx install .` in the repo:

```sh
export SKYFARER_URL=http://127.0.0.1:8080
export SKYFARER_TOKEN=sk_live_…        # or put both in a CLI profile
skyfarer-mcp                           # read-only tools
skyfarer-mcp --allow-writes            # also expose admin tools
```

It accepts the same `--profile`, `--url` and `--token` flags as `skyfarer` and
reads `~/.config/skyfarer/config.toml` (`[profiles.NAME]`) and the
`SKYFARER_PROFILE`, `SKYFARER_URL` and `SKYFARER_TOKEN` environment variables.
A token is required; without one the server prints a message to stderr and
exits with code 3.

For an MCP client such as Claude Desktop, add a server entry like this:

```json
{
  "mcpServers": {
    "skyfarer": {
      "command": "skyfarer-mcp",
      "env": {
        "SKYFARER_URL": "http://127.0.0.1:8080",
        "SKYFARER_TOKEN": "sk_live_…"
      }
    }
  }
}
```

Use an absolute path for `command` if the client doesn't search `PATH`. For
admin tools, add `"args": ["--allow-writes"]`.

## Tools

Read-only tools are always available:

| Tool | What it does | Main arguments |
|---|---|---|
| `skyfarer_status` | Current status, open incidents and channel health | — |
| `skyfarer_incidents` | List incidents, newest detection first | `state`, `provider`, `region`, `q`, `range`, `from`, `to`, `limit`, `cursor` |
| `skyfarer_incident` | One incident with updates, tickets and deliveries | `id` |
| `skyfarer_history` | Availability and SLA report | `range`, `from`, `to`, `provider`, `region`, `format` (`csv` returns raw CSV) |
| `skyfarer_deliveries` | Notification deliveries | `channel`, `status`, `limit`, `cursor` |
| `skyfarer_poll_log` | Poll cycles | `range`, `limit`, `cursor` |

With `--allow-writes`, seven admin tools are added:
`skyfarer_set_provider`, `skyfarer_test_channel`, `skyfarer_add_webhook`,
`skyfarer_add_user`, `skyfarer_create_token`, `skyfarer_set_settings` and
`skyfarer_set_rules`. Their arguments mirror the CLI/API; each is described by
a JSON Schema in `tools/list`.

Tools return a `content` array with one text block: pretty-printed JSON by
default, or the raw CSV for `skyfarer_history` with `format: "csv"`. API and
usage errors come back as tool results with `isError: true`, so an agent can
read the message and carry on; protocol-level problems use JSON-RPC errors.

## Protocol and safety

- Supports the current stateless `2026-07-28` revision (`server/discover`,
  `resultType` on results) and the older `initialize` handshake used by
  pre-2026 clients. `tools/list` and `tools/call` are the same in both eras.
- Notifications (`notifications/initialized`, `notifications/cancelled`) get
  no reply. Logs go to **stderr**; stdout carries only protocol messages.
- Changes go through the same admin endpoints as the dashboard, so the
  token's scopes and its user's role still decide what is allowed. Prefer a
  service account with only the scopes the agent needs.
- Secrets stay write-only: settings and webhooks return configured flags, not
  values. `skyfarer_create_token` is the exception — the plaintext token is
  returned once, exactly as in the dashboard, so treat the tool result as a
  secret.
- Rate limits are shared with the API (120/min per token, 300/min per IP by
  default); a `429` is reported to the agent with its `Retry-After` hint.
