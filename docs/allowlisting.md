# Allowlisting

There are two decisions: which local tool Codex exposes, and which network destination that tool may reach. Tool configuration is in `config/codex.toml`; network permission is in `config/network.json`. Both templates are controlled from the host. Neither file is mounted into the writable agent workspace. The Codex template is copied into its writable state directory at startup; tool lists configure the session, while the separate gateway enforces network access even if a container process changes its own configuration.

## Host rules

```json
{
  "allow": ["api.openai.com", "auth.openai.com", "chatgpt.com", "example.com", "api.example.com"],
  "deny": ["tracking.example.com"],
  "ports": [80, 443],
  "private_allow": []
}
```

| Entry | Meaning |
| --- | --- |
| `example.com` | Only that exact host |
| `api.example.com` | Only that API subdomain |
| `.example.com` | Apex plus all subdomains, at any depth |
| `203.0.113.1` | Exact literal IP; private/reserved-address rules still apply |
| `deny: ["tracking.example.com"]` | Deny wins even if `.example.com` is allowed |
| `allow: []` | Deny every external destination |

Use lowercase ASCII hostnames or punycode. Do not include a protocol, path, query, port, CIDR, `*`, or `*.example.com`. Use `.example.com` only when you intend to permit the entire domain. Lists with malformed entries, duplicate hosts, duplicate JSON keys, or unknown fields fail validation and prevent startup.

```sh
./sandbox allow add example.com api.example.com
./sandbox allow deny tracking.example.com
./sandbox allow check api.example.com
./sandbox allow remove example.com
./sandbox reload
```

`remove` removes exactly the specified pattern from both allow and deny. It does not erase a broader suffix that still matches the same host. `check` reports the host rule; it does not resolve DNS or test port/private-address permission.

The Rust CLI and gateway share one validated policy parser. `./sandbox allow fingerprint` prints its canonical SHA256; `doctor` shows the same fingerprint for the applied policy.

Policy edits do not affect an already running proxy until reload. A new launcher operation applies any changed policy automatically. Reload terminates open tunnels; create a new session afterward. This matters when revoking permission: an existing TLS connection must not keep using the old decision.

## Common development profiles

```sh
./sandbox allow profile github
./sandbox allow profile npm
./sandbox allow profile python
# Or all three:
./sandbox allow profile development
```

| Profile | Hosts added |
| --- | --- |
| `openai` | `api.openai.com`, `auth.openai.com`, `chatgpt.com` |
| `github` | `github.com`, `api.github.com`, `raw.githubusercontent.com`, `objects.githubusercontent.com`, `codeload.github.com` |
| `npm` | `registry.npmjs.org` |
| `python` | `pypi.org`, `files.pythonhosted.org` |
| `development` | GitHub, npm, and Python profiles combined |

Profiles add hosts without removing existing rules. A deny remains effective after adding a profile. Package scripts can download from additional hosts; add their actual destinations individually after checking the log. Git repositories should use HTTPS. Direct SSH, arbitrary TCP, QUIC, and DNS access remain blocked.

Docker pulls and Dockerfile `RUN` installation happen during trusted builds, before runtime filtering. This lets you bake tools into an image without granting their installation hosts to future agent sessions. Rebuild explicitly when upgrading a pinned CLI/MCP version.

## Redirects and browser assets

Every new proxy connection checks its own destination. Allowing a page does not allow its redirect target, CDN, login provider, websocket API, or embedded resource hosts.

```sh
./sandbox allow add docs.example.com static.example.com api.example.com
./sandbox logs --follow
```

The log shows decision, HTTP status, method, and destination host/port. It omits request paths, query strings, headers, and bodies. `TCP_DENIED/403` identifies a policy denial. A remote website's own 403 is different; use the decision token as well as the status.

HTTPS uses CONNECT with normal certificate verification in the client. Squid does not decrypt the tunnel. The firewall controls its requested destination and port, not URLs, HTTPS methods, payloads, or TLS SNI inside an allowed tunnel. Allowed multi-tenant services and forwarding APIs can reach other resources on a caller's behalf.

## Additional ports

Ports apply to all allowed hosts:

```sh
./sandbox allow add api.example.com
./sandbox allow port 8443
./sandbox reload
```

This allows proxy connections to `api.example.com:8443`. To remove a port, edit `ports` in `config/network.json` and reload. A non-HTTP tool needs explicit support for HTTP CONNECT; adding a port does not create direct socket access.

## Private endpoints

Private, loopback, host, metadata, multicast, and reserved addresses are blocked by default, including when an allowed hostname resolves to them. A development server running inside the agent container can be accessed directly at `127.0.0.1` without external egress.

To intentionally reach an external private service through the proxy, allow its exact host, TCP port, and resolved private IP:

```sh
./sandbox allow add internal.example.com
./sandbox allow port 8443
./sandbox allow private 10.20.30.40
./sandbox reload
```

The domain must match `allow`, must not match `deny`, and must resolve to an IP in `private_allow`. `private_allow` accepts individual local/private IPs, not entire networks. Remove exceptions by editing that list and reloading. The private service must also be routable from your Docker engine. `host.docker.internal` availability depends on the engine; there is no default host access.

## Local MCP servers

Configure only the servers you want to expose:

```toml
[mcp_servers.internal_docs]
url = "https://docs-api.example.com/mcp"
enabled = true
enabled_tools = ["search", "fetch"] # Replace with actual tool names from this server.
```

```sh
./sandbox allow add docs-api.example.com
./sandbox reload
./sandbox chat
```

A remote MCP transport must honor the configured HTTP proxy. If it does not, it fails closed; it cannot make a direct connection. A stdio MCP process launched in this container shares the same firewall. Install its command in the Docker image, declare `command` and `args` under its named table, and allowlist every service it calls. Disabling a named server uses `enabled = false` or removes its table.

`enabled_tools` permits only the listed tool names; omitted tools stay unavailable. Use the server's actual names. The server at a permitted remote endpoint can perform operations on its own infrastructure. This firewall controls the transport to that server, not its downstream actions.

## Container browser

Use the optional browser image and the supplied local MCP example:

```sh
# First set SANDBOX_IMAGE_TARGET=browser in .env.
cat config/browser.example.toml >> config/codex.toml
./sandbox allow add example.com
./sandbox build
./sandbox reload
./sandbox chat
```

Append the example once. The named `browser` MCP server has an explicit `enabled_tools` list for navigation, snapshots, interaction, screenshots, and tabs. Add a tool name there only when needed. Its Chromium process runs inside the same network namespace as Codex and uses `http://127.0.0.1:3128`. The image pins Playwright MCP, and its arguments use the installed Chromium executable. See [Microsoft's Playwright MCP documentation](https://github.com/microsoft/playwright-mcp) for additional browser options.

Direct browser traffic, DNS, and UDP are blocked by the firewall even if browser proxy settings are removed. Browser access to local app servers remains possible inside the container. This setup provides a container browser; host browser and host Computer Use processes are separate capabilities.

## Hosted search, apps, and connectors

Hosted capabilities are disabled in the bundled Codex config. There is no host account or plugin directory mounted into this sandbox.

To opt into a named plugin, configure the exact plugin ID from your connected Codex installation, enable the capabilities it needs, and allow its container-side endpoints:

```toml
[features]
apps = true
plugins = true

[plugins."your-plugin@your-marketplace"]
enabled = true

# Replace the IDs with actual installed plugin/server names.
[plugins."your-plugin@your-marketplace".mcp_servers.your_server]
enabled_tools = ["one_read_tool", "another_read_tool"]
```

Edit the existing `[features]` table rather than adding a duplicate table. Configure each additional plugin individually; keep unwanted plugins absent/disabled. Installation and login happen in the sandbox's own state volume. Available plugins and authentication support depend on the Codex client and account; the example is a configuration pattern, not a bundled connector.

For hosted web search, `web_search = "live"` enables the capability. It uses OpenAI's hosted service. `tools.web_search.allowed_domains`, where supported, filters search results; it is not an outbound firewall for the search service.

Container-side calls still need an allowed destination. Requests a connector, remote MCP server, or hosted search service makes from its own servers never pass through your container firewall. Use that provider's permissions and tool allowlists to limit those operations. Keep hosted capabilities disabled if every downstream destination must be governed exclusively by your egress policy. [Official OpenAI permission documentation](https://learn.chatgpt.com/docs/permissions) describes these separate surfaces.

## Troubleshooting

| Symptom | Next step |
| --- | --- |
| `TCP_DENIED/403` | Add the exact logged host and required port; reload |
| Allowed page partly loads | Add its required CDN/API hosts, checking each denied connection |
| Connection refused with no proxy decision | The client may ignore proxy variables; configure its HTTP CONNECT support |
| DNS resolution fails inside the agent | Expected for direct DNS; HTTP clients should send hostnames to the proxy |
| IPv6-only or local service fails | Check private-address policy, Docker routing, and proxy support |
| Gateway unhealthy | Run `./sandbox logs`; invalid policy or unavailable kernel firewall support prevents startup |
| Existing session loses networking after reload | Start a new container session in the gateway's current namespace |
| Authentication fails | Inspect the destination log; confirm API-key or device-login prerequisites |

Use `./sandbox shell -- curl -v https://your-host.example/` to inspect a connection, and `./sandbox allow render` to inspect generated rules. Avoid credentials in URLs. The sandbox never responds to a networking failure by granting broader access.
