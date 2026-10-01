# Codex egress sandbox

A small, independent Docker sandbox for unattended Codex work. Codex can edit files and run commands freely inside the container. A separate gateway permits outgoing HTTP/HTTPS only to hosts you allowlist. Removing proxy variables cannot open direct TCP, UDP, DNS, or IPv6 access.

The CLI, allowlist parser, proxy configuration generator, healthcheck, and VM helpers are implemented in Rust. The host and gateway use the same policy implementation. The project has its own images, network, credential volume, and optional test VM. It does not mount your home directory, host Codex configuration, SSH agent, or Docker socket.

## Start

Install [Rust through rustup](https://rustup.rs) and Docker with Compose v2 on the host. Use macOS, Linux, or WSL on Windows. The project pins Rust 1.90.0 and commits `Cargo.lock`; `./sandbox` builds and runs the Rust CLI automatically. Start Docker, then:

```sh
cp .env.example .env
./sandbox build
./sandbox verify
./sandbox login
./sandbox run "Create a small hello-world app and run it."
```

`login` uses a device code, so no callback port needs publishing. Open its link in your normal browser. Alternatively, `./sandbox login --api-key` securely prompts for a key and sends it through stdin. Credentials stay in this project's Docker volume. [Official OpenAI authentication documentation](https://learn.chatgpt.com/docs/auth) explains the account prerequisites.

The default workspace is `./workspace`. Set `SANDBOX_WORKSPACE` in `.env` to an absolute path to another project when needed. Changes in `/workspace` write through to that directory. Keep the sandbox's own policy files outside the mounted workspace.

For an isolated macOS test engine using an installed Lima:

```sh
./sandbox vm start
./sandbox build
./sandbox verify
```

This creates only `.runtime/lima/codex-egress`, mounts only this project into the VM, and does not change your global Docker context. Repeating `vm start` starts the existing instance. The launcher detects this dedicated runtime automatically. Use `SANDBOX_DOCKER=docker ./sandbox ...` to explicitly select your regular Docker engine. Stop the test VM with `./sandbox vm stop`. The scripts in `tools/` remain thin compatibility launchers for these Rust commands.

## Add network access

Only OpenAI API, authentication, and ChatGPT hosts are initially allowed. Development registries and websites are opt-in:

```sh
./sandbox allow add example.com api.example.com
./sandbox allow profile development    # GitHub, npm, and PyPI
./sandbox allow deny tracking.example.com
./sandbox allow list
./sandbox reload
```

You can also edit [config/network.json](config/network.json). Exact hosts allow only themselves. A leading dot, such as `.example.com`, allows the apex and all its subdomains. Deny entries override allow entries. Global wildcards are rejected. Emptying `allow` blocks all external destinations.

Policy edits apply on `reload` or the next `up`, `run`, `chat`, `shell`, or `verify`. Applying changes restarts the gateway and closes existing tunnels. Start a new container session after reloading; an existing container may still hold the previous network namespace. Image rebuilds are unnecessary for policy changes.

See [the allowlisting guide](docs/allowlisting.md) for domains, ports, local endpoints, browser tools, MCP servers, connectors, redirects, and troubleshooting.

## Everyday commands

| Command | Purpose |
| --- | --- |
| `./sandbox chat` | Interactive Codex session with automatic command execution |
| `./sandbox run "task"` | Run a task noninteractively |
| `./sandbox run --json --ephemeral "task"` | JSON events without saved session history |
| `./sandbox shell` | Open bash behind the same firewall |
| `./sandbox shell -- curl https://api.openai.com/v1/models` | Run one command; a 401 without credentials is expected |
| `./sandbox allow profile github` | Add only GitHub's common development hosts |
| `./sandbox allow remove example.com` | Remove an exact entry from both allow and deny |
| `./sandbox allow check example.com` | Check host matching without making a network request |
| `./sandbox reload` | Apply network changes and terminate old proxy tunnels |
| `./sandbox logs --follow` | Watch allowed and denied destinations |
| `./sandbox doctor` | Show runtime, versions, policy fingerprint, and capabilities |
| `./sandbox verify` | Run live firewall checks without credentials or model calls |
| `./sandbox login-status` | Check the sandbox's own authentication |
| `./sandbox logout` | Remove its cached authentication |
| `./sandbox down` | Stop the gateway and remove its network; preserve login state |
| `./sandbox vm start` / `./sandbox vm stop` | Start or stop the dedicated macOS Lima runtime |

Codex runs with `approval_policy = "never"` and `danger-full-access` inside Docker. The launcher passes the corresponding CLI flag explicitly. The external Docker firewall remains in force for the Codex client and every process it starts. [Official OpenAI documentation](https://learn.chatgpt.com/docs/agent-approvals-security) distinguishes approval policy from sandbox enforcement.

## Browser and MCP tools

Local MCP servers are configured individually in [config/codex.toml](config/codex.toml). Their processes share the firewall. For a browser:

1. Set `SANDBOX_IMAGE_TARGET=browser` in `.env`.
2. Append [config/browser.example.toml](config/browser.example.toml) to `config/codex.toml`.
3. Add each site and required asset/API host with `./sandbox allow add ...`.
4. Run `./sandbox build`, then `./sandbox verify` and `./sandbox chat`.

The optional image installs Chromium and a pinned Playwright MCP server. It explicitly uses the proxy. Unlisted assets and redirects remain blocked.

Hosted search, apps, plugins, image generation, and host browser/computer access are off by default. Hosted services perform their own downstream requests outside your Docker network; an egress firewall cannot constrain those requests. The allowlisting guide explains how to enable named tools while preserving that distinction.

## Verification and scope

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
./sandbox verify
python3 tests/runtime.py
```

Rust unit tests exercise policy validation and atomic CLI edits. Python is needed only for the live test scripts: it is installed in the agent image, and Python 3.9+ on the host runs `tests/runtime.py`. Production helpers do not depend on Python.

`verify` tests the bundled baseline: allowed OpenAI HTTPS, rejected HTTP/HTTPS destinations, ports, private/host targets, direct IPv4/IPv6, Docker DNS, raw packets, UID impersonation, firewall edits, writable container files, and Codex's actual strict configuration. With the browser image, it also tests real Chromium and Playwright MCP navigation. If you intentionally change those baseline permissions, some negative checks will correctly stop passing.

`tests/runtime.py` creates a separate temporary Compose project and checks suffix rules, deny precedence, an empty allowlist, private-address restrictions and explicit exceptions, redirects, and fail-closed behavior when the proxy stops. It removes only its own test containers and volume.

[Architecture and limits](docs/architecture.md) describes the enforcement boundary. The firewall limits destinations, not operations at an allowed destination. HTTPS stays end-to-end encrypted; there is no custom root certificate. The mounted workspace and sandbox login state are accessible to Codex. Docker image pulls, package installation during image builds, and VM provisioning are trusted setup steps outside the runtime allowlist.

## Build the helper binary

```sh
cargo build --locked --release
./target/release/sandbox --root "$PWD" allow list
```

The resulting binary can run without Cargo or a Python interpreter; keep `compose.yaml` and `config/` with the project and pass `--root` when running elsewhere. The gateway builds its Linux copy from the same Rust sources in a multi-stage Dockerfile. Rust and Cargo stay out of the final gateway image. The small shell entrypoints only launch the binary or install Linux firewall rules before dropping privileges.
