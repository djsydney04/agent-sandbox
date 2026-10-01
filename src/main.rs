mod policy;

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand};
use policy::{Policy, normalize_host, profile};
use serde_json::Value;
use std::{
    env, fs,
    io::{self, IsTerminal, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

#[derive(Parser)]
#[command(
    name = "sandbox",
    version,
    about = "Codex Docker sandbox with an external egress allowlist"
)]
struct Cli {
    /// Project directory (also selectable with SANDBOX_ROOT).
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Build the gateway and selected agent image.
    Build,
    /// Start the gateway and apply any policy changes.
    Up,
    /// Apply policy changes and close existing proxy tunnels.
    Reload,
    /// Stop this project's containers; preserve login state.
    Down,
    /// Show runtime, versions, policy fingerprint, and capabilities.
    Doctor,
    /// Run live firewall checks without a model request.
    Verify,
    /// Show proxy decisions (host and port only).
    Logs {
        #[arg(long)]
        follow: bool,
    },
    /// Run a Codex task noninteractively.
    Run {
        prompt: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        ephemeral: bool,
    },
    /// Open an interactive Codex session.
    Chat {
        prompt: Option<String>,
        #[arg(long)]
        model: Option<String>,
    },
    /// Open bash or run a command inside the firewall.
    Shell(Passthrough),
    /// Sign into the sandbox's own credential volume.
    Login {
        #[arg(long)]
        api_key: bool,
    },
    /// Check the sandbox's authentication.
    LoginStatus,
    /// Remove its cached authentication.
    Logout,
    /// Edit and inspect the host-controlled network policy.
    Allow {
        #[command(subcommand)]
        operation: Allow,
    },
    /// Manage this project's dedicated Lima VM.
    Vm {
        #[command(subcommand)]
        operation: Vm,
    },
    /// Run Docker commands against the selected engine (also used by tests).
    Docker(Passthrough),
    #[command(hide = true)]
    Gateway {
        #[command(subcommand)]
        operation: Gateway,
    },
}

#[derive(Args)]
struct Passthrough {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Subcommand)]
enum Allow {
    List,
    Render,
    /// Print the canonical policy SHA256.
    Fingerprint,
    Check {
        host: String,
    },
    Add {
        #[arg(required = true)]
        hosts: Vec<String>,
    },
    Deny {
        #[arg(required = true)]
        hosts: Vec<String>,
    },
    Remove {
        #[arg(required = true)]
        hosts: Vec<String>,
    },
    Profile {
        #[arg(value_parser = ["openai", "github", "npm", "python", "development"])]
        name: String,
    },
    Port {
        #[arg(required = true)]
        ports: Vec<u16>,
    },
    Private {
        #[arg(required = true)]
        ips: Vec<String>,
    },
}

#[derive(Subcommand)]
enum Vm {
    Start,
    Stop,
}

#[derive(Subcommand)]
enum Gateway {
    Render {
        policy: PathBuf,
        output: PathBuf,
        fingerprint: PathBuf,
    },
    Healthcheck,
}

fn root_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit.or_else(|| env::var_os("SANDBOX_ROOT").map(PathBuf::from)) {
        return path
            .canonicalize()
            .context("Resolve sandbox project directory");
    }
    for origin in [env::current_dir()?, env::current_exe()?] {
        if let Some(path) = origin
            .ancestors()
            .find(|p| p.join("compose.yaml").is_file() && p.join("config/network.json").is_file())
        {
            return Ok(path.to_path_buf());
        }
    }
    bail!("Cannot find the sandbox project; pass --root PATH or use ./sandbox.")
}

struct Runtime {
    root: PathBuf,
}

impl Runtime {
    fn docker(&self, args: &[String]) -> Result<Command> {
        if let Ok(override_command) = env::var("SANDBOX_DOCKER") {
            let words = shell_words::split(&override_command).context("Parse SANDBOX_DOCKER")?;
            let (program, arguments) = words
                .split_first()
                .context("SANDBOX_DOCKER must not be empty")?;
            let mut command = Command::new(program);
            command.args(arguments).args(args);
            return Ok(command);
        }
        if self.root.join(".runtime/lima/codex-egress").is_dir() {
            let mut command = Command::new("limactl");
            command.env("LIMA_HOME", self.root.join(".runtime/lima"));
            command.args(["shell", "codex-egress", "--", "env"]);
            // Forward only nonsecret project settings through the VM boundary.
            for name in [
                "COMPOSE_PROJECT_NAME",
                "CODEX_VERSION",
                "SANDBOX_IMAGE_TARGET",
                "SANDBOX_WORKSPACE",
                "TERM",
            ] {
                if let Ok(value) = env::var(name) {
                    command.arg(format!("{name}={value}"));
                }
            }
            command.arg("docker").args(args);
            return Ok(command);
        }
        let mut command = Command::new("docker");
        command.args(args);
        Ok(command)
    }

    fn compose(&self, args: &[&str]) -> Result<Command> {
        let mut values = vec![
            "compose".into(),
            "--project-directory".into(),
            self.root.display().to_string(),
            "--file".into(),
            self.root.join("compose.yaml").display().to_string(),
        ];
        values.extend(args.iter().map(|s| (*s).to_owned()));
        self.docker(&values)
    }

    fn checked(&self, args: &[&str]) -> Result<()> {
        let status = self
            .compose(args)?
            .status()
            .context("Run Docker Compose; start your Docker engine first")?;
        ensure!(status.success(), "Docker Compose failed with {status}.");
        Ok(())
    }

    fn capture(&self, args: &[&str]) -> Result<String> {
        let output = self
            .compose(args)?
            // Lima's persistent SSH master can retain stderr after the command
            // exits. Inherit it so capturing config cannot wait on that pipe.
            .stderr(Stdio::inherit())
            .output()
            .context("Run Docker Compose; start your Docker engine first")?;
        ensure!(
            output.status.success(),
            "Docker Compose failed with {}.",
            output.status
        );
        String::from_utf8(output.stdout).context("Docker output was not UTF-8")
    }

    fn check_workspace(&self) -> Result<()> {
        let config: Value = serde_json::from_str(&self.capture(&["config", "--format", "json"])?)?;
        let agent = &config["services"]["agent"];
        ensure!(
            agent["network_mode"] == "service:gateway" && agent["privileged"] != true,
            "agent must share only the gateway network namespace and must not be privileged."
        );
        ensure!(
            agent["cap_drop"] == serde_json::json!(["ALL"])
                && agent["cap_add"].as_array().is_none_or(Vec::is_empty)
                && agent["user"] == "0:0",
            "agent must run as 0:0 with all capabilities dropped, so it cannot impersonate the proxy UID."
        );
        ensure!(
            agent["security_opt"]
                .as_array()
                .is_some_and(|options| options.iter().any(|o| o == "no-new-privileges:true")),
            "agent must set no-new-privileges:true."
        );
        if let Some(mounts) = agent["volumes"].as_array() {
            for mount in mounts {
                if mount["type"] != "bind" {
                    continue;
                }
                let target = mount["target"].as_str().context("Mount has no target")?;
                ensure!(
                    !matches!(target, "/var/run/docker.sock" | "/run/docker.sock"),
                    "Do not mount the Docker socket into the agent."
                );
                if target == "/workspace" {
                    let source = Path::new(
                        mount["source"]
                            .as_str()
                            .context("Workspace has no source")?,
                    );
                    fs::create_dir_all(source)?;
                    let source = source.canonicalize()?;
                    ensure!(
                        !self.root.join("config").starts_with(&source),
                        "The workspace must not contain this sandbox's policy files. Use ./workspace or a separate project directory."
                    );
                }
            }
        }
        Ok(())
    }

    fn ensure_up(&self, policy: &Policy, force: bool) -> Result<()> {
        self.check_workspace()?;
        self.checked(&["up", "-d", "--wait", "gateway"])?;
        let active = self.capture(&["exec", "-T", "gateway", "cat", "/run/policy.sha256"])?;
        if force || active.trim() != policy.fingerprint() {
            println!("Applying policy; existing proxied connections will close.");
            self.checked(&["restart", "gateway"])?;
            self.checked(&["up", "-d", "--wait", "gateway"])?;
            let active = self.capture(&["exec", "-T", "gateway", "cat", "/run/policy.sha256"])?;
            ensure!(
                active.trim() == policy.fingerprint(),
                "Gateway did not apply the requested policy; refusing to start an agent."
            );
        }
        Ok(())
    }

    fn run_container(&self, command: &[String], no_tty: bool, input: Option<&str>) -> Result<i32> {
        let mut args = vec!["run", "--rm", "--no-deps"];
        if no_tty || !io::stdin().is_terminal() {
            args.push("-T");
        }
        args.push("agent");
        args.extend(command.iter().map(String::as_str));
        let mut process = self.compose(&args)?;
        if let Some(input) = input {
            let mut child = process.stdin(Stdio::piped()).spawn()?;
            child
                .stdin
                .take()
                .context("Open credential stdin")?
                .write_all(input.as_bytes())?;
            return Ok(exit_code(child.wait()?));
        }
        Ok(exit_code(process.status()?))
    }

    fn vm(&self, operation: Vm) -> Result<i32> {
        let home = self.root.join(".runtime/lima");
        let exists = home.join("codex-egress").is_dir();
        let mut command = Command::new("limactl");
        command.env("LIMA_HOME", &home);
        match operation {
            Vm::Start => {
                fs::create_dir_all(&home)?;
                if exists {
                    command.args(["start", "--tty=false", "codex-egress"]);
                } else {
                    command.args([
                        "start",
                        "--tty=false",
                        "--name=codex-egress",
                        "--vm-type=vz",
                        "--cpus=2",
                        "--memory=3",
                        "--disk=16",
                    ]);
                    command
                        .arg(format!("--mount-only={}:w", self.root.display()))
                        .arg("template:docker-rootful");
                }
            }
            Vm::Stop => {
                if !exists {
                    println!("No sandbox VM has been created.");
                    return Ok(0);
                }
                command.args(["stop", "codex-egress"]);
            }
        }
        Ok(exit_code(command.status().context(
            "Run Lima; install limactl to use the dedicated macOS VM",
        )?))
    }
}

fn edit(policy: &mut Policy, operation: Allow) -> Result<bool> {
    match operation {
        Allow::List => println!("{}", serde_json::to_string_pretty(policy)?),
        Allow::Render => print!("{}", policy.render()),
        Allow::Fingerprint => println!("{}", policy.fingerprint()),
        Allow::Check { host } => {
            let host = normalize_host(&host)?;
            println!(
                "{} {host} (host rule only; ports and private-IP restrictions also apply)",
                if policy.allowed(&host)? {
                    "ALLOW"
                } else {
                    "DENY"
                }
            );
        }
        Allow::Add { hosts } | Allow::Deny { hosts } | Allow::Remove { hosts } => {
            // Resolved below in edit_hosts, before changing or saving the policy.
            let _ = hosts;
            unreachable!("Host edits are handled separately");
        }
        Allow::Profile { name } => {
            policy.allow.extend(profile(&name)?);
            policy.allow.sort();
            policy.allow.dedup();
            return Ok(true);
        }
        Allow::Port { ports } => {
            policy.ports.extend(ports);
            policy.ports.sort();
            policy.ports.dedup();
            return Ok(true);
        }
        Allow::Private { ips } => {
            let ips = ips
                .iter()
                .map(|s| s.parse::<std::net::IpAddr>().map(|ip| ip.to_string()))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            policy.private_allow.extend(ips);
            policy.private_allow.sort();
            policy.private_allow.dedup();
            return Ok(true);
        }
    }
    Ok(false)
}

fn allow(path: &Path, operation: Allow) -> Result<()> {
    let mut policy = Policy::load(path)?;
    let changed = match operation {
        Allow::Add { hosts } => {
            policy.allow.extend(
                hosts
                    .iter()
                    .map(|h| normalize_host(h))
                    .collect::<Result<Vec<_>>>()?,
            );
            policy.allow.sort();
            policy.allow.dedup();
            true
        }
        Allow::Deny { hosts } => {
            policy.deny.extend(
                hosts
                    .iter()
                    .map(|h| normalize_host(h))
                    .collect::<Result<Vec<_>>>()?,
            );
            policy.deny.sort();
            policy.deny.dedup();
            true
        }
        Allow::Remove { hosts } => {
            let hosts = hosts
                .iter()
                .map(|h| normalize_host(h))
                .collect::<Result<Vec<_>>>()?;
            policy.allow.retain(|h| !hosts.contains(h));
            policy.deny.retain(|h| !hosts.contains(h));
            true
        }
        other => edit(&mut policy, other)?,
    };
    if changed {
        policy.save(path)?;
        println!(
            "Saved config/network.json. Run ./sandbox reload to apply now; the next sandbox command also applies changes."
        );
    }
    Ok(())
}

fn gateway(operation: Gateway) -> Result<()> {
    match operation {
        Gateway::Render {
            policy,
            output,
            fingerprint,
        } => {
            let policy = Policy::load(&policy)?;
            fs::write(output, policy.render())?;
            fs::write(fingerprint, policy.fingerprint() + "\n")?;
        }
        Gateway::Healthcheck => {
            ensure!(
                Path::new("/run/policy.sha256").is_file(),
                "Missing running policy fingerprint."
            );
            let address: SocketAddr = "127.0.0.1:3128".parse()?;
            let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            stream.write_all(b"GET http://sandbox-health.invalid/ HTTP/1.1\r\nHost: sandbox-health.invalid\r\nConnection: close\r\n\r\n")?;
            let mut response = [0; 128];
            let count = stream.read(&mut response)?;
            ensure!(
                String::from_utf8_lossy(&response[..count])
                    .lines()
                    .next()
                    .is_some_and(|line| line.contains(" 403 ")),
                "Proxy did not deny the healthcheck destination."
            );
        }
    }
    Ok(())
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).into()).collect()
}

fn execute(cli: Cli) -> Result<i32> {
    if let Action::Gateway { operation } = cli.command {
        gateway(operation)?;
        return Ok(0);
    }
    let runtime = Runtime {
        root: root_path(cli.root)?,
    };
    let policy_path = runtime.root.join("config/network.json");
    match cli.command {
        Action::Vm { operation } => return runtime.vm(operation),
        Action::Docker(args) => return Ok(exit_code(runtime.docker(&args.args)?.status()?)),
        Action::Allow { operation } => {
            allow(&policy_path, operation)?;
            return Ok(0);
        }
        Action::Down => {
            runtime.checked(&["down"])?;
            return Ok(0);
        }
        Action::Logs { follow } => {
            let mut args = vec!["logs", "--tail", "100"];
            if follow {
                args.push("--follow");
            }
            args.push("gateway");
            runtime.checked(&args)?;
            return Ok(0);
        }
        _ => {}
    }
    let policy = Policy::load(&policy_path)?;
    if matches!(cli.command, Action::Build) {
        runtime.check_workspace()?;
        runtime.checked(&["build"])?;
        return Ok(0);
    }
    runtime.ensure_up(&policy, matches!(cli.command, Action::Reload))?;
    let mut no_tty = false;
    let command = match cli.command {
        Action::Up | Action::Reload => return Ok(0),
        Action::Doctor => {
            runtime.checked(&["ps"])?;
            println!("Policy SHA256: {}", policy.fingerprint());
            no_tty = true;
            strings(&[
                "sh",
                "-c",
                "codex --version && python3 --version && git --version && grep -E \"^(Uid|CapEff|CapBnd|NoNewPrivs):\" /proc/self/status",
            ])
        }
        Action::Verify => {
            no_tty = true;
            strings(&["python3", "/opt/sandbox/verify.py"])
        }
        Action::Shell(args) => {
            if args.args.is_empty() {
                strings(&["bash"])
            } else {
                args.args
            }
        }
        Action::Login { api_key: true } => {
            let mut key = rpassword::prompt_password("OpenAI API key: ")?;
            ensure!(!key.is_empty(), "An API key is required.");
            key.push('\n');
            return runtime.run_container(
                &strings(&["codex", "login", "--with-api-key"]),
                true,
                Some(&key),
            );
        }
        Action::Login { api_key: false } => strings(&["codex", "login", "--device-auth"]),
        Action::LoginStatus => strings(&["codex", "login", "status"]),
        Action::Logout => strings(&["codex", "logout"]),
        Action::Run {
            prompt,
            model,
            json,
            ephemeral,
        } => {
            let mut command = strings(&[
                "codex",
                "exec",
                "--skip-git-repo-check",
                "--strict-config",
                "--dangerously-bypass-approvals-and-sandbox",
            ]);
            if json {
                command.push("--json".into());
            }
            if ephemeral {
                command.push("--ephemeral".into());
            }
            if let Some(model) = model {
                command.extend(["--model".into(), model]);
            }
            if let Some(prompt) = prompt {
                command.push(prompt);
            }
            command
        }
        Action::Chat { prompt, model } => {
            let mut command = strings(&[
                "codex",
                "--strict-config",
                "--dangerously-bypass-approvals-and-sandbox",
            ]);
            if let Some(model) = model {
                command.extend(["--model".into(), model]);
            }
            if let Some(prompt) = prompt {
                command.push(prompt);
            }
            command
        }
        _ => unreachable!("Non-agent commands were handled above"),
    };
    runtime.run_container(&command, no_tty, None)
}

fn main() {
    let code = match execute(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("sandbox: {error:#}");
            1
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_edits_are_atomic_and_remove_denies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("network.json");
        fs::write(
            &path,
            r#"{"allow":["api.example.com"],"deny":[],"ports":[80,443],"private_allow":[]}"#,
        )
        .unwrap();
        allow(
            &path,
            Allow::Add {
                hosts: strings(&["registry.npmjs.org"]),
            },
        )
        .unwrap();
        assert!(
            Policy::load(&path)
                .unwrap()
                .allow
                .contains(&"registry.npmjs.org".into())
        );
        allow(
            &path,
            Allow::Deny {
                hosts: strings(&["api.example.com"]),
            },
        )
        .unwrap();
        assert!(
            !Policy::load(&path)
                .unwrap()
                .allowed("api.example.com")
                .unwrap()
        );
        allow(
            &path,
            Allow::Remove {
                hosts: strings(&["api.example.com"]),
            },
        )
        .unwrap();
        let p = Policy::load(&path).unwrap();
        assert!(
            !p.allow.contains(&"api.example.com".into())
                && !p.deny.contains(&"api.example.com".into())
        );
        let before = fs::read(&path).unwrap();
        assert!(
            allow(
                &path,
                Allow::Add {
                    hosts: strings(&["*"])
                }
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn shell_and_docker_arguments_preserve_flags_and_literals() {
        for name in ["shell", "docker"] {
            let cli = Cli::try_parse_from([
                "sandbox",
                name,
                "--",
                "curl",
                "--noproxy",
                "*",
                "https://example.com/?a=$HOME",
            ])
            .unwrap();
            let arguments = match cli.command {
                Action::Shell(args) | Action::Docker(args) => args.args,
                _ => panic!(),
            };
            assert_eq!(
                arguments,
                strings(&["curl", "--noproxy", "*", "https://example.com/?a=$HOME"])
            );
        }
    }
}
