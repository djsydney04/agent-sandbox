use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, net::IpAddr, path::Path};

// Keep the proxy ACL and private-exception validation on the same address set.
const NON_PUBLIC: &str = "0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 ::/128 ::1/128 64:ff9b::/96 100::/64 2001:db8::/32 fc00::/7 fe80::/10 ff00::/8";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub ports: Vec<u16>,
    pub private_allow: Vec<String>,
}

pub fn normalize_host(value: &str) -> Result<String> {
    ensure!(
        !value.is_empty() && value.trim() == value,
        "Hosts must be nonempty without surrounding whitespace."
    );
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let value = value.to_ascii_lowercase();
    let value = value.trim_end_matches('.');
    let host = value.strip_prefix('.').unwrap_or(value);
    ensure!(
        host.len() <= 253 && host.split('.').count() >= 2,
        "Use an exact hostname, IP, or .example.com suffix: {value:?}"
    );
    for label in host.split('.') {
        ensure!(
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "Invalid host (no URLs, ports, paths, or * wildcards): {value:?}"
        );
    }
    Ok(value.to_owned())
}

fn normalize_unique(values: &mut Vec<String>, kind: &str) -> Result<()> {
    *values = values
        .iter()
        .map(|s| normalize_host(s))
        .collect::<Result<_>>()?;
    values.sort();
    ensure!(
        !values.windows(2).any(|w| w[0] == w[1]),
        "Duplicate normalized host in {kind}."
    );
    Ok(())
}

fn non_public(address: IpAddr) -> bool {
    if let IpAddr::V6(v6) = address
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        return non_public(IpAddr::V4(v4));
    }
    NON_PUBLIC.split_whitespace().any(|entry| {
        let (network, bits) = entry.split_once('/').expect("constant CIDR");
        let network: IpAddr = network.parse().expect("constant address");
        let bits: u32 = bits.parse().expect("constant prefix");
        match (address, network) {
            (IpAddr::V4(address), IpAddr::V4(network)) => {
                let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
                u32::from(address) & mask == u32::from(network) & mask
            }
            (IpAddr::V6(address), IpAddr::V6(network)) => {
                let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
                u128::from(address) & mask == u128::from(network) & mask
            }
            _ => false,
        }
    })
}

impl Policy {
    pub fn parse(source: &str) -> Result<Self> {
        // Derived struct deserialization rejects duplicate keys and wrong types.
        let mut policy: Self = serde_json::from_str(source).context("Invalid policy JSON")?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::parse(&fs::read_to_string(path).with_context(|| format!("Read {}", path.display()))?)
    }

    pub fn validate(&mut self) -> Result<()> {
        normalize_unique(&mut self.allow, "allow")?;
        normalize_unique(&mut self.deny, "deny")?;
        ensure!(
            !self.ports.is_empty() && !self.ports.contains(&0),
            "ports must contain integer TCP ports between 1 and 65535."
        );
        self.ports.sort();
        ensure!(
            !self.ports.windows(2).any(|w| w[0] == w[1]),
            "Duplicate port."
        );
        for value in &mut self.private_allow {
            let ip: IpAddr = value
                .parse()
                .context("private_allow accepts exact IP strings only")?;
            ensure!(
                non_public(ip) && !ip.is_unspecified() && !ip.is_multicast(),
                "private_allow accepts exact private/local IPs only: {value}"
            );
            *value = ip.to_string();
        }
        self.private_allow.sort();
        ensure!(
            !self.private_allow.windows(2).any(|w| w[0] == w[1]),
            "Duplicate private IP."
        );
        Ok(())
    }

    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.validate()?;
        let mut temporary = tempfile::NamedTempFile::new_in(
            path.parent().context("Policy needs a parent directory")?,
        )?;
        writeln!(temporary, "{}", serde_json::to_string_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o644))?;
        }
        temporary.as_file().sync_all()?;
        temporary.persist(path).map_err(|error| error.error)?;
        Ok(())
    }

    pub fn allowed(&self, host: &str) -> Result<bool> {
        let host = normalize_host(host)?;
        let matches = |pattern: &String| {
            host == *pattern
                || pattern
                    .strip_prefix('.')
                    .is_some_and(|apex| host == apex || host.ends_with(pattern))
        };
        Ok(self.allow.iter().any(matches) && !self.deny.iter().any(matches))
    }

    pub fn fingerprint(&self) -> String {
        // Validation canonicalizes all lists before a policy reaches this method.
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).expect("serialize policy"))
        )
    }

    pub fn render(&self) -> String {
        let mut lines: Vec<String> = [
            "http_port 127.0.0.1:3128",
            "visible_hostname codex-egress-sandbox",
            "pid_filename /tmp/squid.pid",
            "cache_effective_user egress-proxy",
            "cache_effective_group egress-proxy",
            "cache deny all",
            "cache_store_log none",
            "cache_log /dev/stderr",
            "logformat egress %ts.%03tu %Ss/%03>Hs %rm %>rd:%>rP",
            "access_log stdio:/dev/stdout egress",
            "logfile_rotate 0",
            "forwarded_for delete",
            "via off",
            "pinger_enable off",
            "shutdown_lifetime 1 seconds",
            "connect_timeout 10 seconds",
            "acl manager proto cache_object",
        ]
        .iter()
        .map(|s| (*s).into())
        .collect();
        lines.push(format!(
            "acl safe_ports port {}",
            self.ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        ));
        lines.extend([
            "http_access deny manager".into(),
            "http_access deny !safe_ports".into(),
        ]);
        if !self.deny.is_empty() {
            lines.extend([
                format!("acl denied dstdomain -n {}", self.deny.join(" ")),
                "http_access deny denied".into(),
            ]);
        }
        if !self.allow.is_empty() {
            lines.extend([
                format!("acl permitted dstdomain -n {}", self.allow.join(" ")),
                "http_access deny !permitted".into(),
            ]);
            if !self.private_allow.is_empty() {
                let entries = self
                    .private_allow
                    .iter()
                    .map(|ip| format!("{ip}/{}", if ip.contains(':') { 128 } else { 32 }))
                    .collect::<Vec<_>>()
                    .join(" ");
                lines.extend([
                    format!("acl private_exception dst {entries}"),
                    "http_access allow permitted private_exception".into(),
                ]);
            }
            lines.extend([
                format!("acl non_public dst {NON_PUBLIC}"),
                "http_access deny non_public".into(),
                "http_access allow permitted".into(),
            ]);
        }
        lines.push("http_access deny all".into());
        lines.join("\n") + "\n"
    }
}

pub fn profile(name: &str) -> Result<Vec<String>> {
    let entries: &[&str] = match name {
        "openai" => &["api.openai.com", "auth.openai.com", "chatgpt.com"],
        "github" => &[
            "github.com",
            "api.github.com",
            "raw.githubusercontent.com",
            "objects.githubusercontent.com",
            "codeload.github.com",
        ],
        "npm" => &["registry.npmjs.org"],
        "python" => &["pypi.org", "files.pythonhosted.org"],
        "development" => {
            return Ok([profile("github")?, profile("npm")?, profile("python")?].concat());
        }
        _ => bail!("Unknown profile {name:?}; use openai, github, npm, python, or development."),
    };
    Ok(entries.iter().map(|s| (*s).into()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Policy {
        Policy::parse(
            r#"{"allow":["api.example.com"],"deny":[],"ports":[80,443],"private_allow":[]}"#,
        )
        .unwrap()
    }

    #[test]
    fn exact_hosts_exclude_siblings_and_subdomains() {
        let p = base();
        assert!(p.allowed("api.example.com").unwrap());
        assert!(!p.allowed("example.com").unwrap());
        assert!(!p.allowed("evil.api.example.com").unwrap());
    }

    #[test]
    fn suffix_and_deny_precedence() {
        let mut p = base();
        p.allow = vec![".example.com".into()];
        p.deny = vec!["blocked.example.com".into()];
        for host in ["example.com", "api.example.com", "a.b.example.com"] {
            assert!(p.allowed(host).unwrap());
        }
        for host in ["blocked.example.com", "example.com.evil.com"] {
            assert!(!p.allowed(host).unwrap());
        }
    }

    #[test]
    fn injection_and_global_wildcards_rejected() {
        for host in [
            "*",
            ".com",
            "*.example.com",
            "https://example.com",
            "example.com:443",
            "example.com/path",
            "example.com\nhttp_access allow all",
            " example.com",
            "example..com",
            "-example.com",
            "é.example.com",
        ] {
            assert!(normalize_host(host).is_err(), "{host}");
        }
    }

    #[test]
    fn hosts_and_ips_normalized() {
        assert_eq!(
            normalize_host("API.Example.COM.").unwrap(),
            "api.example.com"
        );
        assert_eq!(normalize_host("2001:0db8::1").unwrap(), "2001:db8::1");
    }

    #[test]
    fn duplicate_keys_and_normalized_hosts_rejected() {
        assert!(
            Policy::parse(r#"{"allow":[],"allow":[],"deny":[],"ports":[443],"private_allow":[]}"#)
                .is_err()
        );
        let mut p = base();
        p.allow.push("API.EXAMPLE.COM.".into());
        assert!(p.validate().is_err());
    }

    #[test]
    fn invalid_schema_and_ports_fail_closed() {
        for input in [
            r#"{"allow":[],"deny":[],"ports":[],"private_allow":[]}"#,
            r#"{"allow":[],"deny":[],"ports":[true],"private_allow":[]}"#,
            r#"{"allow":[],"deny":[],"ports":[0],"private_allow":[]}"#,
            r#"{"allow":[],"deny":[],"ports":[65536],"private_allow":[]}"#,
            r#"{"allow":[],"deny":[],"ports":[443,443],"private_allow":[]}"#,
            r#"{"allow":"example.com","deny":[],"ports":[443],"private_allow":[]}"#,
            r#"{"allow":[],"deny":[],"ports":[443],"private_allow":[],"unknown":true}"#,
        ] {
            assert!(Policy::parse(input).is_err(), "{input}");
        }
    }

    #[test]
    fn private_exceptions_are_exact_nonpublic_addresses() {
        for invalid in ["0.0.0.0/0", "8.8.8.8", "0.0.0.0", "::", "ff02::1"] {
            let mut p = base();
            p.private_allow = vec![invalid.into()];
            assert!(p.validate().is_err(), "{invalid}");
        }
        for valid in ["10.0.0.1", "127.0.0.1", "::1", "fd00::1", "::ffff:10.0.0.1"] {
            let mut p = base();
            p.private_allow = vec![valid.into()];
            assert!(p.validate().is_ok(), "{valid}");
        }
    }

    #[test]
    fn empty_allowlist_renders_no_permit_rule() {
        let mut p = base();
        p.allow.clear();
        assert!(!p.render().contains("http_access allow"));
        assert!(p.render().ends_with("http_access deny all\n"));
    }

    #[test]
    fn private_exception_still_requires_host_and_port() {
        let mut p = base();
        p.private_allow = vec!["10.0.0.1".into()];
        let config = p.render();
        assert!(
            config.find("http_access deny !safe_ports").unwrap()
                < config
                    .find("http_access allow permitted private_exception")
                    .unwrap()
        );
        assert!(
            config.find("http_access deny !permitted").unwrap()
                < config
                    .find("http_access allow permitted private_exception")
                    .unwrap()
        );
        assert!(
            config.find("http_access deny non_public").unwrap()
                < config.find("http_access allow permitted\n").unwrap()
        );
    }

    #[test]
    fn fingerprint_tracks_canonical_effective_policy() {
        let p = base();
        let mut other = p.clone();
        other.ports.reverse();
        other.validate().unwrap();
        assert_eq!(p.fingerprint(), other.fingerprint());
        other.deny.push("api.example.com".into());
        assert_ne!(p.fingerprint(), other.fingerprint());
    }

    #[test]
    fn invalid_save_preserves_file_and_leaves_no_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network.json");
        let mut p = base();
        p.save(&path).unwrap();
        let before = fs::read(&path).unwrap();
        p.allow.push("*".into());
        assert!(p.save(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
