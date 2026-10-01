#!/bin/sh
set -eu

# Install policies before starting the proxy or allowing an agent to join.
# These chains live in the shared network namespace, outside the agent filesystem.
for firewall in iptables ip6tables; do
    "$firewall" -w -P OUTPUT DROP
    "$firewall" -w -P FORWARD DROP
    "$firewall" -w -F OUTPUT
    "$firewall" -w -A OUTPUT -m owner --uid-owner 10001 -j ACCEPT
done

# Docker's DNS stub rewrites port 53 before OUTPUT filtering. Block its entire IP
# before allowing loopback, rather than just blocking its original DNS port.
iptables -w -A OUTPUT -d 127.0.0.11 -j REJECT
iptables -w -A OUTPUT -o lo -j ACCEPT
iptables -w -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w -A OUTPUT -j REJECT
ip6tables -w -A OUTPUT -o lo -j ACCEPT
ip6tables -w -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -w -A OUTPUT -j REJECT

sandbox-helper gateway render /policy/network.json /run/squid.conf /run/policy.sha256

# Docker creates these pipes as root. Permit the unprivileged proxy to reopen
# its own inherited stdout/stderr for destination-only logging.
chmod a+w /dev/stdout /dev/stderr

# Squid owns outbound connections. Neither it nor the agent retains capabilities
# to change the firewall or assume another UID.
exec setpriv --reuid=10001 --regid=10001 --clear-groups \
    --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
    squid -N -f /run/squid.conf
