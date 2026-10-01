"""Live verification inside the actual agent container; no credentials or models."""
import errno
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from check_codex import check_browser_mcp, check_codex

failures = []


def report(label, passed, detail=''):
    print(('PASS ' if passed else 'FAIL ') + label + (' — ' + detail if detail else ''), flush=True)
    if not passed:
        failures.append(label)


def request(url, *extra):
    result = subprocess.run(['curl', '-sS', '--connect-timeout', '3', '--max-time', '15', '-o', '/dev/null', '-w', '%{http_code}', *extra, url], capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr.strip()


# The default policy allows OpenAI; authentication is not required for this probe.
code, status, error = request('https://api.openai.com/v1/models')
report('Allowed HTTPS reaches OpenAI', code == 0 and status in ('401','200'), status or error)
code, status, error = request('http://example.com/')
report('Unlisted HTTP is denied by proxy', code == 0 and status == '403', status or error)
code, status, error = request('https://example.com/')
report('Unlisted HTTPS tunnel is denied', code != 0 and '403' in error, error)
code, status, error = request('https://api.openai.com:8443/')
report('Unlisted port on allowed host is denied', code != 0 and '403' in error, error)
for host in ('169.254.169.254', 'host.docker.internal', '10.0.0.1'):
    code, status, error = request('http://' + host + '/')
    report('Private/host destination denied: ' + host, code == 0 and status == '403', status or error)

for family, host in ((socket.AF_INET,'1.1.1.1'),(socket.AF_INET6,'2606:4700:4700::1111')):
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        try:
            connection.connect((host,443))
            report('Direct TCP blocked: ' + host, False)
        except OSError as error:
            report('Direct TCP blocked: ' + host, error.errno in (errno.EPERM,errno.EACCES,errno.ECONNREFUSED,errno.ENETUNREACH), str(error))

code, status, error = request('https://api.openai.com/', '--noproxy', '*')
report('Clearing proxy cannot bypass firewall', code != 0, error)

# Docker's DNS stub can otherwise forward arbitrary names out of the container.
for protocol, socktype in (('UDP',socket.SOCK_DGRAM),('TCP',socket.SOCK_STREAM)):
    with socket.socket(socket.AF_INET, socktype) as connection:
        connection.settimeout(1)
        try:
            if socktype == socket.SOCK_DGRAM:
                # Valid A query, so receiving a response would prove a DNS leak.
                query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
                connection.connect(('127.0.0.11',53))
                connection.send(query)
                connection.recv(512)
            else:
                connection.connect(('127.0.0.11',53))
            report('Docker DNS bypass blocked: ' + protocol, False)
        except OSError as error:
            report('Docker DNS bypass blocked: ' + protocol, True, str(error))

with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as connection:
    connection.settimeout(1)
    try:
        connection.connect(('1.1.1.1',53))
        connection.send(b'\x00')
        connection.recv(32)
        report('Direct UDP blocked',False)
    except OSError as error:
        report('Direct UDP blocked', error.errno in (errno.EPERM,errno.EACCES,errno.ECONNREFUSED,errno.ENETUNREACH), str(error))

try:
    os.setuid(10001)
    report('Agent cannot impersonate proxy UID',False)
except PermissionError:
    report('Agent cannot impersonate proxy UID',True)

try:
    connection = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
    connection.close()
    report('Raw packets blocked',False)
except PermissionError:
    report('Raw packets blocked',True)

result = subprocess.run(['iptables','-P','OUTPUT','ACCEPT'],capture_output=True,text=True)
report('Agent cannot change firewall',result.returncode != 0)

status_text = Path('/proc/self/status').read_text()
report('No effective or bounding capabilities', 'CapEff:\t0000000000000000' in status_text and 'CapBnd:\t0000000000000000' in status_text)
report('Privilege gains disabled','NoNewPrivs:\t1' in status_text)

path = Path('/usr/local/share') / ('egress-write-check-' + str(os.getpid()))
try:
    path.write_text('container filesystem is writable\n')
    report('Filesystem writable outside workspace',path.read_text().startswith('container'))
finally:
    path.unlink(missing_ok=True)

# A local development server in the sandbox remains usable without egress.
with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
    listener.bind(('127.0.0.1',0))
    listener.listen()
    with socket.create_connection(listener.getsockname(),timeout=2) as client:
        server, _ = listener.accept()
        server.close()
        report('Local app connections work',True)

if shutil.which('chromium'):
    with tempfile.TemporaryDirectory() as profile:
        result = subprocess.run(['chromium','--headless','--no-sandbox','--disable-gpu','--disable-quic','--proxy-server=http://127.0.0.1:3128','--user-data-dir='+profile,'--dump-dom','https://api.openai.com/v1/models'],capture_output=True,text=True,timeout=30)
        report('Chromium reaches allowlisted HTTPS through proxy',result.returncode == 0 and ('Missing bearer' in result.stdout or 'authentication' in result.stdout.lower()),result.stdout[:120])
        result = subprocess.run(['chromium','--headless','--no-sandbox','--disable-gpu','--disable-quic','--proxy-server=http://127.0.0.1:3128','--user-data-dir='+profile,'--dump-dom','https://example.com/'],capture_output=True,text=True,timeout=30)
        report('Chromium unlisted site is blocked','ERR_TUNNEL_CONNECTION_FAILED' in result.stdout + result.stderr)

try:
    check_codex()
    if shutil.which('playwright-mcp'):
        check_browser_mcp()
except Exception as error:
    report('Codex / optional browser MCP configuration',False,str(error))

print(str(len(failures)) + ' failed checks.',flush=True)
raise SystemExit(1 if failures else 0)
