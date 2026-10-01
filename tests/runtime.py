"""Exercise real policy changes in an independent, disposable Compose project."""
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent.parent
def docker_command():
    return [str(ROOT / 'sandbox'), 'docker', '--']

project = 'codex-egress-test-' + uuid.uuid4().hex[:10]
failures = []


def check(label, success, detail=''):
    print(('PASS ' if success else 'FAIL ') + label + (' — ' + detail if detail else ''), flush=True)
    if not success:
        failures.append(label)


def main():
    (ROOT / '.runtime').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='policy-test-', dir=ROOT / '.runtime') as directory:
        source = Path(directory)
        policy_dir = source / 'config'
        policy_dir.mkdir()
        (source / 'workspace').mkdir()
        override = source / 'compose.json'
        override.write_text(json.dumps({'services':{
            'gateway':{'volumes':[{'type':'bind','source':str(policy_dir),'target':'/policy','read_only':True}], 'extra_hosts':['private-test.example:127.0.0.1']},
            'agent':{'volumes':[{'type':'bind','source':str(source / 'workspace'),'target':'/workspace'}]},
        }}))
        command = docker_command() + ['compose','--project-directory',str(ROOT),'-p',project,'-f',str(ROOT / 'compose.yaml'),'-f',str(override)]

        def compose(*args, required=True):
            result = subprocess.run(command + list(args),capture_output=True,text=True,timeout=120)
            if required and result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            return result

        def write_policy(policy):
            (policy_dir / 'network.json').write_text(json.dumps(policy))

        def apply(policy):
            write_policy(policy)
            compose('restart','gateway')
            compose('up','-d','--wait','gateway')
            fingerprint = compose('exec','-T','gateway','cat','/run/policy.sha256').stdout.strip()
            expected = subprocess.run([str(ROOT / 'sandbox'), '--root',str(source),'allow','fingerprint'],capture_output=True,text=True,check=True).stdout.strip()
            check('Running policy fingerprint matches host', fingerprint == expected)

        def run_agent(*args):
            return compose('run','--rm','-T','--no-deps','agent',*args,required=False)

        def http_status(url):
            result = run_agent('curl','-sS','--connect-timeout','3','--max-time','15','-o','/dev/null','-w','%{http_code}',url)
            return result.stdout.strip(), result.returncode

        policy = {'allow':['api.openai.com','auth.openai.com','chatgpt.com'], 'deny':[], 'ports':[80,443], 'private_allow':[]}
        write_policy(policy)
        try:
            compose('up','-d','--wait','gateway')
            baseline = run_agent('python3','/opt/sandbox/verify.py')
            print(baseline.stdout, end='', flush=True)
            check('Full baseline firewall verification',baseline.returncode == 0,baseline.stderr[-300:] if baseline.returncode else '')

            for family in ('iptables-save','ip6tables-save'):
                rules = compose('exec','-T','gateway',family).stdout
                check(family + ' has default-deny OUTPUT and proxy owner exception',':OUTPUT DROP' in rules and '--uid-owner 10001 -j ACCEPT' in rules and '-A OUTPUT -j REJECT' in rules)

            policy = dict(policy, allow=['.openai.com'])
            apply(policy)
            status, code = http_status('https://api.openai.com/v1/models')
            check('Suffix rule allows subdomain',code == 0 and status in ('401','200'),status)

            policy = dict(policy, deny=['api.openai.com'])
            apply(policy)
            status, code = http_status('http://api.openai.com/')
            check('Exact deny overrides suffix allow',code == 0 and status == '403',status)

            policy = dict(policy, allow=[], deny=[])
            apply(policy)
            status, code = http_status('http://api.openai.com/')
            check('Empty allowlist denies formerly allowed destination',code == 0 and status == '403',status)

            policy = dict(policy, allow=['private-test.example'], ports=[80,443,8123])
            apply(policy)
            status, code = http_status('http://private-test.example:8123/')
            check('Allowed hostname resolving to loopback remains denied',code == 0 and status == '403',status)

            policy = dict(policy, private_allow=['127.0.0.1'])
            apply(policy)
            fixture = '''import http.server
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.com/")
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"fixture-ok")
http.server.HTTPServer(("127.0.0.1",8123),Handler).serve_forever()
'''
            fixture_file = source / 'workspace/fixture.py'
            fixture_file.write_text(fixture)
            # The fixture is inside the firewall and reachable only through an
            # explicit private-host/port/IP exception.
            fixture_container = project + '-fixture'
            compose('run','-d','--no-deps','--name',fixture_container,'agent','python3','/workspace/fixture.py')
            status, code = http_status('http://private-test.example:8123/')
            check('Explicit host + port + private IP permits local fixture',code == 0 and status == '200',status)
            redirected = run_agent('curl','-sS','-L','--max-time','15','-o','/dev/null','-w','%{http_code}','http://private-test.example:8123/redirect')
            check('Redirect to unlisted destination is denied',redirected.returncode == 0 and redirected.stdout.strip() == '403',redirected.stdout.strip())

            # An agent already holding the namespace must not get direct egress
            # when the proxy is stopped or cannot be reached.
            compose('stop','gateway')
            stopped = subprocess.run(docker_command() + ['exec',fixture_container,'curl','-sS','--noproxy','*','--connect-timeout','3','--max-time','5','https://1.1.1.1/'],capture_output=True,text=True,timeout=15)
            check('Proxy shutdown leaves direct egress blocked',stopped.returncode != 0)
            proxied = subprocess.run(docker_command() + ['exec',fixture_container,'curl','-sS','--connect-timeout','3','--max-time','5','https://api.openai.com/'],capture_output=True,text=True,timeout=15)
            check('Proxy shutdown closes proxy access',proxied.returncode != 0)
        except Exception as error:
            check('Runtime tests complete',False,str(error))
            logs = compose('logs','--tail','50','gateway',required=False)
            print(logs.stdout + logs.stderr,flush=True)
        finally:
            compose('down','--volumes','--remove-orphans',required=False)
    print(str(len(failures)) + ' failed runtime checks.',flush=True)
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
