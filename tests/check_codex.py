"""Inspect the installed Codex configuration without making a model request."""
import json
import selectors
import subprocess
import tempfile
import time


def rpc(process, number, method, params):
    process.stdin.write(json.dumps({'jsonrpc':'2.0','id':number,'method':method,'params':params}) + '\n')
    process.stdin.flush()
    deadline = time.monotonic() + 20
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(timeout=max(0,deadline-time.monotonic())):
                break
            line = process.stdout.readline()
            if not line:
                raise RuntimeError('Service exited before replying to ' + method)
            response = json.loads(line)
            if response.get('id') == number:
                if 'error' in response:
                    raise RuntimeError(str(response['error']))
                return response['result']
    raise RuntimeError('Timed out waiting for ' + method)


def check_codex():
    with tempfile.TemporaryFile(mode='w+') as errors:
        process = subprocess.Popen(['codex','app-server','--strict-config'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors,text=True)
        try:
            rpc(process,1,'initialize',{'clientInfo':{'name':'egress-verify','version':'1.0'},'capabilities':{'experimentalApi':True}})
            config = rpc(process,2,'config/read',{'includeLayers':False})['config']
            assert config['approval_policy'] == 'never', 'Approvals are not configured for auto-run.'
            assert config['sandbox_mode'] == 'danger-full-access', 'Container filesystem access is restricted.'
            assert config['web_search'] == 'disabled', 'Hosted search is enabled.'
            features = config['features']
            for feature in ('apps','plugins','browser_use','browser_use_external','computer_use','in_app_browser','image_generation','hooks','multi_agent','network_proxy'):
                assert features.get(feature) is False, 'Unexpected enabled capability: ' + feature
            print('PASS Codex strict config: unattended execution and hosted capabilities disabled.',flush=True)
        finally:
            process.terminate()
            process.communicate(timeout=5)


def check_browser_mcp():
    with tempfile.TemporaryFile(mode='w+') as errors:
        process = subprocess.Popen(['playwright-mcp','--headless','--browser','chromium','--executable-path','/usr/bin/chromium','--proxy-server','http://127.0.0.1:3128','--no-sandbox'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors,text=True)
        try:
            rpc(process,1,'initialize',{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'egress-verify','version':'1.0'}})
            process.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'}) + '\n')
            process.stdin.flush()
            names = {tool['name'] for tool in rpc(process,2,'tools/list',{})['tools']}
            expected = {'browser_navigate','browser_snapshot','browser_click','browser_type','browser_wait_for','browser_take_screenshot','browser_close','browser_tabs'}
            assert expected <= names, 'Example allowlist contains unknown browser tool names.'
            result = rpc(process,3,'tools/call',{'name':'browser_navigate','arguments':{'url':'https://api.openai.com/v1/models'}})
            contents = json.dumps(result).lower()
            assert not result.get('isError') and 'http status: 401' in contents, 'MCP browser could not reach allowed OpenAI endpoint: ' + contents[:1000]
            result = rpc(process,4,'tools/call',{'name':'browser_navigate','arguments':{'url':'https://example.com/'}})
            assert 'ERR_TUNNEL_CONNECTION_FAILED' in json.dumps(result), 'MCP browser reached an unlisted site.'
            print('PASS Playwright MCP: example tool names, allowed navigation, denied navigation.',flush=True)
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()


if __name__ == '__main__':
    check_codex()
