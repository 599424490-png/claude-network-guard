"""Install a private Mihomo ingress while keeping normal rule-mode routing."""
import argparse
import copy
import datetime
import http.client
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import shutil
import yaml

ROOT = Path(__file__).resolve().parent


def guard_configuration(original, programs, route_name):
    data = copy.deepcopy(original)
    if not route_name or any(c in route_name for c in ',\r\n') or not programs or any(',' in path or '\n' in path or '\r' in path for path in programs):
        raise ValueError('Invalid protected executable paths')
    listeners = data.get('listeners') or []
    for item in listeners:
        if str(item.get('port')) == '17897' and item.get('name') != 'ClaudeNetworkGuard':
            raise ValueError('Port 17897 belongs to another configured listener')
    data['listeners'] = [item for item in listeners if item.get('name') != 'ClaudeNetworkGuard'] + [
        {'name': 'ClaudeNetworkGuard', 'type': 'mixed', 'listen': '127.0.0.1',
         'port': 17897, 'proxy': route_name, 'udp': False}]
    prefix = ['IN-PORT,17897,' + route_name] + ['PROCESS-PATH,' + path + ',' + route_name for path in programs]
    data['rules'] = prefix + [rule for rule in data.get('rules', []) if rule not in prefix]
    return data


def reload_config(controller, path):
    raw = open(controller.pipe, 'r+b', buffering=0)
    reader = io.BufferedReader(raw)
    response = None
    class Pipe:
        def makefile(self, *_):
            return reader
    try:
        # Verge's service can restrict filesystem reload paths. Send the
        # existing configuration only over the authenticated local pipe.
        body = json.dumps({'payload': path.read_text(encoding='utf-8-sig')}).encode()
        headers = ('PUT /configs?force=true HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n'
                   'Content-Type: application/json\r\nContent-Length: ' + str(len(body)) + '\r\n')
        if controller.secret:
            headers += 'Authorization: Bearer ' + controller.secret + '\r\n'
        payload = (headers + '\r\n').encode() + body
        offset = 0
        while offset < len(payload):
            written = raw.write(payload[offset:])
            if not written:
                raise OSError('Pipe write failed')
            offset += written
        response = http.client.HTTPResponse(Pipe())
        response.begin()
        if response.status != 204:
            error = response.read(4096).decode('utf-8', errors='replace').lower()
            flags = [word for word in ('path', 'allowed', 'payload', 'parse', 'rule', 'proxy', 'listener', 'permission', 'port') if word in error]
            raise RuntimeError('Mihomo configuration reload rejected: HTTP ' + str(response.status) + '; categories=' + ','.join(flags))
    finally:
        if response:
            response.close()
        reader.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--backup-dir', type=Path, default=ROOT / 'private-route-backups')
    args = parser.parse_args()
    loader = importlib.machinery.SourceFileLoader('guard_route_installer', str(ROOT / 'claude-guard.pyw'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    guard = importlib.util.module_from_spec(spec)
    loader.exec_module(guard)
    config_path = ROOT / 'guard-config.json'
    config = guard.load_config()
    guard.check_firewall()
    controller = guard.Controller(config)
    live = controller.get('/configs')
    if live.get('mode') not in {'rule', 'global'} or live.get('mixed-port') != 7897:
        raise RuntimeError('Use rule/global mode with mixed port 7897 before setup')
    before_proxies = controller.get('/proxies')['proxies']
    global_chain = guard.resolve_proxy_chain(before_proxies)
    route_name = config.get('rule_proxy_name') or global_chain[0][1]
    before_chain = guard.resolve_proxy_chain(before_proxies, route_name)
    runtime_path = Path(config['clash_config'])
    profiles_root = runtime_path.parent
    profiles = yaml.safe_load((profiles_root / 'profiles.yaml').read_text(encoding='utf-8'))
    active = next(item for item in profiles['items'] if item['uid'] == profiles['current'])
    if active.get('type') != 'local' or Path(active['file']).name != active['file']:
        raise RuntimeError('Automatic setup currently requires a local Clash Verge profile')
    source_path = profiles_root / 'profiles' / active['file']
    programs = json.loads((ROOT / 'firewall-manifest.json').read_text(encoding='utf-8-sig'))['programs']
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    backup = args.backup_dir / stamp
    backup.mkdir(parents=True, exist_ok=False)
    originals = {source_path: source_path.read_bytes(), runtime_path: runtime_path.read_bytes(),
                 config_path: config_path.read_bytes()}
    for index, (path, content) in enumerate(originals.items()):
        (backup / (str(index) + '-' + path.name)).write_bytes(content)
    try:
        for path in (source_path, runtime_path):
            data = yaml.safe_load(originals[path].decode('utf-8-sig'))
            data = guard_configuration(data, programs, route_name)
            if path == runtime_path:
                data['mode'] = live['mode']
            temporary = path.with_suffix(path.suffix + '.guard-tmp')
            temporary.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding='utf-8')
            temporary.replace(path)
        reload_config(controller, runtime_path)
        new_config = json.loads(originals[config_path].decode('utf-8-sig'))
        new_config['proxy_url'] = 'http://127.0.0.1:17897'
        new_config['rule_proxy_name'] = route_name
        config_path.write_text(json.dumps(new_config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        config = guard.load_config()
        controller = guard.Controller(config)
        after_live = controller.get('/configs')
        chain = guard.validate_live_route(config, controller, after_live, controller.get('/proxies')['proxies'])
        if chain != before_chain:
            raise RuntimeError('Selected proxy changed during setup')
    except Exception:
        for path, content in originals.items():
            path.write_bytes(content)
        try:
            reload_config(controller, runtime_path)
        except Exception:
            pass
        raise
    print(json.dumps({'ok': True, 'mode': after_live['mode'], 'claude_proxy': config['proxy_url'],
                      'guard_rules': 1 + len(programs), 'rest_of_rules_preserved': True}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Errors can contain configuration credentials: report only the class.
        print(json.dumps({'ok': False, 'error_category': type(exc).__name__}))
        raise SystemExit(1)
