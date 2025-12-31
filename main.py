import json, requests, base64, yaml, urllib.parse, warnings
from datetime import datetime, timedelta

warnings.filterwarnings("ignore")

# 订阅源列表
URL_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ip/singbox/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json"
]

def get_node_info(item):
    try:
        if not isinstance(item, dict): return None
        raw_server = item.get('server') or item.get('add') or item.get('address')
        if not raw_server or str(raw_server).startswith('127.'): return None
        
        server_str = str(raw_server).strip()
        server, port = "", ""
        if ']:' in server_str: 
            server, port = server_str.split(']:')[0] + ']', server_str.split(']:')[1]
        elif server_str.startswith('[') and ']' in server_str:
            server, port = server_str, (item.get('port') or item.get('server_port'))
        elif server_str.count(':') == 1:
            server, port = server_str.split(':')
        else:
            server, port = server_str, (item.get('port') or item.get('server_port') or item.get('port_num'))

        if port: port = str(port).split(',')[0].split('-')[0].split('/')[0].strip()
        if not server or not port: return None

        secret = item.get('auth') or item.get('auth_str') or item.get('auth-str') or \
                 item.get('password') or item.get('uuid') or item.get('id')
        if not secret: return None

        p_type = str(item.get('type', '')).lower()
        if 'auth' in item or 'hy2' in p_type or 'hysteria2' in p_type: p_type = 'hysteria2'
        elif 'uuid' in item or 'vless' in p_type: p_type = 'vless'
        else: p_type = 'hysteria2' if 'auth' in item else 'vless'

        tls_obj = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
        sni = item.get('servername') or item.get('sni') or tls_obj.get('server_name') or tls_obj.get('sni') or ""
        reality_obj = item.get('reality-opts') or tls_obj.get('reality') or item.get('reality') or {}
        if not isinstance(reality_obj, dict): reality_obj = {}
        pbk = reality_obj.get('public-key') or reality_obj.get('public_key') or item.get('public-key') or ""
        sid = reality_obj.get('short-id') or reality_obj.get('short_id') or item.get('short-id') or ""
        
        return {
            "server": server, "port": int(port), "type": p_type, 
            "sni": sni, "secret": secret, "pbk": pbk, "sid": sid, "raw_server": server_str
        }
    except: return None

def main():
    raw_nodes_data = []
    headers = {'User-Agent': 'Mozilla/5.0'}
    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=12, verify=False)
            if r.status_code != 200: continue
            content = r.text.strip()
            data = json.loads(content) if (content.startswith('{') or content.startswith('[')) else yaml.safe_load(content)
            
            def extract_dicts(obj):
                res = []
                if isinstance(obj, dict):
                    res.append(obj); [res.extend(extract_dicts(v)) for v in obj.values()]
                elif isinstance(obj, list):
                    [res.extend(extract_dicts(i)) for i in obj]
                return res
            
            for d in extract_dicts(data):
                node = get_node_info(d)
                if node: raw_nodes_data.append(node)
        except: continue

    unique_configs = []
    seen_configs = set()
    for n in raw_nodes_data:
        config_key = (n['type'], n['raw_server'], n['port'], n['secret'], n['sni'], n['pbk'])
        if config_key not in seen_configs:
            unique_configs.append(n); seen_configs.add(config_key)

    clash_proxies = []
    uri_links = []
    beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%H%M")
    
    for index, n in enumerate(unique_configs, start=1):
        tag = n['server'].split('.')[-1].replace(']', '') if '.' in n['server'] else "v6"
        node_name = f"{index:02d}_{n['type'].upper()}_{tag}_{beijing_time}"
        
        name_enc = urllib.parse.quote(node_name)
        srv_uri = f"[{n['server']}]" if (':' in n['server'] and not n['server'].startswith('[')) else n['server']
        srv_clash = n['server'].replace('[','').replace(']','')
        
        if n["type"] == "hysteria2":
            uri_links.append(f"hysteria2://{n['secret']}@{srv_uri}:{n['port']}?insecure=1&allowInsecure=1#{name_enc}")
            clash_proxies.append({"name": node_name, "type": "hysteria2", "server": srv_clash, "port": n["port"], "password": n["secret"], "tls": True, "sni": n["sni"], "skip-cert-verify": True})
        elif n["type"] == "vless" and n['pbk']:
            uri_links.append(f"vless://{n['secret']}@{srv_uri}:{n['port']}?encryption=none&security=reality&type=tcp&pbk={n['pbk']}&sid={n['sid']}#{name_enc}")
            clash_proxies.append({"name": node_name, "type": "vless", "server": srv_clash, "port": n["port"], "uuid": n["secret"], "tls": True, "udp": True, "servername": n["sni"], "network": "tcp", "reality-opts": {"public-key": n["pbk"], "short-id": n["sid"]}, "client-fingerprint": "chrome"})

    # --- 核心：Clash 分流规则配置 ---
    p_names = [p["name"] for p in clash_proxies]
    
    clash_config = {
        "port": 7890, "socks-port": 7891, "allow-lan": True, "mode": "rule", "log-level": "info",
        "dns": {"enable": True, "ipv6": False, "enhanced-mode": "fake-ip", "nameserver": ["223.5.5.5", "119.29.29.29"], "fallback": ["8.8.8.8", "1.1.1.1"]},
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + p_names + ["DIRECT"]},
            {"name": "⚡ 自动选择", "type": "url-test", "proxies": p_names, "url": "http://www.gstatic.com/generate_204", "interval": 300},
            {"name": "🌍 全球直连", "type": "select", "proxies": ["DIRECT", "🚀 节点选择"]},
            {"name": "🛑 广告拦截", "type": "select", "proxies": ["REJECT", "DIRECT", "🚀 节点选择"]},
            {"name": "🍎 苹果服务", "type": "select", "proxies": ["DIRECT", "🚀 节点选择", "⚡ 自动选择"]},
            {"name": "Ⓜ️ 微软服务", "type": "select", "proxies": ["DIRECT", "🚀 节点选择", "⚡ 自动选择"]},
            {"name": "🐟 漏网之鱼", "type": "select", "proxies": ["🚀 节点选择", "DIRECT", "⚡ 自动选择"]}
        ],
        "rule-providers": {
            "reject": {"type": "http", "behavior": "domain", "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt", "path": "./ruleset/reject.yaml", "interval": 86400},
            "proxy": {"type": "http", "behavior": "domain", "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt", "path": "./ruleset/proxy.yaml", "interval": 86400},
            "direct": {"type": "http", "behavior": "domain", "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt", "path": "./ruleset/direct.yaml", "interval": 86400},
            "private": {"type": "http", "behavior": "domain", "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt", "path": "./ruleset/private.yaml", "interval": 86400},
            "apple": {"type": "http", "behavior": "domain", "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt", "path": "./ruleset/apple.yaml", "interval": 86400},
            "microsoft": {"type": "http", "behavior": "domain", "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/microsoft.yaml", "path": "./ruleset/microsoft.yaml", "interval": 86400},
            "gfw": {"type": "http", "behavior": "domain", "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt", "path": "./ruleset/gfw.yaml", "interval": 86400}
        },
        "rules": [
            "RULE-SET,private,DIRECT",
            "RULE-SET,reject,🛑 广告拦截",
            "RULE-SET,apple,🍎 苹果服务",
            "RULE-SET,microsoft,Ⓜ️ 微软服务",
            "RULE-SET,proxy,🚀 节点选择",
            "RULE-SET,gfw,🚀 节点选择",
            "GEOIP,LAN,DIRECT",
            "GEOIP,CN,🌍 全球直连",
            "MATCH,🐟 漏网之鱼"
        ]
    }

    # 写入文件
    with open("node.txt", "w", encoding="utf-8") as f: f.write("\n".join(uri_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(uri_links).encode()).decode())
    with open("clash.yaml", "w", encoding="utf-8") as f: yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    
    print(f"✅ 成功! 节点数: {len(clash_proxies)}，规则集已加载")

if __name__ == "__main__":
    main()
