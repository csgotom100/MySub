import json, requests, base64, yaml, urllib.parse, warnings
from datetime import datetime, timedelta

warnings.filterwarnings("ignore")

# 20个精准数据源
URL_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/4/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/5/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/6/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ip/singbox/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/4/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/5/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/6/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ip/singbox/2/config.json"
]

beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%m%d-%H%M")

def get_node_info(item):
    try:
        if not isinstance(item, dict): return None
        server = item.get('server') or item.get('add') or item.get('address')
        port_raw = item.get('port') or item.get('server_port') or item.get('port_num')
        if not server or not port_raw: return None

        port = str(port_raw).split(',')[0].split('-')[0].strip()
        p_type = str(item.get('type', '')).lower()
        
        # 严格从 JSON 提取凭据，不猜测
        if p_type in ['hy2', 'hysteria2'] or 'auth_str' in item or 'auth-str' in item:
            p_type = 'hysteria2'
            secret = item.get('auth_str') or item.get('auth-str') or item.get('password') or item.get('auth')
        else:
            secret = item.get('uuid') or item.get('id') or item.get('password')

        if not secret: return None

        tls_obj = item.get('tls', {})
        if not isinstance(tls_obj, dict): tls_obj = {}
        sni = item.get('servername') or item.get('sni') or tls_obj.get('server_name') or ""
        
        addr_tag = str(server).split('.')[-1].replace(']', '')
        name = f"{p_type.upper()}_{addr_tag}_{beijing_time}"
        
        return {
            "name": name, "server": server, "port": int(port), "type": p_type,
            "sni": sni, "secret": secret, "raw": item
        }
    except:
        return None

def main():
    nodes_list = []
    headers = {'User-Agent': 'Mozilla/5.0'}

    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=12, verify=False)
            if r.status_code != 200: continue
            try:
                data = json.loads(r.text)
            except:
                data = yaml.safe_load(r.text)
            
            def find_proxies(obj):
                if isinstance(obj, dict):
                    if any(k in obj for k in ['server', 'add', 'address']):
                        node = get_node_info(obj)
                        if node: nodes_list.append(node)
                    for v in obj.values(): find_proxies(v)
                elif isinstance(obj, list):
                    for i in obj: find_proxies(i)
            find_proxies(data)
        except:
            continue

    if not nodes_list: return

    unique_nodes = []
    seen = set()
    for n in nodes_list:
        key = f"{n['server']}:{n['port']}"
        if key not in seen:
            unique_nodes.append(n)
            seen.add(key)

    uri_links = []
    clash_proxies = []

    for n in unique_nodes:
        name_enc = urllib.parse.quote(n["name"])
        srv = f"[{n['server']}]" if ":" in str(n['server']) and "[" not in str(n['server']) else n['server']
        
        if n["type"] == "hysteria2":
            sni_part = f"&sni={n['sni']}" if n['sni'] else ""
            uri_links.append(f"hysteria2://{n['secret']}@{srv}:{n['port']}?insecure=1&allowInsecure=1{sni_part}#{name_enc}")
            cp = {"name": n["name"], "type": "hysteria2", "server": n["server"], "port": n["port"], "password": n["secret"], "tls": True, "skip-cert-verify": True}
            if n['sni']: cp["sni"] = n['sni']
            clash_proxies.append(cp)
        
        elif n["type"] == "vless":
            raw = n["raw"]
            tls_obj = raw.get('tls', {}) if isinstance(raw.get('tls'), dict) else {}
            ro = raw.get('reality-opts') or tls_obj.get('reality', {})
            pbk = ro.get('public-key') or ro.get('public_key', '')
            sid = ro.get('short-id') or ro.get('short_id', '')
            sni_part = f"&sni={n['sni']}" if n['sni'] else ""
            uri_links.append(f"vless://{n['secret']}@{srv}:{n['port']}?encryption=none&security=reality&pbk={pbk}&sid={sid}&type=tcp{sni_part}#{name_enc}")
            clash_proxies.append({"name": n["name"], "type": "vless", "server": n["server"], "port": n["port"], "uuid": n["secret"], "network": "tcp", "tls": True, "udp": True, "sni": n["sni"], "skip-cert-verify": True})

        elif n["type"] == "tuic":
            uri_links.append(f"tuic://{n['secret']}%3A{n['secret']}@{srv}:{n['port']}?sni={n['sni']}&alpn=h3&congestion_control=cubic#{name_enc}")
            clash_proxies.append({"name": n["name"], "type": "tuic", "server": n["server"], "port": n["port"], "uuid": n["secret"], "password": n["secret"], "alpn": ["h3"], "tls": True, "sni": n["sni"], "skip-cert-verify": True, "udp": True})

    with open("node.txt", "w", encoding="utf-8") as f: f.write("\n".join(uri_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(uri_links).encode()).decode())
    with open("clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)

    print(f"Done! Total: {len(clash_proxies)}")

if __name__ == "__main__":
    main()
