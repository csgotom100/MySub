import json, requests, base64, yaml, urllib.parse, warnings
from datetime import datetime, timedelta

warnings.filterwarnings("ignore")

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
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json"
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
        
        # --- 仿照成功案例的密码提取策略 ---
        # 优先寻找 auth_str (dongtaiwang.com 常见的存放处)
        secret = item.get('auth_str') or item.get('auth-str') or item.get('password') or item.get('auth') or item.get('uuid')
        
        if not secret: return None

        # 识别协议
        if 'auth' in str(item) or 'hy2' in p_type or 'hysteria2' in p_type:
            p_type = 'hysteria2'
        elif 'uuid' in item:
            p_type = 'vless'

        # SNI 必须保持，如果没有则强制使用 microsoft
        tls_obj = item.get('tls', {})
        if not isinstance(tls_obj, dict): tls_obj = {}
        sni = item.get('servername') or item.get('sni') or tls_obj.get('server_name') or "www.microsoft.com"
        
        addr_tag = str(server).split('.')[-1].replace(']', '')
        name = f"{p_type.upper()}_{addr_tag}_{beijing_time}"
        
        return {
            "name": name, "server": server, "port": int(port), "type": p_type,
            "sni": sni, "secret": secret, "raw": item
        }
    except: return None

def main():
    nodes_list = []
    headers = {'User-Agent': 'Mozilla/5.0'}

    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=10, verify=False)
            if r.status_code != 200: continue
            try:
                data = json.loads(r.text)
            except:
                data = yaml.safe_load(r.text)
            
            def find_proxies(obj):
                if isinstance(obj, dict):
                    if any(k in obj for k in ['server', 'add']):
                        node = get_node_info(obj)
                        if node: nodes_list.append(node)
                    for v in obj.values(): find_proxies(v)
                elif isinstance(obj, list):
                    for i in obj: find_proxies(i)
            find_proxies(data)
        except: continue

    unique_nodes = []
    seen = set()
    for n in nodes_list:
        key = f"{n['server']}:{n['port']}"
        if key not in seen:
            unique_nodes.append(n)
            seen.add(key)

    links = []
    clash_proxies = []

    for n in unique_nodes:
        name_enc = urllib.parse.quote(n["name"])
        srv = f"[{n['server']}]" if ":" in str(n['server']) and "[" not in str(n['server']) else n['server']
        
        if n["type"] == "hysteria2":
            # 这里的参数完全对齐你提供的成功样本
            links.append(f"hysteria2://{n['secret']}@{srv}:{n['port']}?sni={n['sni']}&insecure=1&allowInsecure=1#{name_enc}")
            clash_proxies.append({
                "name": n["name"], "type": "hysteria2", "server": n["server"], "port": n["port"],
                "password": n["secret"], "tls": True, "sni": n["sni"], "skip-cert-verify": True
            })
        
        elif n["type"] == "vless":
            # 保持原有 VLESS 逻辑
            raw = n["raw"]
            tls_obj = raw.get('tls', {}) if isinstance(raw.get('tls'), dict) else {}
            ro = raw.get('reality-opts') or tls_obj.get('reality', {})
            pbk = ro.get('public-key') or ro.get('public_key', '')
            sid = ro.get('short-id') or ro.get('short_id', '')
            links.append(f"vless://{n['secret']}@{srv}:{n['port']}?encryption=none&security=reality&sni={n['sni']}&pbk={pbk}&sid={sid}&type=tcp&headerType=none#{name_enc}")
            clash_proxies.append({"name": n["name"], "type": "vless", "server": n["server"], "port": n["port"], "uuid": n["secret"], "network": "tcp", "tls": True, "udp": True, "sni": n["sni"], "skip-cert-verify": True})

    # 写入文件
    with open("node.txt", "w", encoding="utf-8") as f: f.write("\n".join(links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(links).encode()).decode())
    with open("clash.yaml", "w", encoding="utf-8") as f: yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True)

if __name__ == "__main__":
    main()
