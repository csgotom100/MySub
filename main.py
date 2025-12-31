import json, requests, base64, yaml, urllib.parse, warnings
from datetime import datetime, timedelta

warnings.filterwarnings("ignore")

URL_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json"
]

beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%m%d-%H%M")

def get_node_info(item):
    try:
        if not isinstance(item, dict): return None
        
        raw_server = item.get('server') or item.get('add') or item.get('address')
        if not raw_server: return None
        
        # 1. 提取 IP 和 端口
        if ':' in str(raw_server):
            parts = str(raw_server).split(':')
            server = parts[0]
            port_part = parts[1].split(',')[0].split('-')[0].strip()
        else:
            server = raw_server
            port_part = item.get('port') or item.get('server_port') or item.get('port_num')
        
        if not server or not port_part: return None

        # 2. 凭据提取 (auth 优先)
        secret = item.get('auth') or item.get('auth_str') or item.get('auth-str') or \
                 item.get('password') or item.get('uuid') or item.get('id')
        if not secret: return None

        # 3. 协议判定 (放宽判定条件，防止漏掉)
        p_type = str(item.get('type', '')).lower()
        if 'auth' in item or 'hy2' in p_type or 'hysteria2' in p_type:
            p_type = 'hysteria2'
        elif 'uuid' in item or 'id' in item or 'vless' in p_type:
            p_type = 'vless'
        elif 'tuic' in p_type:
            p_type = 'tuic'
        else:
            # 如果没有明确 type 但有 auth，默认给 hy2
            if 'auth' in item: p_type = 'hysteria2'
            else: return None

        # 4. SNI 提取
        tls_obj = item.get('tls', {})
        if not isinstance(tls_obj, dict): tls_obj = {}
        sni = item.get('servername') or item.get('sni') or \
              tls_obj.get('sni') or tls_obj.get('server_name') or ""
        
        # 备注加上端口末尾，防止重名
        addr_tag = f"{server.split('.')[-1]}_{port_part}"
        name = f"{p_type.upper()}_{addr_tag}_{beijing_time}"
        
        return {
            "name": name, "server": server, "port": int(port_part), 
            "type": p_type, "sni": sni, "secret": secret, "raw_server_str": str(raw_server), "raw": item
        }
    except:
        return None

def main():
    all_extracted_nodes = []
    headers = {'User-Agent': 'Mozilla/5.0'}

    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=15, verify=False)
            if r.status_code != 200: continue
            
            try:
                data = json.loads(r.text)
            except:
                data = yaml.safe_load(r.text)
            
            def find_nodes_recursive(obj):
                if isinstance(obj, dict):
                    if any(k in obj for k in ['server', 'add', 'address']):
                        node = get_node_info(obj)
                        if node: all_extracted_nodes.append(node)
                    for v in obj.values(): find_nodes_recursive(v)
                elif isinstance(obj, list):
                    for i in obj: find_nodes_recursive(i)
            
            find_nodes_recursive(data)
        except: continue

    # --- 改进的去重逻辑 ---
    unique_nodes = []
    seen_identifiers = set()
    for n in all_extracted_nodes:
        # 使用 协议 + 原始服务器地址字符串 作为唯一标识
        # 这样即使 IP 相同但端口跳跃范围不同的节点也会被保留
        identifier = f"{n['type']}_{n['raw_server_str']}"
        if identifier not in seen_identifiers:
            unique_nodes.append(n)
            seen_identifiers.add(identifier)

    uri_links = []
    clash_proxies = []

    for n in unique_nodes:
        name_enc = urllib.parse.quote(n["name"])
        srv_display = f"[{n['server']}]" if ":" in str(n['server']) and "[" not in str(n['server']) else n['server']
        
        if n["type"] == "hysteria2":
            sni_part = f"&sni={n['sni']}" if n['sni'] else ""
            uri_links.append(f"hysteria2://{n['secret']}@{srv_display}:{n['port']}?insecure=1&allowInsecure=1{sni_part}#{name_enc}")
            clash_proxies.append({
                "name": n["name"], "type": "hysteria2", "server": n["server"], "port": n["port"],
                "password": n["secret"], "tls": True, "sni": n["sni"], "skip-cert-verify": True
            })
            
        elif n["type"] == "vless":
            raw = n["raw"]
            tls_info = raw.get('tls', {}) if isinstance(raw.get('tls'), dict) else {}
            ropts = raw.get('reality-opts') or tls_info.get('reality', {})
            pbk = ropts.get('public-key') or ropts.get('public_key', '')
            sid = ropts.get('short-id') or ropts.get('short_id', '')
            sni_part = f"&sni={n['sni']}" if n['sni'] else ""
            uri_links.append(f"vless://{n['secret']}@{srv_display}:{n['port']}?encryption=none&security=reality&pbk={pbk}&sid={sid}&type=tcp{sni_part}#{name_enc}")
            clash_proxies.append({
                "name": n["name"], "type": "vless", "server": n["server"], "port": n["port"],
                "uuid": n["secret"], "network": "tcp", "tls": True, "udp": True, "sni": n["sni"], "skip-cert-verify": True
            })

    with open("node.txt", "w", encoding="utf-8") as f: f.write("\n".join(uri_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(uri_links).encode()).decode())
    
    with open("clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 完成! 提取并保留了 {len(unique_nodes)} 个节点")

if __name__ == "__main__":
    main()
