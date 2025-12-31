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
        
        # 1. 提取原始地址字符串
        raw_server = item.get('server') or item.get('add') or item.get('address')
        if not raw_server or str(raw_server).startswith('127.'): return None
        
        server_str = str(raw_server).strip()
        server = ""
        port = ""

        # --- 增强型地址解析：处理 IPv6 和 端口跳跃 ---
        if ']:' in server_str: # [2001:...]:27921
            server = server_str.split(']:')[0] + ']'
            port = server_str.split(']:')[1]
        elif server_str.startswith('[') and ']' in server_str: # [2001:...]
            server = server_str
            port = item.get('port') or item.get('server_port')
        elif server_str.count(':') == 1: # 1.2.3.4:27921
            server, port = server_str.split(':')
        else: # 纯地址，端口在独立字段
            server = server_str
            port = item.get('port') or item.get('server_port') or item.get('port_num')

        # 清洗端口：只取第一位
        if port:
            port = str(port).split(',')[0].split('-')[0].split('/')[0].strip()
        
        if not server or not port: return None

        # --- 凭据提取：只要有凭据就保留 ---
        secret = item.get('auth') or item.get('auth_str') or item.get('auth-str') or \
                 item.get('password') or item.get('uuid') or item.get('id')
        if not secret: return None

        # --- 协议判定 ---
        p_type = str(item.get('type', '')).lower()
        if 'auth' in item or 'hy2' in p_type or 'hysteria2' in p_type:
            p_type = 'hysteria2'
        elif 'uuid' in item or 'vless' in p_type:
            p_type = 'vless'
        elif 'tuic' in p_type:
            p_type = 'tuic'
        else:
            # 兜底：如果是 Hysteria2 专用源里的，默认为 HY2
            p_type = 'hysteria2'

        # --- SNI 提取 ---
        tls_obj = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
        sni = item.get('servername') or item.get('sni') or \
              tls_obj.get('sni') or tls_obj.get('server_name') or ""
        
        # 备注
        tag = server.split('.')[-1].replace(']', '') if '.' in server else "v6"
        name = f"{p_type.upper()}_{tag}_{port}_{beijing_time}"
        
        return {
            "name": name, "server": server, "port": int(port), 
            "type": p_type, "sni": sni, "secret": secret, "raw_server": server_str
        }
    except:
        return None

def main():
    raw_nodes = []
    headers = {'User-Agent': 'Mozilla/5.0'}

    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=15, verify=False)
            if r.status_code != 200: continue
            data = json.loads(r.text) if url.endswith('.json') else yaml.safe_load(r.text)
            
            # 使用列表来平铺所有发现的字典，避免递归提前结束
            def extract_dicts(obj):
                res = []
                if isinstance(obj, dict):
                    res.append(obj)
                    for v in obj.values(): res.extend(extract_dicts(v))
                elif isinstance(obj, list):
                    for i in obj: res.extend(extract_dicts(i))
                return res
            
            all_dicts = extract_dicts(data)
            for d in all_dicts:
                node = get_node_info(d)
                if node: raw_nodes.append(node)
        except: continue

    # 去重：基于 (服务器+端口+密码)
    unique_nodes = []
    seen = set()
    for n in raw_nodes:
        key = f"{n['raw_server']}_{n['port']}_{n['secret']}"
        if key not in seen:
            unique_nodes.append(n)
            seen.add(key)

    uri_links = []
    clash_proxies = []

    for n in unique_nodes:
        name_enc = urllib.parse.quote(n["name"])
        # URI 格式的 IPv6 必须带括号
        srv_uri = n['server']
        if ':' in srv_uri and not srv_uri.startswith('['): srv_uri = f"[{srv_uri}]"
        # Clash 格式的 IPv6 不能带括号
        srv_clash = n['server'].replace('[','').replace(']','')

        if n["type"] == "hysteria2":
            sni_p = f"&sni={n['sni']}" if n['sni'] else ""
            uri_links.append(f"hysteria2://{n['secret']}@{srv_uri}:{n['port']}?insecure=1&allowInsecure=1{sni_p}#{name_enc}")
            clash_proxies.append({"name": n["name"], "type": "hysteria2", "server": srv_clash, "port": n["port"], "password": n["secret"], "tls": True, "sni": n["sni"], "skip-cert-verify": True})
        elif n["type"] == "vless":
            # 简化的 VLESS，重点在于把节点抓出来
            uri_links.append(f"vless://{n['secret']}@{srv_uri}:{n['port']}?encryption=none&security=reality&type=tcp#{name_enc}")
            clash_proxies.append({"name": n["name"], "type": "vless", "server": srv_clash, "port": n["port"], "uuid": n["secret"], "tls": True, "skip-cert-verify": True})

    with open("node.txt", "w", encoding="utf-8") as f: f.write("\n".join(uri_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(uri_links).encode()).decode())
    with open("clash.yaml", "w", encoding="utf-8") as f: yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 完成! 本次成功提取节点总数: {len(unique_nodes)}")

if __name__ == "__main__":
    main()
