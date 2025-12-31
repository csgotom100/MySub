import json
import requests
import base64
import yaml

URL_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/4/config.json",
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

def parse_to_link(item):
    p_type = str(item.get('type', '')).lower()
    # 兼容多种 server 字段
    server = item.get('server') or item.get('add')
    port = item.get('port') or item.get('port_num')
    
    if not server or not port: return None

    # 处理 IPv6 地址
    if ":" in str(server) and "[" not in str(server):
        server_display = f"[{server}]"
    else:
        server_display = server

    sni = item.get('tls', {}).get('sni') or item.get('sni', 'www.bing.com')
    
    # 1. Hysteria2
    if p_type == 'hysteria2':
        auth = item.get('auth') or item.get('password')
        return f"hysteria2://{auth}@{server_display}:{port}/?sni={sni}&insecure=1"

    # 2. VLESS
    elif p_type == 'vless':
        uuid = item.get('uuid') or item.get('id')
        net = item.get('network') or item.get('transport', {}).get('type', 'tcp')
        return f"vless://{uuid}@{server_display}:{port}?encryption=none&security=tls&sni={sni}&type={net}"

    # 3. Trojan
    elif p_type == 'trojan':
        pw = item.get('password')
        return f"trojan://{pw}@{server_display}:{port}?security=tls&sni={sni}"

    # 4. TUIC
    elif p_type == 'tuic':
        uuid = item.get('uuid') or item.get('id') or item.get('password')
        return f"tuic://{uuid}@{server_display}:{port}?sni={sni}&insecure=1&alpn=h3"

    # 5. VMess
    elif p_type == 'vmess':
        vid = item.get('uuid') or item.get('id')
        v2_config = {"v": "2", "ps": "Node", "add": server, "port": port, "id": vid, "aid": "0", "scy": "auto", "net": "tcp", "type": "none", "tls": "tls", "sni": sni}
        return f"vmess://{base64.b64encode(json.dumps(v2_config).encode()).decode()}"

    return None

def main():
    unique_links = set()
    for url in URL_SOURCES:
        try:
            print(f"Fetching: {url}")
            r = requests.get(url, timeout=10)
            if r.status_code != 200: continue
            
            # YAML (Clash)
            if '.yaml' in url or 'clash' in url:
                data = yaml.safe_load(r.text)
                if isinstance(data, dict):
                    for p in data.get('proxies', []):
                        link = parse_to_link(p)
                        if link: unique_links.add(link)
            
            # JSON (Sing-box / Raw)
            else:
                data = json.loads(r.text)
                if isinstance(data, dict):
                    if 'outbounds' in data:
                        for o in data['outbounds']:
                            link = parse_to_link(o)
                            if link: unique_links.add(link)
                    elif data.get('server') or data.get('type'):
                        link = parse_to_link(data)
                        if link: unique_links.add(link)
        except: continue

    if unique_links:
        node_list = sorted(list(unique_links))
        final_list = [f"{link}#Node_{i+1}" for i, link in enumerate(node_list)]
        
        # 写入文件
        with open("sub.txt", "w") as f:
            f.write(base64.b64encode("\n".join(final_list).encode()).decode())
        with open("nodes.txt", "w") as f:
            f.write("\n".join(final_list))
        print(f"✅ Success! Total nodes: {len(final_list)}")
    else:
        print("❌ No nodes found.")

if __name__ == "__main__":
    main()
