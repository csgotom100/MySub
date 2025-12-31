import json
import requests
import base64
import yaml

# 你的所有来源（JSON + YAML）
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
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/4/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/5/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/6/config.yaml"
]

def parse_json_hy2(content):
    try:
        data = json.loads(content)
        server = data.get('server')
        auth = data.get('auth')
        sni = data.get('tls', {}).get('sni', 'www.bing.com')
        if server and auth:
            return f"hysteria2://{auth}@{server}/?sni={sni}&insecure=1"
    except: return None

def parse_yaml_proxies(content):
    nodes = []
    try:
        data = yaml.safe_load(content)
        if not data or 'proxies' not in data: return nodes
        
        for p in data['proxies']:
            # 1. 处理 Hysteria2
            if p.get('type') == 'hysteria2':
                server = f"{p['server']}:{p['port']}"
                auth = p.get('password', p.get('auth'))
                sni = p.get('sni', 'www.bing.com')
                nodes.append(f"hysteria2://{auth}@{server}/?sni={sni}&insecure=1")
            
            # 2. 处理 VLESS
            elif p.get('type') == 'vless':
                link = f"vless://{p['uuid']}@{p['server']}:{p['port']}?encryption=none&security={p.get('tls', 'none')}&sni={p.get('sni', '')}&type={p.get('network', 'tcp')}"
                nodes.append(link)
                
            # 3. 处理 Trojan
            elif p.get('type') == 'trojan':
                link = f"trojan://{p['password']}@{p['server']}:{p['port']}?security=tls&sni={p.get('sni', '')}"
                nodes.append(link)
    except Exception as e:
        print(f"YAML 解析出错: {e}")
    return nodes

def main():
    unique_links = set()
    for url in URL_SOURCES:
        try:
            print(f"Fetching: {url}")
            r = requests.get(url, timeout=15)
            if r.status_code != 200: continue
            
            if url.endswith('.json'):
                link = parse_json_hy2(r.text)
                if link: unique_links.add(link)
            else: # YAML 格式
                links = parse_yaml_proxies(r.text)
                for l in links: unique_links.add(l)
        except: continue

    if unique_links:
        # 加上节点名称
        final_list = [f"{link}#Node_{i+1}" for i, link in enumerate(unique_links)]
        output = base64.b64encode("\n".join(final_list).encode()).decode()
        with open("sub.txt", "w") as f:
            f.write(output)
        print(f"成功导出 {len(final_list)} 个节点")
    else:
        print("未抓取到有效节点")

if __name__ == "__main__":
    main()
