import json
import requests
import base64
import yaml
import urllib.parse

# 数据源列表
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
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ip/singbox/2/config.json"
]

def parse_to_link(item):
    server = item.get('server') or item.get('add')
    port = item.get('port') or item.get('server_port') or item.get('port_num')
    
    # 兼容处理 server:port 格式
    if server and ':' in str(server) and not port:
        if '[' in str(server):
            parts = str(server).split(']:')
            server, port = parts[0] + ']', (parts[1] if len(parts) > 1 else "")
        else:
            parts = str(server).rsplit(':', 1)
            server, port = parts[0], parts[1]

    if not server or not port: return None

    p_type = str(item.get('type', '')).lower()
    if not p_type and item.get('auth') and item.get('bandwidth'): p_type = 'hysteria2'

    tls_data = item.get('tls', {})
    if isinstance(tls_data, bool): tls_data = {}
    sni = item.get('servername') or item.get('sni') or tls_data.get('server_name') or tls_data.get('sni') or "www.bing.com"
    
    # 对备注进行 URL 编码
    raw_tag = f"{p_type.upper()}_{server}_{port}"
    node_name = urllib.parse.quote(raw_tag)
    server_display = f"[{server}]" if ":" in str(server) and "[" not in str(server) and "," not in str(server) else server

    # --- 协议精准适配逻辑 ---
    
    # 1. Hysteria 2
    if p_type in ['hysteria2', 'hy2']:
        auth = item.get('auth') or item.get('password') or item.get('auth-str')
        return f"hysteria2://{auth}@{server_display}:{port}?sni={sni}&insecure=1&allowInsecure=1#{node_name}"

    # 2. VLESS Reality
    elif p_type == 'vless':
        uuid = item.get('uuid') or item.get('id')
        link = f"vless://{uuid}@{server_display}:{port}?encryption=none&security=reality&sni={sni}"
        ropts = item.get('reality-opts', {})
        rbox = tls_data.get('reality', {})
        pbk = ropts.get('public-key') or rbox.get('public_key')
        sid = ropts.get('short-id') or rbox.get('short_id')
        if pbk: link += f"&pbk={pbk}"
        if sid: link += f"&sid={sid}"
        link += "&type=tcp&headerType=none"
        return f"{link}#{node_name}"

    # 3. TUIC (基于你的成功样本优化)
    elif p_type == 'tuic':
        uuid = item.get('uuid') or item.get('id') or item.get('password')
        # 核心修改：使用 UUID%3AUUID 格式，并补全所有参数
        return f"tuic://{uuid}%3A{uuid}@{server_display}:{port}?sni={sni}&alpn=h3&insecure=1&allowInsecure=1&congestion_control=bbr#{node_name}"
    
    # 4. Hysteria 1
    elif p_type == 'hysteria':
        auth = item.get('auth') or item.get('auth-str')
        return f"hysteria://{server_display}:{port}?auth={auth}&sni={sni}&insecure=1&allowInsecure=1#{node_name}"

    return None

def main():
    unique_links = set()
    for url in URL_SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code != 200: continue
            if 'clash' in url or 'proxies:' in r.text:
                data = yaml.safe_load(r.text)
                if isinstance(data, dict) and 'proxies' in data:
                    for p in data['proxies']:
                        link = parse_to_link(p)
                        if link: unique_links.add(link)
            else:
                data = json.loads(r.text)
                if isinstance(data, dict):
                    if 'outbounds' in data:
                        for o in data['outbounds']:
                            link = parse_to_link(o)
                            if link: unique_links.add(link)
                    elif data.get('server') or data.get('add'):
                        link = parse_to_link(data)
                        if link: unique_links.add(link)
        except: continue

    if unique_links:
        final_list = sorted(list(unique_links))
        full_content = "\n".join(final_list)
        with open("nodes.txt", "w", encoding="utf-8") as f: f.write(full_content)
        encoded_content = base64.b64encode(full_content.strip().encode("utf-8")).decode("utf-8")
        with open("sub.txt", "w", encoding="utf-8") as f: f.write(encoded_content)
        print("✅ TUIC 格式已修正为成功样本格式，请重新订阅！")

if __name__ == "__main__":
    main()
