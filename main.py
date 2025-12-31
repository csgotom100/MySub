import json
import requests
import base64
import yaml

# 数据源列表 - 保持您现有的源不变
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
    # 提取基础连接信息
    raw_server = item.get('server') or item.get('add')
    raw_port = item.get('port') or item.get('server_port') or item.get('port_num')
    
    # 兼容处理 server:port 格式
    if raw_server and ':' in str(raw_server) and not raw_port:
        if '[' in str(raw_server):
            parts = str(raw_server).split(']:')
            server, port = parts[0] + ']', (parts[1] if len(parts) > 1 else "")
        else:
            parts = str(raw_server).rsplit(':', 1)
            server, port = parts[0], parts[1]
    else:
        server, port = raw_server, raw_port

    if not server or not port: return None

    # 识别协议类型
    p_type = str(item.get('type', '')).lower()
    if not p_type and item.get('auth') and item.get('bandwidth'): p_type = 'hysteria2'

    # 设置 SNI
    tls_data = item.get('tls', {})
    if isinstance(tls_data, bool): tls_data = {}
    sni = item.get('servername') or item.get('sni') or tls_data.get('server_name') or tls_data.get('sni') or "www.bing.com"
    
    # 节点显示名称 (备注)
    addr_tag = str(server).split('.')[-1] if '.' in str(server) else "v6"
    node_name = f"{p_type.upper()}_{addr_tag}_{port}"
    server_display = f"[{server}]" if ":" in str(server) and "[" not in str(server) and "," not in str(server) else server

    # --- 各协议链接生成逻辑 (适配 v2rayN V7.x) ---

    # 1. Hysteria 2
    if p_type in ['hysteria2', 'hy2']:
        auth = item.get('auth') or item.get('password') or item.get('auth-str')
        return f"hysteria2://{auth}@{server_display}:{port}?sni={sni}&insecure=1#{node_name}"

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
        return f"{link}#{node_name}"

    # 3. TUIC (精简 V7 适配版)
    elif p_type == 'tuic':
        uuid = item.get('uuid') or item.get('id') or item.get('password')
        return f"tuic://{uuid}@{server_display}:{port}?sni={sni}&alpn=h3&insecure=1#{node_name}"
    
    # 4. Hysteria 1
    elif p_type == 'hysteria':
        auth = item.get('auth') or item.get('auth-str')
        return f"hysteria://{server_display}:{port}?auth={auth}&sni={sni}&insecure=1#{node_name}"

    return None

def main():
    unique_links = set()
    for url in URL_SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code != 200: continue
            
            # YAML 源处理
            if 'clash' in url or 'proxies:' in r.text:
                data = yaml.safe_load(r.text)
                if isinstance(data, dict) and 'proxies' in data:
                    for p in data['proxies']:
                        link = parse_to_link(p)
                        if link: unique_links.add(link)
            # JSON 源处理
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
        # 排序确保输出整洁
        final_list = sorted(list(unique_links))
        full_content = "\n".join(final_list)
        
        # 保存明文 nodes.txt
        with open("nodes.txt", "w", encoding="utf-8") as f:
            f.write(full_content)
            
        # 保存 Base64 sub.txt
        # 注意：使用 standard b64 编码，确保没有冗余换行
        b64_bytes = base64.b64encode(full_content.encode("utf-8"))
        with open("sub.txt", "w", encoding="utf-8") as f:
            f.write(b64_bytes.decode("utf-8"))
            
        print(f"✅ 运行成功！共捕获 {len(final_list)} 个节点。")
    else:
        print("❌ 未能抓取到任何有效节点。")

if __name__ == "__main__":
    main()
