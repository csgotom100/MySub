import json, requests, base64, yaml, urllib.parse
from datetime import datetime, timedelta

# 数据源列表
URL_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/1/config.yaml"
]

beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%m%d-%H%M")

def get_node_info(item):
    """超级兼容解析器：尝试提取任何可能的服务器信息"""
    try:
        # 1. 提取服务器地址和端口
        server = item.get('server') or item.get('add') or item.get('address')
        port = item.get('port') or item.get('server_port') or item.get('port_num')
        
        # 针对部分 JSON 格式里 server 直接带端口的情况 (例如 "1.2.3.4:1234")
        if server and ':' in str(server) and not port:
            parts = str(server).rsplit(':', 1)
            server, port = parts[0], parts[1]
            
        if not server or not port: return None

        # 2. 识别协议
        p_type = str(item.get('type', '')).lower()
        if not p_type:
            if 'auth' in item or 'password' in item: p_type = 'hysteria2'
            elif 'uuid' in item: p_type = 'vless'
            else: p_type = 'proxy'

        # 3. 提取安全配置
        tls_data = item.get('tls', {})
        if isinstance(tls_data, bool): tls_data = {}
        sni = item.get('servername') or item.get('sni') or tls_data.get('server_name') or "www.microsoft.com"
        
        # 备注名
        addr_tag = str(server).split('.')[-1] if '.' in str(server) else "v6"
        name = f"{p_type.upper()}_{addr_tag}_{beijing_time}"
        
        return {
            "name": name, "server": server, "port": int(port), "type": p_type,
            "sni": sni, "uuid": item.get('uuid') or item.get('id') or item.get('password'),
            "auth": item.get('auth') or item.get('password') or item.get('auth-str'),
            "item": item, "tls_data": tls_data
        }
    except: return None

def main():
    nodes_data = []
    print("开始从多个源抓取数据...")

    for url in URL_SOURCES:
        try:
            r = requests.get(url, timeout=15)
            if r.status_code != 200: continue
            
            # 暴力解析：管它是 JSON 还是 YAML，只要能转成字典就解析
            content = None
            try:
                content = yaml.safe_load(r.text)
            except:
                content = json.loads(r.text)
            
            if not content: continue

            # 寻找所有的代理对象
            raw_list = []
            if isinstance(content, dict):
                # 兼容 Clash(proxies), Sing-box(outbounds), 或者直接就是节点字典
                raw_list = content.get('proxies') or content.get('outbounds') or [content]
            elif isinstance(content, list):
                raw_list = content

            for p in raw_list:
                if isinstance(p, dict):
                    info = get_node_info(p)
                    if info: nodes_data.append(info)
        except: continue

    if not nodes_data:
        print("❌ 未捕获到任何节点，请检查源链接。")
        return

    # --- 1. 生成通用 URI (node.txt & sub.txt) ---
    links = []
    for info in nodes_data:
        name_enc = urllib.parse.quote(info["name"])
        srv = f"[{info['server']}]" if ":" in str(info['server']) else info['server']
        
        if info["type"] in ["tuic"]:
            links.append(f"tuic://{info['uuid']}%3A{info['uuid']}@{srv}:{info['port']}?sni={info['sni']}&alpn=h3&congestion_control=cubic#{name_enc}")
        elif info["type"] in ["hysteria2", "hy2"]:
            links.append(f"hysteria2://{info['auth']}@{srv}:{info['port']}?sni={info['sni']}&insecure=1#{name_enc}")
        elif info["type"] == "vless":
            r = info["item"].get('reality-opts') or info["tls_data"].get('reality', {})
            pbk = r.get('public-key') or r.get('public_key', '')
            sid = r.get('short-id') or r.get('short_id', '')
            links.append(f"vless://{info['uuid']}@{srv}:{info['port']}?encryption=none&security=reality&sni={info['sni']}&pbk={pbk}&sid={sid}&type=tcp&headerType=none#{name_enc}")

    unique_links = sorted(list(set(links)))
    with open("node.txt", "w", encoding="utf-8") as f: f.write("\n".join(unique_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(unique_links).encode()).decode())

    # --- 2. 生成 Clash YAML ---
    clash_proxies = []
    seen = set()
    for n in nodes_data:
        p = {"name": n["name"], "server": n["server"], "port": n["port"], "udp": True, "tls": True, "sni": n["sni"], "skip-cert-verify": True}
        if n["type"] in ["hysteria2", "hy2"]:
            p.update({"type": "hysteria2", "password": n["auth"]})
        elif n["type"] == "tuic":
            p.update({"type": "tuic", "uuid": n["uuid"], "password": n["uuid"], "alpn": ["h3"], "congestion-controller": "cubic"})
        elif n["type"] == "vless":
            p.update({"type": "vless", "uuid": n["uuid"], "network": "tcp"})
        else: continue
        
        if p["name"] not in seen:
            clash_proxies.append(p)
            seen.add(p["name"])

    clash_config = {
        "proxies": clash_proxies,
        "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": [p["name"] for p in clash_proxies] + ["DIRECT"]}],
        "rules": ["MATCH,🚀 节点选择"]
    }
    with open("clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 处理完成！节点总数: {len(clash_proxies)}")

if __name__ == "__main__":
    main()
