import json, requests, base64, yaml, urllib.parse, warnings
from datetime import datetime, timedelta

# 禁用安全证书警告
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
    """解析字典内容，特别优化 HY2 识别"""
    try:
        if not isinstance(item, dict): return None
        server = item.get('server') or item.get('add') or item.get('address')
        port = item.get('port') or item.get('server_port') or item.get('port_num')
        if not server or not port or str(server).startswith('127.'): return None

        # 1. 协议识别逻辑
        p_type = str(item.get('type', '')).lower()
        if not p_type:
            # 增强判断：包含 auth 且没有 uuid 的通常是 hy2
            if 'auth' in item: p_type = 'hysteria2'
            elif 'uuid' in item: p_type = 'vless'
            else: p_type = 'proxy'
        
        # 统一将 hy2 标识符标准化
        if p_type in ['hy2', 'hysteria2']: p_type = 'hysteria2'

        # 2. 安全参数提取
        tls_data = item.get('tls', {})
        if isinstance(tls_data, bool): tls_data = {}
        sni = item.get('servername') or item.get('sni') or tls_data.get('server_name') or "www.microsoft.com"
        
        # 3. 核心凭据提取
        # HY2 的密码可能在 auth, password, auth-str 中
        auth = item.get('auth') or item.get('password') or item.get('auth-str') or item.get('auth_str')
        uuid = item.get('uuid') or item.get('id') or item.get('password')

        addr_tag = str(server).split('.')[-1] if '.' in str(server) else "node"
        name = f"{p_type.upper()}_{addr_tag}_{beijing_time}"
        
        return {
            "name": name, "server": server, "port": int(port), "type": p_type,
            "sni": sni, "uuid": uuid, "auth": auth, "raw": item
        }
    except: return None

def main():
    raw_list = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}

    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=15, verify=False)
            if r.status_code != 200: continue
            
            # 尝试解析 YAML 或 JSON
            try:
                data = yaml.safe_load(r.text)
            except:
                data = json.loads(r.text)
            
            # 深度优先递归搜索所有字典对象（因为 Alvin9999 的 HY2 节点有时藏得很深）
            def search_recursive(obj):
                if isinstance(obj, dict):
                    if (obj.get('server') or obj.get('add')) and (obj.get('port') or obj.get('server_port')):
                        node = get_node_info(obj)
                        if node: raw_list.append(node)
                    for k in obj: search_recursive(obj[k])
                elif isinstance(obj, list):
                    for i in obj: search_recursive(i)

            search_recursive(data)
        except: continue

    if not raw_list:
        print("❌ 未捕获到任何有效节点")
        return

    # 全局去重
    unique_nodes = []
    seen_addr = set()
    for n in raw_list:
        addr_key = f"{n['server']}:{n['port']}"
        if addr_key not in seen_addr:
            unique_nodes.append(n)
            seen_addr.add(addr_key)

    # 1. 生成 node.txt (URI)
    links = []
    for n in unique_nodes:
        name_enc = urllib.parse.quote(n["name"])
        srv = f"[{n['server']}]" if ":" in str(n['server']) else n['server']
        
        # HY2 链接格式
        if n["type"] == "hysteria2":
            links.append(f"hysteria2://{n['auth']}@{srv}:{n['port']}?sni={n['sni']}&insecure=1&allowInsecure=1#{name_enc}")
        # TUIC 链接格式
        elif n["type"] == "tuic":
            links.append(f"tuic://{n['uuid']}%3A{n['uuid']}@{srv}:{n['port']}?sni={n['sni']}&alpn=h3&insecure=1&congestion_control=cubic#{name_enc}")
        # VLESS 链接格式
        elif n["type"] == "vless":
            raw = n["raw"]
            tls_obj = raw.get('tls', {}) if isinstance(raw.get('tls'), dict) else {}
            ropts = raw.get('reality-opts') or tls_obj.get('reality', {})
            pbk = ropts.get('public-key') or ropts.get('public_key', '')
            sid = ropts.get('short-id') or ropts.get('short_id', '')
            links.append(f"vless://{n['uuid']}@{srv}:{n['port']}?encryption=none&security=reality&sni={n['sni']}&pbk={pbk}&sid={sid}&type=tcp#{name_enc}")

    with open("node.txt", "w", encoding="utf-8") as f: f.write("\n".join(links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(links).encode()).decode())

    # 2. 生成 clash.yaml
    clash_proxies = []
    for n in unique_nodes:
        p = {"name": n["name"], "server": n["server"], "port": n["port"], "udp": True, "tls": True, "sni": n["sni"], "skip-cert-verify": True}
        if n["type"] == "hysteria2":
            p.update({"type": "hysteria2", "password": n["auth"]})
        elif n["type"] == "tuic":
            p.update({"type": "tuic", "uuid": n["uuid"], "password": n["uuid"], "alpn": ["h3"], "congestion-controller": "cubic"})
        elif n["type"] == "vless":
            p.update({"type": "vless", "uuid": n["uuid"], "network": "tcp"})
        else: continue
        clash_proxies.append(p)

    config = {
        "proxies": clash_proxies,
        "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": [x["name"] for x in clash_proxies] + ["DIRECT"]}],
        "rules": ["MATCH,🚀 节点选择"]
    }
    with open("clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 执行完成！当前去重后节点总数: {len(unique_nodes)}")

if __name__ == "__main__":
    main()
