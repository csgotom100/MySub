import json
import requests
import base64
import yaml
import urllib.parse
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

# 获取北京时间 (UTC+8)
beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%m%d-%H%M")

def get_node_info(item):
    """提取节点基础信息"""
    server = item.get('server') or item.get('add')
    port = item.get('port') or item.get('server_port') or item.get('port_num')
    if not server or not port: return None

    p_type = str(item.get('type', '')).lower()
    if not p_type and item.get('auth') and item.get('bandwidth'): p_type = 'hysteria2'
    
    tls_data = item.get('tls', {})
    if isinstance(tls_data, bool): tls_data = {}
    sni = item.get('servername') or item.get('sni') or tls_data.get('server_name') or tls_data.get('sni') or "www.microsoft.com"
    
    addr_short = str(server).split('.')[-1] if '.' in str(server) else "v6"
    name = f"{p_type.upper()}_{addr_short}_{beijing_time}"
    
    return {
        "name": name, "server": server, "port": int(port), "type": p_type,
        "sni": sni, "uuid": item.get('uuid') or item.get('id') or item.get('password'),
        "auth": item.get('auth') or item.get('password') or item.get('auth-str'),
        "tls_data": tls_data, "item": item
    }

def create_clash_proxy(info):
    """转换为 Clash 节点字典"""
    p = {
        "name": info["name"],
        "server": info["server"],
        "port": info["port"],
        "udp": True,
        "tls": True,
        "sni": info["sni"],
        "skip-cert-verify": True
    }
    
    if info["type"] in ['hysteria2', 'hy2']:
        p["type"] = "hysteria2"
        p["password"] = info["auth"]
    elif info["type"] == 'vless':
        p["type"] = "vless"
        p["uuid"] = info["uuid"]
        p["network"] = "tcp"
        ropts = info["item"].get('reality-opts', {})
        rbox = info["tls_data"].get('reality', {})
        p["reality-opts"] = {
            "public-key": ropts.get('public-key') or rbox.get('public_key'),
            "short-id": ropts.get('short-id') or rbox.get('short_id')
        }
    elif info["type"] == 'tuic':
        p["type"] = "tuic"
        p["uuid"] = info["uuid"]
        p["password"] = info["uuid"]
        p["alpn"] = ["h3"]
        p["congestion-controller"] = "cubic" # 对应截图中的配置
    elif info["type"] == 'hysteria':
        p["type"] = "hysteria"
        p["auth_str"] = info["auth"]
        p["up"] = 100
        p["down"] = 100
    else:
        return None
    return p

def main():
    nodes_data = []
    for url in URL_SOURCES:
        try:
            r = requests.get(url, timeout=15)
            if r.status_code != 200: continue
            content = yaml.safe_load(r.text) if ('clash' in url or 'yaml' in url) else json.loads(r.text)
            
            proxies_list = []
            if isinstance(content, dict):
                proxies_list = content.get('proxies', content.get('outbounds', [content] if 'server' in content else []))
            elif isinstance(content, list):
                proxies_list = content

            for p in proxies_list:
                info = get_node_info(p)
                if info: nodes_data.append(info)
        except: continue

    if not nodes_data: return

    # 生成通用 URI (node.txt & sub.txt)
    links = []
    for info in nodes_data:
        name_enc = urllib.parse.quote(info["name"])
        srv = f"[{info['server']}]" if ":" in str(info['server']) else info['server']
        
        if info["type"] == "tuic":
            links.append(f"tuic://{info['uuid']}%3A{info['uuid']}@{srv}:{info['port']}?sni={info['sni']}&alpn=h3&insecure=1&allowInsecure=1&congestion_control=cubic#{name_enc}")
        elif info["type"] in ["hysteria2", "hy2"]:
            links.append(f"hysteria2://{info['auth']}@{srv}:{info['port']}?sni={info['sni']}&insecure=1&allowInsecure=1#{name_enc}")
        elif info["type"] == "vless":
            ropts = info["item"].get('reality-opts', {})
            rbox = info["tls_data"].get('reality', {})
            pbk = ropts.get('public-key') or rbox.get('public_key')
            sid = ropts.get('short-id') or rbox.get('short_id')
            links.append(f"vless://{info['uuid']}@{srv}:{info['port']}?encryption=none&security=reality&sni={info['sni']}&pbk={pbk}&sid={sid}&type=tcp&headerType=none#{name_enc}")

    unique_links = sorted(list(set(links)))
    with open("node.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(unique_links))
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(unique_links).encode()).decode())

    # 生成 Clash
    clash_proxies = []
    seen_names = set()
    for n in nodes_data:
        p_obj = create_clash_proxy(n)
        if p_obj and p_obj["name"] not in seen_names:
            clash_proxies.append(p_obj)
            seen_names.add(p_obj["name"])

    clash_config = {
        "proxies": clash_proxies,
        "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": [p["name"] for p in clash_proxies] + ["DIRECT"]}],
        "rules": ["MATCH,🚀 节点选择"]
    }
    with open("clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 修复完成！时间：{beijing_time}")

if __name__ == "__main__":
    main()
