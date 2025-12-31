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
    """
    严格按照 JSON 字典内容提取，不进行硬编码猜测
    """
    try:
        if not isinstance(item, dict): return None
        
        # 提取地址和端口
        server = item.get('server') or item.get('add') or item.get('address')
        port_raw = item.get('port') or item.get('server_port') or item.get('port_num')
        if not server or not port_raw: return None
        
        # 端口格式化（处理范围端口）
        port = str(port_raw).split(',')[0].split('-')[0].strip()
        
        # 协议类型
        p_type = str(item.get('type', '')).lower()
        
        # --- 核心凭据提取逻辑 ---
        # 1. 如果是 Hysteria2，依次寻找 auth_str, password, auth
        if p_type in ['hy2', 'hysteria2'] or 'auth_str' in item or 'auth-str' in item:
            p_type = 'hysteria2'
            secret = item.get('auth_str') or item.get('auth-str') or item.get('password') or item.get('auth')
        # 2. 如果是 VLESS/TUIC，依次寻找 uuid, id, password
        else:
            secret = item.get('uuid') or item.get('id') or item.get('password')

        if not secret: return None

        # 3. 提取 TLS/SNI 相关
        tls_obj = item.get('tls', {})
        if not isinstance(tls_obj, dict): tls_obj = {}
        # 优先级：item直接定义的sni > tls对象内的server_name > 默认值
        sni = item.get('servername') or item.get('sni') or tls_obj.get('server_name') or tls_obj.get('sni') or ""
        
        insecure = 1 if (item.get('skip-cert-verify') or tls_obj.get('insecure') or True) else 0

        addr_tag = str(server).split('.')[-1].replace(']', '')
        name = f"{p_type.upper()}_{addr_tag}_{beijing_time}"
        
        return {
            "name": name, "server": server, "port": int(port), "type": p_type,
            "sni": sni, "secret": secret, "insecure": insecure, "raw": item
        }
    except:
        return None

def main():
    nodes_list = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=12, verify=False)
            if r.status_code != 200: continue
            
            # 解析内容
            try:
                data = json.loads(r.text)
            except:
                data = yaml.safe_load(r.text)
            
            # 深度优先搜索所有包含 server 关键词的字典
            def find_proxies(obj):
                if isinstance(obj, dict):
                    if any(k in obj for k in ['server', 'add', 'address']):
                        node = get_node_info(obj)
                        if node: nodes_list.append(node)
                    for v in obj.values(): find_proxies(v)
                elif isinstance(obj, list):
                    for i in obj: find_proxies(i)
            
            find_proxies(data)
        except:
            continue

    if not nodes_list: return

    # 去重
    unique_nodes = []
    seen = set()
    for n in nodes_list:
        key = f"{n['server']}:{n['port']}"
        if key not in seen:
            unique_nodes.append(n)
            seen.add(key)

    # 格式化输出
    uri_links = []
    clash_proxies = []

    for n in unique_nodes:
        name_enc = urllib.parse.quote(n["name"])
        srv = f"[{n['server']}]" if ":" in str(n['server']) and "[" not in str(n['server']) else n['server']
        
        if n["type"] == "hyst
