import json, requests, base64, yaml, urllib.parse, warnings
from datetime import datetime, timedelta

# 禁用安全证书警告（防止部分源证书过期导致脚本中断）
warnings.filterwarnings("ignore")

# 你提供的 20 个核心数据源
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

# 获取当前北京时间 (UTC+8)
beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%m%d-%H%M")

def get_node_info(item):
    """解析字典内容并返回统一的节点对象"""
    try:
        if not isinstance(item, dict): return None
        # 兼容多种命名字段
        server = item.get('server') or item.get('add') or item.get('address')
        port = item.get('port') or item.get('server_port')
        if not server or not port or str(server).startswith('127.'): return None

        # 协议识别逻辑
        p_type = str(item.get('type', '')).lower()
        if not p_type:
            if 'auth' in item: p_type = 'hysteria2'
            elif 'uuid' in item: p_type = 'vless'
            else: p_type = 'proxy'

        # TLS 及 SNI 提取
        tls_data = item.get('tls', {})
        if isinstance(tls_data, bool): tls_data = {}
        sni = item.get('servername') or item.get('sni') or tls_data.get('server_name') or "www.microsoft.com"
        
        # 备注格式：协议_IP末段_北京时间
        addr_tag = str(server).split('.')[-1] if '.' in str(server) else "node"
        name = f"{p_type.upper()}_{addr_tag}_{beijing_time}"
        
        return {
            "name": name, "server": server, "port": int(port), "type": p_type,
            "sni": sni, "uuid": item.get('uuid') or item.get('id') or item.get('password'),
            "auth": item.get('auth') or item.get('password') or item.get('auth-str'),
            "item": item, "tls_data": tls_data
        }
    except:
        return None

def main():
    raw_results = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}

    print(f"🚀 开始处理 {len(URL_SOURCES)} 个数据源...")

    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=15, verify=False)
            if r.status_code != 200: continue
            
            # 根据后缀或内容尝试解析 YAML/JSON
            data = None
            try:
                data = yaml.safe_load(r.text)
            except:
                data = json.loads(r.text)
            
            if not data: continue

            # 深度优先搜索所有包含服务器特征的字典对象
            def deep_search(obj):
                if isinstance(obj, dict):
                    # 如果当前字典像是一个节点配置
                    if (obj.get('server') or obj.get('add')) and (obj.get('port') or obj.get('server_port')):
                        node = get_node_info(obj)
                        if node: raw_results.append(node)
                    # 继续向内层搜索
                    for k in obj: deep_search(obj[k])
                elif isinstance(obj, list):
                    for i in obj: deep_search(i)

            deep_search(data)
        except Exception as e:
            print(f"⚠️ 解析源失败: {url} -> {e}")

    if not raw_results:
        print("❌ 未抓取到任何有效节点，请检查源链接。")
        return

    # 全局智能去重（基于 IP 和 端口）
    unique_nodes = []
    seen_addresses = set()
    for n in raw_results:
        addr_key = f
