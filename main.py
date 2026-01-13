import json
import requests
import base64
import yaml
import urllib.parse
import warnings
from datetime import datetime, timedelta

# 忽略不安全的 HTTPS 请求警告
warnings.filterwarnings("ignore")

# 订阅源列表
URL_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ip/singbox/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json"
]


def get_node_info(item):
    try:
        if not isinstance(item, dict):
            return None

        raw_server = item.get('server') or item.get('add') or item.get('address')
        if not raw_server or str(raw_server).startswith('127.'):
            return None

        server_str = str(raw_server).strip()
        server, port = "", ""

        # 处理带有端口的地址格式
        if ']:' in server_str:
            server, port = server_str.split(']:')[0] + ']', server_str.split(']:')[1]
        elif server_str.startswith('[') and ']' in server_str:
            server = server_str
            port = item.get('port') or item.get('server_port')
        elif server_str.count(':') == 1:
            server, port = server_str.split(':')
        else:
            server = server_str
            port = item.get('port') or item.get('server_port') or item.get('port_num')

        if port:
            port = str(port).split(',')[0].split('-')[0].split('/')[0].strip()

        if not server or not port:
            return None

        # 提取密钥/密码
        secret = (
            item.get('auth') or item.get('auth_str') or item.get('auth-str') or
            item.get('password') or item.get('uuid') or item.get('id')
        )
        if not secret:
            return None

        # 判定协议类型
        p_type = str(item.get('type', '')).lower()
        if any(x in p_type for x in ['hy2', 'hysteria2']) or 'auth' in item:
            p_type = 'hysteria2'
        elif any(x in p_type for x in ['vless']):
            p_type = 'vless'
        else:
            p_type = 'vless' if 'uuid' in item else 'hysteria2'

        # 提取 TLS/SNI 信息
        tls_obj = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
        sni = (
            item.get('servername') or item.get('sni') or
            tls_obj.get('server_name') or tls_obj.get('sni') or ""
        )

        # 提取 REALITY 核心参数
        reality_obj = item.get('reality-opts') or tls_obj.get('reality') or item.get('reality') or {}
        if not isinstance(reality_obj, dict):
            reality_obj = {}

        pbk = (
            reality_obj.get('public-key') or reality_obj.get('public_key') or
            item.get('public-key') or ""
        )
        sid = (
            reality_obj.get('short-id') or reality_obj.get('short_id') or
            item.get('short-id') or ""
        )

        return {
            "server": server,
            "port": int(port),
            "type": p_type,
            "sni": sni,
            "secret": secret,
            "pbk": pbk,
            "sid": sid,
            "raw_server": server_str
        }
    except:
        return None


def main():
    raw_nodes_data = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }

    # 1. 抓取与解析
    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=15, verify=False)
            if r.status_code != 200:
                continue

            content = r.text.strip()

            # 尝试解析 JSON 或 YAML
            if content.startswith(('{', '[')):
                data = json.loads(content)
            else:
                data = yaml.safe_load(content)

            def extract_dicts(obj):
                res = []
                if isinstance(obj, dict):
                    res.append(obj)
                    for v in obj.values():
                        res.extend(extract_dicts(v))
                elif isinstance(obj, list):
                    for i in obj:
                        res.extend(extract_dicts(i))
                return res

            for d in extract_dicts(data):
                node = get_node_info(d)
                if node:
                    raw_nodes_data.append(node)

        except Exception:
            continue

    # 2. 去重
    unique_configs = []
    seen_configs = set()

    for n in raw_nodes_data:
        config_key = (n['type'], n['raw_server'], n['port'], n['secret'], n['pbk'])
        if config_key not in seen_configs:
            unique_configs.append(n)
            seen_configs.add(config_key)

    clash_proxies = []
    uri_links = []

    # 北京时间戳（用于节点名称）
    beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%H%M")

    # 3. 格式化输出
    for index, n in enumerate(unique_configs, start=1):
        tag = n['server'].split('.')[-1].replace(']', '') if '.' in n['server'] else "node"
        node_name = f"{index:02d}_{n['type'].upper()}_{tag}_{beijing_time}"
        name_enc = urllib.parse.quote(node_name)

        # 适配 IPv6 地址格式
        srv_uri = n['server']
        if ':' in srv_uri and not srv_uri.startswith('['):
            srv_uri = f"[{srv_uri}]"

        srv_clash = n['server'].replace('[', '').replace(']', '')

        if n["type"] == "hysteria2":
            uri = (
                f"hysteria2://{n['secret']}@{srv_uri}:{n['port']}?"
                f"insecure=1&allowInsecure=1&sni={n['sni']}#{name_enc}"
            )
            uri_links.append(uri)

            clash_proxies.append({
                "name": node_name,
                "type": "hysteria2",
                "server": srv_clash,
                "port": n["port"],
                "password": n["secret"],
                "tls": True,
                "sni": n["sni"],
                "skip-cert-verify": True
            })

        elif n["type"] == "vless" and n['pbk']:
            vless_uri = (
                f"vless://{n['secret']}@{srv_uri}:{n['port']}?"
                f"encryption=none&security=reality&type=tcp&"
                f"sni={n['sni']}&fp=chrome&pbk={n['pbk']}&sid={n['sid']}&headerType=none"
                f"#{name_enc}"
            )
            uri_links.append(vless_uri)

            clash_proxies.append({
                "name": node_name,
                "type": "vless",
                "server": srv_clash,
                "port": n["port"],
                "uuid": n["secret"],
                "tls": True,
                "udp": True,
                "servername": n["sni"],
                "network": "tcp",
                "reality-opts": {
                    "public-key": n["pbk"],
                    "short-id": n["sid"]
                },
                "client-fingerprint": "chrome"
            })

    # 4. 生成 Clash 配置
    p_names = [p["name"] for p in clash_proxies]

    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "nameserver": ["223.5.5.5", "119.29.29.29"],
            "fallback": ["8.8.8.8", "1.1.1.1"]
        },
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + p_names + ["DIRECT"]},
            {"name": "⚡ 自动选择", "type": "url-test", "proxies": p_names, "url": "http://www.gstatic.com/generate_204", "interval": 300},
            {"name": "🌍 全球直连", "type": "select", "proxies": ["DIRECT", "🚀 节点选择"]},
            {"name": "🛑 广告拦截", "type": "select", "proxies": ["REJECT", "DIRECT", "🚀 节点选择"]},
            {"name": "🐟 漏网之鱼", "type": "select", "proxies": ["🚀 节点选择", "DIRECT", "⚡ 自动选择"]}
        ],
        "rules": [
            "GEOIP,LAN,DIRECT",
            "GEOIP,CN,🌍 全球直连",
            "MATCH,🐟 漏网之鱼"
        ]
    }

    # 5. 写入文件
    try:
        with open("node.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(uri_links))

        with open("sub.txt", "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(uri_links).encode()).decode())

        with open("clash.yaml", "w", encoding="utf-8") as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

        print(f"处理完成！捕获有效节点: {len(clash_proxies)} 个")
        print("生成文件：node.txt / sub.txt / clash.yaml")

    except Exception as e:
        print(f"写入文件失败: {e}")


if __name__ == "__main__":
    main()
