import json
import requests
import base64

# 你提供的 8 个 Hysteria2 节点链接（包含了 4 个节点及各自的备份镜像）
URL_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/4/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json"
]

def get_node_link(url):
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            config = resp.json()
            server = config.get('server')
            auth = config.get('auth')
            # 提取 SNI，如果没有则默认使用 www.bing.com
            sni = config.get('tls', {}).get('sni', 'www.bing.com')
            if server and auth:
                # 拼接标准 Hysteria2 链接
                return f"hysteria2://{auth}@{server}/?sni={sni}&insecure=1"
    except Exception as e:
        print(f"请求失败: {url}")
    return None

def main():
    nodes = set() # 使用 set 集合自动去重
    for url in URL_SOURCES:
        link = get_node_link(url)
        if link:
            nodes.add(link)
    
    if not nodes:
        print("未获取到有效节点")
        return

    # 为节点添加名称后缀并合并
    final_list = [f"{link}#ChromeGo_{i+1}" for i, link in enumerate(nodes)]
    combined_str = "\n".join(final_list)
    
    # 转换为 Base64 编码（通用的订阅格式）
    b64_sub = base64.b64encode(combined_str.encode('utf-8')).decode('utf-8')
    
    with open("sub.txt", "w") as f:
        f.write(b64_sub)
    print(f"转换成功，提取了 {len(final_list)} 个去重后的节点。")

if __name__ == "__main__":
    main()
