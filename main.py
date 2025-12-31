import json
import requests
import base64

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

def main():
    nodes_dict = {} # 用 server 作为键来去重

    for url in URL_SOURCES:
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                c = resp.json()
                server = c.get('server')
                auth = c.get('auth')
                sni = c.get('tls', {}).get('sni', 'www.bing.com')
                if server and auth:
                    link = f"hysteria2://{auth}@{server}/?sni={sni}&insecure=1"
                    nodes_dict[server] = link # 同一个服务器 IP 只保留一个
        except:
            continue
    
    if nodes_dict:
        # 将字典转为列表并加上编号名称
        final_nodes = [f"{link}#Node_{i+1}" for i, link in enumerate(nodes_dict.values())]
        combined = "\n".join(final_nodes)
        # 编码为 Base64
        b64_data = base64.b64encode(combined.encode('utf-8')).decode('utf-8')
        with open("sub.txt", "w") as f:
            f.write(b64_data)
        print(f"成功提取 {len(final_nodes)} 个节点")

if __name__ == "__main__":
    main()
