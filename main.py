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
    # 使用字典去重：Key 是节点内容，Value 是生成的链接
    # 这样如果内容完全一致，后抓到的会覆盖前面的，达到去重效果
    unique_nodes = {}

    for url in URL_SOURCES:
        try:
            print(f"正在抓取: {url}")
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                c = resp.json()
                server = c.get('server')
                auth = c.get('auth')
                sni = c.get('tls', {}).get('sni', 'www.bing.com')
                
                if server and auth:
                    # 以 server 和 auth 的组合作为唯一标识
                    identity = f"{server}_{auth}"
                    link = f"hysteria2://{auth}@{server}/?sni={sni}&insecure=1"
                    unique_nodes[identity] = link
                    print(f"解析成功: {server}")
        except:
            print(f"链接无效，跳过: {url}")
            continue
    
    if unique_nodes:
        # 获取去重后的链接列表
        node_links = list(unique_nodes.values())
        final_nodes = [f"{link}#ChromeGo_{i+1}" for i, link in enumerate(node_links)]
        combined = "\n".join(final_nodes)
        
        # Base64 编码输出
        b64_data = base64.b64encode(combined.encode('utf-8')).decode('utf-8')
        with open("sub.txt", "w") as f:
            f.write(b64_data)
        print(f"成功提取 {len(node_links)} 个唯一节点（已剔除重复信息）")
    else:
        print("未发现有效节点")

if __name__ == "__main__":
    main()
