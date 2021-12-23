import requests
import base64
import re, os, sys
import time, platform
import json
from urllib.parse import quote, unquote
import config

Authorization = config.Authorization
headers = {
    "Connection": "keep-alive",
    "Authorization": Authorization
}

def fofa_spider(search_key, output_path='', batch=False):
    if len(Authorization) == 0:
        print('[-] 未检测到 Authorization 的值, 请查看 config.py 是否配置正确 ?')
    else:
        print('[+] 成功检测到 Authorization !')

    searchbs64 = quote(str(base64.b64encode(search_key.encode()), encoding='utf-8'))
    print('[+] 检测到fofa语法为: {0}'.format(search_key))
    print("[*] 生成fofa爬取页面: https://fofa.so/result?&qbase64=" + searchbs64)
    try:
        html = requests.get(url="https://fofa.so/result?&qbase64=" + searchbs64, headers=headers).text
        data_num = re.findall('<span class="pSpanColor">([^<]+)</span>', html)[0]
        page_num = re.findall('<li class="number">([^<]+)</li>', html)[-1]
        print('[+] 检测到 {0} 条数据, 共 {1} 页'.format(data_num, page_num))
    except:
        print('[-] fofa_spider获取到 {0} 条数据, 请检查fofa语法是否有误: {1}'.format(0, search_key))
        return

    data_sum = 0
    cache_data = []
    start_page = 1
    stop_page = page_num            # 默认在最大页数结束
    percent = -1

    if not batch:
        choice = str(input('[+] 现在开始数据抓取?[Y/n]'))
        if choice == 'n':
            sys.exit()
    if platform.system().lower() == 'windows':
        os.system('cls')
    else:
        os.system('clear')
    print('+------------------------------------- FOFA Spider ------------------------------------------')
    print('|                                      Processing...                                        ')


    for i in range(int(start_page), int(stop_page) + 1):        # 爬虫模块
        now = int(i/int(stop_page)*100)
        if now > percent:
            percent = now
            print('[*] 当前爬取进度 {0}% , 总共获取 {1} 条数据'.format(percent, data_sum))
        try:
            req = requests.get(
                'https://api.fofa.so/v1/search?qbase64=' + searchbs64 + "&full=false&pn=" + str(i) + "&ps=10",
                headers=headers, timeout=10)
        except:
            print('[-] 请求超时, 请检查网络是否通畅')
            continue
        req_json = json.loads(req.text)
        assets_list = req_json['data']['assets']
        if len(assets_list) != 0:
            for asset in assets_list:
                data_sum += 1
                url = asset['link']
                ip = asset['ip']
                title = asset['title']
                data = (url, ip, title)
                cache_data.append(data)
                print('[+] URL: {0}         IP: {1}         Title: {2}'.format(url, ip, title))
        else:
            print('[-] fofa_spider 在返回包中未检测到任何数据, 可能是Authorization配置错误, ip被封或该账号获取数据达到上限')

        if len(cache_data) > 0 and output_path != '':       # 缓存数据写入文件
            output = open(output_path, 'a+', encoding='utf-8')
            for each_cahe_data in cache_data:
                print('[+] URL: {0}     IP: {1}     Title: {2}'.format(each_cahe_data[0], each_cahe_data[1], each_cahe_data[2]), file=output)
            output.close()
            cache_data.clear()
        else:
            print('[-] 正在结束 fofa_spider ......')
            break
    print('[+] fofa_spider 结束, 此次任务总共获取 {0} 条数据, 任务完成度: {1}% !'.format(data_sum, percent))
    print('+-------------------------------------   END   ---------------------------------------------')
    time.sleep(2)
    if output_path != '':
        print('[*] fofa_spider 已将此次获取的数据已写入 "{0}" 文件 !'.format(output_path))
        print('[*] 即将进入资产分析 ......')
        time.sleep(3)





if __name__ == '__main__':
    fofa_spider('domain="baidu.com"', '1.txt')