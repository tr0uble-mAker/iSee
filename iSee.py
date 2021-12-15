import re
import os
import argparse

default_input_path = './text.txt'      # 目标文件的默认路径
default_output_path = './report.txt'    # 输出结果默认路径

def logo():
    print(r'''
         _   ____            
        (_) / ___|  ___  ___ 
        | | \___ \ / _ \/ _ \
        | |  ___) |  __/  __/
        |_| |____/ \___|\___|
                                    whoami: https://github.com/tr0uble-mAker        
                                    Author: tr0uble_mAker
    ''')
def usage():
    print('''
        用法: 
                从指定文本中提取资产: python3 iSee.py -f text.txt
                指定输出结果保存路径: python3 iSee.py -f text.txt -o report.txt
    ''')


def file_to_str(input_path):        # 读取目标输入文本
    input_file = open(input_path, 'r', errors='ignore')
    str = input_file.read()
    input_file.close()
    return str


def find_ips(str):                   # 解析所有ip
    ip_list = []
    ips = re.findall(r'(?:(?:[0-9]+\.){3}(?:[0-9]+))', str)
    for ip1 in ips:
        ip_rex = r'^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})$'
        if re.search(ip_rex, ip1):
            ip2 = ip1
            if ip2 not in ip_list:
                ip_list.append(ip2)
    return ip_list


def find_domains(str):                # 解析所有域名
    domain_list = []
    domains = re.findall(r'(?:(?:[a-zA-Z0-9\-_]+\.)+(?:[a-zA-Z0-9\-_]+))', str)
    for domain1 in domains:
        domain_rex = r'('
        topHosts = [
            '.com', '.la', '.io', '.co', '.info', '.net', '.org', '.me', '.mobi',
            '.us', '.biz', '.xxx', '.ca', '.co.jp', '.com.cn', '.net.cn', '.site',
            '.org.cn', '.mx', '.tv', '.ws', '.ag', '.com.ag', '.net.ag',
            '.org.ag', '.am', '.asia', '.at', '.be', '.com.br', '.net.br',
            '.bz', '.com.bz', '.net.bz', '.cc', '.com.co', '.net.co', '.vip',
            '.nom.co', '.de', '.es', '.com.es', '.nom.es', '.org.es',
            '.eu', '.fm', '.fr', '.gs', '.in', '.co.in', '.firm.in', '.gen.in',
            '.ind.in', '.net.in ', '.org.in ', '.it', '.jobs', '.jp', '.ms',
            '.com.mx', '.nl', '.nu', '.co.nz', '.net.nz', '.org.nz', '.club',
            '.se', '.tc', '.tk', '.tw', '.com.tw', '.idv.tw', '.org.tw', '.email'
            '.hk', '.co.uk', '.me.uk', '.org.uk', '.vg', '.com.hk', '.top', '.ltd', '.work',
        ]
        for topHost in topHosts:
            rex_topHost = topHost.replace('.', '\.')
            domain_rex += '{0}|'.format(rex_topHost)
        domain_rex = domain_rex.rstrip('|') + ')$'
        if re.search(domain_rex, domain1):
            domain2 = domain1
            if domain2 not in domain_list:
                domain_list.append(domain2)
    return domain_list

def filter(input_path):         # 过滤输入函数
    str = file_to_str(input_path)
    ips = find_ips(str)
    domains = find_domains(str)
    relsult = {
        'ip': ips,
        'domain': domains,
    }
    return relsult

def find_B(ip_list):
    b_dict = {}
    for ip in ip_list:
        b_key = re.search(r'(([0-9]+\.]*){2})', ip)[0]
        b_key += '0.0/16'
        if b_key in b_dict.keys():
            b_dict[b_key].append(ip)
        else:
            b_dict[b_key] = []
            b_dict[b_key].append(ip)
    return b_dict


def find_C(ip_list):
    c_dict = {}
    for ip in ip_list:
        c_key = re.search(r'(([0-9]+\.]*){3})', ip)[0]
        c_key += '0/24'
        if c_key in c_dict.keys():
            c_dict[c_key].append(ip)
        else:
            c_dict[c_key] = []
            c_dict[c_key].append(ip)
    return c_dict


def find_base_domain(domain_list):
    base_domain_dict = {}
    for domain in domain_list:
        base_domain = ''
        base_domain_list = domain.split('.')
        if len(base_domain_list) > 2:
            base_domain_list.pop(0)
            for host in base_domain_list:
                base_domain += host + '.'
            base_domain = base_domain.rstrip('.')
        else:
            base_domain = domain
        base_domain_key = base_domain
        if base_domain_key in base_domain_dict.keys():
            base_domain_dict[base_domain_key].append(domain)
        else:
            base_domain_dict[base_domain_key] = []
            base_domain_dict[base_domain_key].append(domain)
    return base_domain_dict


def identify(relsult):              # 依次返回 ip列表 b段 c段 域名列表 根域名
    ip_list = relsult['ip']
    c_dict = find_C(ip_list)
    b_dict = find_B(ip_list)
    domain_list = relsult['domain']
    base_domain_dict = find_base_domain(domain_list)
    return (ip_list, b_dict, c_dict, domain_list, base_domain_dict)

import time


def output(identify_relsult_tuple, output_path):
    ip_list = identify_relsult_tuple[0]
    b_dict = identify_relsult_tuple[1]
    c_dict = identify_relsult_tuple[2]
    domain_list = identify_relsult_tuple[3]
    base_domain_dict = identify_relsult_tuple[4]
    log = open(output_path, 'a+', encoding='utf-8')
    print('[INFO] {0}'.format(time.strftime("%Y/%m/%d  %I:%M:%S")), file=log)
    print('[+] 识别到 {0} 个ip:'.format(len(ip_list)))
    print('[+] 识别到 {0} 个ip:'.format(len(ip_list)), file=log)
    for ip in ip_list:
        print('{0}'.format(ip))
        print('{0}'.format(ip), file=log)
    print('[+] 识别到 {0} 个域名:'.format(len(domain_list)))
    print('[+] 识别到 {0} 个域名:'.format(len(domain_list)), file=log)
    for domain in domain_list:
        print('{0}'.format(domain))
        print('{0}'.format(domain), file=log)
    print('[*] 解析到 {0} 个B段:'.format(len(b_dict)))
    print('[*] 解析到 {0} 个B段:'.format(len(b_dict)), file=log)
    for b_key in b_dict.keys():
        print('    {0}         共有 {1} 条数据在此B段中'.format(b_key, len(b_dict[b_key])))
        print('    {0}         共有 {1} 条数据在此B段中'.format(b_key, len(b_dict[b_key])), file=log)
    print('[*] 解析到 {0} 个C段'.format(len(c_dict)))
    print('[*] 解析到 {0} 个C段'.format(len(c_dict)), file=log)
    for c_key in c_dict.keys():
        print('    {0}         共有 {1} 条数据在此C段中'.format(c_key, len(c_dict[c_key])))
        print('    {0}         共有 {1} 条数据在此C段中'.format(c_key, len(c_dict[c_key])), file=log)
    print('[*] 解析到 {0} 个主域名:'.format(len(base_domain_dict)))
    print('[*] 解析到 {0} 个主域名:'.format(len(base_domain_dict)), file=log)
    for base_domain_key in base_domain_dict.keys():
        print('    {0}         该主域下总共包含 {1} 个域名'.format(base_domain_key, len(base_domain_dict[base_domain_key])))
        print('    {0}         该主域下总共包含 {1} 个域名'.format(base_domain_key, len(base_domain_dict[base_domain_key])), file=log)
    log.close()


def parser():
    parser = argparse.ArgumentParser(usage='python3 iSee.py -f text.txt -o report.txt',
                                     description='iSee: 一款资产收集和整理工具',
                                     )
    p = parser.add_argument_group('iSee 的参数')
    p.add_argument("-f", dest='input_path', type=str, help="目标文件路径")
    p.add_argument("-o", dest='output_path', type=str, help="输出结果保存路径 (默认输出在当前目录下的 report.txt )", default=default_output_path)
    args = parser.parse_args()
    return args


def main():
    args = parser()
    if args.input_path != None:
        if os.path.exists(args.input_path):
            print('[+] 检测到目标文件 "{0}" !'.format(args.input_path))
            filter_relsult_dict = filter(args.input_path)
            identify_relsult_tuple = identify(filter_relsult_dict)
            output(identify_relsult_tuple, args.output_path)
            print('\n[+] 结果已保存到 "{0}" 中'.format(args.output_path))
        else:
            print('[-] 目标文件 "{0}" 不存在!'.format(args.input_path))
    else:
        usage()




if __name__ == '__main__':
    logo()
    main()
