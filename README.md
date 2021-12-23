# iSee
iSee 是一款资产收集并整理的工具，可以从大量杂乱的文本信息中提取出资产信息(如域名,ip,b段,c段)，从而帮助渗透测试人员收集目标更多的资产    
### 介绍
iSee支持FOFA爬虫模式并能够在fofa搜索结果中提取整理资产信息，同时也是一款SRC挖掘神器，将SRC的资产信息黏贴到文本导入iSee，得到的b段，c段可以直接用nmap, masscan等工具进行扫描，有助于发现目标厂商的更多资产信息，尤其是防火墙,VPN等设备的弱口令！ip和域名可以直接导入goby,awvs等扫描器。    
在SRC挖掘或者hvv红队视角下iSee旨在帮助渗透测试人员快速在信息收集得到的杂乱文本信息中整理出目标所有资产，以快速发现目标的脆弱资产。
     
### 用法         

          从指定文本中提取资产:        python3 iSee.py -f text.txt
          从FOFA查询结果中提取资产:    python3 iSee.py --fofa          （需要在config.py配置 Authorization 的值）
          提取资产后自动进行fofa查询:  python3 iSee.py -f text.txt --fofa
### 参数  
          -f        目标文件
          -o        输出文件路径
          --fofa    fofa爬虫
          
          
### Screenshot
![image](https://user-images.githubusercontent.com/71172892/146388672-b4e12df0-0f20-4d8e-af3c-7b08cfe4561d.png)
![image](https://user-images.githubusercontent.com/71172892/146219368-59c1643d-54a8-4b31-9403-b487ecea3f0e.png)
![image](https://user-images.githubusercontent.com/71172892/146388188-795eb486-72e8-40d4-ab8e-d2a23e78636b.png)

