# iSee
iSee 是一款资产收集并整理的工具，可以从大量杂乱的文本信息中提取出资产信息(如域名,ip,b段,c段)，从而帮助渗透测试人员收集目标更多的资产    
SRC挖掘神器，将SRC的资产信息黏贴到文本导入iSee，得到的b段，c段可以直接用nmap, masscan等工具进行扫描，有助于发现目标厂商的更多资产信息，尤其是防火墙,VPN等设备的弱口令！ip和域名可以直接导入goby,awvs等扫描器。    
在SRC挖掘或者hvv红队视角下iSee旨在帮助渗透测试人员快速在信息收集得到的杂乱文本信息中整理出目标所有资产，以快速发现目标的脆弱资产。
     
### 用法         

          从指定文本中提取资产:   python3 iSee.py -f text.txt
          指定输出结果保存路径:   python3 iSee.py -f text.txt -o report.txt
### Screenshot
![image](https://user-images.githubusercontent.com/71172892/146219076-41dd51a2-293d-4fcd-b691-638e1d277921.png)
![image](https://user-images.githubusercontent.com/71172892/146219368-59c1643d-54a8-4b31-9403-b487ecea3f0e.png)
