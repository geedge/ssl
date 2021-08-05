# 0. 功能升级历史

* 2021.8.5

  ssl2.0版本已经废弃，但是可能出现第一个包是ssl2.0,后续数据包tls1.2的情况，因此支持第一个数据包识别错误，第二个数据包继续解析的。参见imaps-64593.pcap

  **注意ssl.h有更新，向上兼容**	 

* 2021.7.27

  证书拥有者subject和颁发者issuer包括commonName +  organizationName + organizationalUnitName + localityName + streetAddress + stateOrProvinceName + countryName

  **注意ssl.h有更新**	 

* 2021.4.17

  支持esni提取，使用方法参考ssl.h中 st_esni_t结构体

  **注意ssl.h有更新**

* 2020.12.2 
支持session ticket的获取，以及new_session_ticket报文的解析。
**注意ssl.h有更新。**
获取new_session_ticket请在inf文件注册。
（https://git.mesalab.cn/MESA_Platform/ssl/-/wikis/Session-Ticket）

# 1.简介

ssl.so是sapp平台解析层插件。

# 2.业务层开发指南

参见wiki链接
https://git.mesalab.cn/MESA_Platform/ssl/wikis/SSL%E4%B8%9A%E5%8A%A1%E5%B1%82%E5%BC%80%E5%8F%91%E6%8C%87%E5%8D%97

业务层demo:
参见project ssl_service_test project

