# F5-BIG-IP-TOOLS

## 工具简介

针对 CVE-2022-1388 的快速利用工具，新手代码，有问题欢迎提issus


## 使用方法
	-u url
		you target, example: https://192.168.1.1
	-c command to eval
		you command to eval, example: id
	-v the vul to use
		options: cve-2022-1388 cve-2021-22986 cve-2020-5902
	-m only use in cve-2020-5902
		options: fileRead userList dirList

### poc

<code> main -u http://127.0.0.1 -v cve-2022-1388</code>

### exp

<code> main -u http://127.0.0.1 -v cve-2021-22986 -c command</code>

## 免责声明

本工具仅面向合法授权的企业安全建设行为，例如企业内部攻防演练、漏洞验证和复测，如您需要测试本工具的可用性，请自行搭建靶机环境。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标使用。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。
