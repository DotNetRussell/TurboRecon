# TurboRecon
Turbo Recon is a python script that automates the early stages of a pentest. It facilitates more consistent testing and is easy to extend

## Usage
### It slices, it dices, it automates your recon scanning 
```
python3 turborecon.py                     
usage: turborecon.py [-h] [--no-ping] [--username USERNAME] [--wordlist WORDLIST] [--threads THREADS] ip
turbohacker.py: error: the following arguments are required: ip
```

### Sample output
```
python3 turborecon.py 10.10.11.82 --threads 50
Pinging target 10.10.11.82...
Ping successful. Target is up.
Running nmap scan on 10.10.11.82...
Running nmap SSH enumeration on 10.10.11.82:22...
Running hydra SSH brute-force on 10.10.11.82:22 with username 'admin', wordlist '/usr/share/wordlists/rockyou.txt', and 50 threads...
Running nikto on 10.10.11.82:8000...
Running dirb on 10.10.11.82:8000...
Running gobuster on 10.10.11.82:8000...
Running whatweb on 10.10.11.82:8000...

Scan Summary:
+--------+-----------+----------+
|   Port | Service   | Status   |
+========+===========+==========+
|     22 | ssh       | Scanned  |
+--------+-----------+----------+
|   8000 | http      | Scanned  |
+--------+-----------+----------+

Detailed scan results saved to pentest_report_10.10.11.82_20250820_181557.txt
```

### Sample Report
```
Pentest Report for 10.10.11.82
Generated on: 20250820_181557


========================================
Command: ping -c 4 10.10.11.82
========================================
PING 10.10.11.82 (10.10.11.82) 56(84) bytes of data.
64 bytes from 10.10.11.82: icmp_seq=1 ttl=63 time=25.7 ms
64 bytes from 10.10.11.82: icmp_seq=2 ttl=63 time=25.8 ms
64 bytes from 10.10.11.82: icmp_seq=3 ttl=63 time=26.4 ms
64 bytes from 10.10.11.82: icmp_seq=4 ttl=63 time=26.4 ms

--- 10.10.11.82 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3140ms
rtt min/avg/max/mdev = 25.737/26.094/26.447/0.334 ms


========================================
Command: nmap -p- -sC -sV -oX nmap_scan.xml 10.10.11.82
========================================
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-20 18:16 EDT
Nmap scan report for 10.10.11.82
Host is up (0.027s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodeTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.99 seconds


========================================
Command: nmap --script ssh2-enum-algos,ssh-auth-methods -p 22 10.10.11.82
========================================
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-20 18:16 EDT
Nmap scan report for 10.10.11.82
Host is up (0.026s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|_    password
| ssh2-enum-algos: 
|   kex_algorithms: (10)
|       curve25519-sha256
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group16-sha512
|       diffie-hellman-group18-sha512
|       diffie-hellman-group14-sha256
|       kex-strict-s-v00@openssh.com
|   server_host_key_algorithms: (5)
|       rsa-sha2-512
|       rsa-sha2-256
|       ssh-rsa
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (6)
|       chacha20-poly1305@openssh.com
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|       aes128-gcm@openssh.com
|       aes256-gcm@openssh.com
|   mac_algorithms: (10)
|       umac-64-etm@openssh.com
|       umac-128-etm@openssh.com
|       hmac-sha2-256-etm@openssh.com
|       hmac-sha2-512-etm@openssh.com
|       hmac-sha1-etm@openssh.com
|       umac-64@openssh.com
|       umac-128@openssh.com
|       hmac-sha2-256
|       hmac-sha2-512
|       hmac-sha1
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com

Nmap done: 1 IP address (1 host up) scanned in 0.54 seconds


========================================
Command: hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.11.82:22 -t 50
========================================
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-08-20 18:16:28
[DATA] max 50 tasks per 1 server, overall 50 tasks, 14344399 login tries (l:1/p:14344399), ~286888 tries per task
[DATA] attacking ssh://10.10.11.82:22/
[STATUS] 116.00 tries/min, 116 tries in 00:01h, 14344300 to do in 2060:58h, 33 active
0 of 1 target completed, 0 valid password found
[INFO] Writing restore file because 2 server scans could not be completed
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-08-20 18:19:14
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[ERROR] all children were disabled due too many connection errors
[ERROR] 1 target was disabled because of too many errors
[ERROR] 1 targets did not complete


========================================
Command: nikto -h http://10.10.11.82:8000
========================================
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.11.82
+ Target Hostname:    10.10.11.82
+ Target Port:        8000
+ Start Time:         2025-08-20 18:19:15 (GMT-4)
---------------------------------------------------------------------------
+ Server: gunicorn/20.0.4
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: GET, OPTIONS, HEAD .
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8074 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2025-08-20 18:26:50 (GMT-4) (455 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested


========================================
Command: dirb http://10.10.11.82:8000 -S -o dirb_output.txt
========================================

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: dirb_output.txt
START_TIME: Wed Aug 20 18:26:50 2025
URL_BASE: http://10.10.11.82:8000/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
OPTION: Silent Mode

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://10.10.11.82:8000/ ----
+ http://10.10.11.82:8000/dashboard (CODE:302|SIZE:199)
+ http://10.10.11.82:8000/download (CODE:200|SIZE:10696)
+ http://10.10.11.82:8000/login (CODE:200|SIZE:667)
+ http://10.10.11.82:8000/logout (CODE:302|SIZE:189)
+ http://10.10.11.82:8000/register (CODE:200|SIZE:651)

-----------------
END_TIME: Wed Aug 20 18:31:00 2025
DOWNLOADED: 4612 - FOUND: 5


========================================
Command: gobuster dir -u http://10.10.11.82:8000 -w /usr/share/wordlists/dirb/common.txt -o gobuster_output.txt
========================================
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.82:8000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/dashboard            (Status: 302) [Size: 199] [--> /login]

/download             (Status: 200) [Size: 10696]

/login                (Status: 200) [Size: 667]

/logout               (Status: 302) [Size: 189] [--> /]

/register             (Status: 200) [Size: 651]

===============================================================
Finished
===============================================================


========================================
Command: whatweb http://10.10.11.82:8000
========================================
http://10.10.11.82:8000 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[gunicorn/20.0.4], IP[10.10.11.82], Script, Title[Welcome to CodeTwo]

```
Scan Summary Table:
  Port  Service    Status
    22  ssh        Scanned
  8000  http       Scanned
Detailed scan results saved to pentest_report_10.10.11.82_20250820_181557.txt
