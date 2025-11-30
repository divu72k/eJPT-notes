✅ 1. Generate More Host Discovery & Network Scanning Activity

This is the biggest component.

Perform full Nmap workflows

Don’t rely only on the initial quick scans.

Do these:

Basic Discovery
nmap -sn <network-range>

Heavy Port Scans
nmap -p- <target>
nmap -sV -sC <target>
nmap -A <target>

UDP Scans (they count a lot)
nmap -sU <target>

Version + Script Scan
nmap -sV -sC -p <commonly open ports> <target>

Vulnerability Script Scan
nmap --script vuln <target>

Scan all hosts in the subnet

Even if you don’t think they matter.

nmap -sV -sC <subnet>/24


The goal:
Show the exam engine that you enumerated properly, not just speed-ran.

✅ 2. Use More Host Enumeration

Once you gain credentials or access, enumerate heavily.

Windows enumeration

Run:

net user
net localgroup
net view /domain
wmic product get name
wmic qfe
whoami /priv

Linux enumeration

Run:

uname -a
sudo -l
lsusb
lspci
netstat -ano
ps aux


Every command like these increases “host-side activity” in the logs.

✅ 3. Don’t skip web enumeration

Even if you know the flag location.

Use:

Gobuster / Dirsearch
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt

WhatWeb
whatweb <url>

Nikto
nikto -h <url>

✅ 4. Use multiple exploitation attempts (even failed ones count)

For example:

SMB enumeration:
enum4linux -a <ip>
smbclient -L <ip>
smbmap -H <ip>

FTP:
ftp <ip>

SSH brute-check:

(Not brute-forcing; just trying default passwords)

ssh user@ip

HTTP parameter fuzzing:

Even light attempts count.

✅ 5. DO NOT tunnel everything in a single command

The exam engine tracks interaction frequency, not just results.

Example: Instead of one mega-Nmap command → run multiple smaller ones that generate more logs.

✅ 6. Spend time on machines

Activity is also time-based.
If you rush, the system flags you as having insufficient engagement.

Stay at least:

30–40 minutes on host enumeration

20–30 minutes on network mapping

at least 2–3 hours on the overall exam to generate traffic

(Yes, even if you can finish faster.)

🔥 Most eJPT students who fail on “activity” skipped these:
Missed Activity	Why It Hurts
No UDP scanning	Removes ~20% of network activity logs
Minimal host enumeration	Makes it look like you didn’t explore compromised systems
Only Nmap + immediately exploiting	Insufficient variety of actions
Didn’t enumerate all hosts	The engine expects multi-host engagement
Too fast	Looks automated / incomplete
⭐ Pro Strategy to Guarantee Enough Activity

Here’s a workflow that ALWAYS registers full activity:

1️⃣ Full network scan
nmap -sn <subnet>/24
nmap -p- -sV -sC <host>
nmap -sU <host>

2️⃣ Web enumeration (if applicable)
gobuster dir -u <url> -w common.txt
whatweb <url>
nikto -h <url>

3️⃣ SMB/FTP/SSH enumeration
enum4linux -a
smbmap
smbclient -L
ftp

4️⃣ Once inside a box → heavy enumeration
sudo -l
ps aux
netstat -anu
netstat -tulpn
whoami /all
wmic qfe
