**Two types:**
(i)Active
(ii)Passive

Can be done by the [[IMPORTANT COMMANDS AND TOOLS]] mentioned.
**ACTIVE INFO GATHERING:**
Acquiring info by interacting with the target.

**PASSIVE INFO GATHERING:**
Acquiring info by not interacting with the target.

**FOOTPRINTING:**
Footprinting is an ethical hacking technique used to gather as much data as possible about a specific targeted computer system, an infrastructure and networks to identify opportunities to penetrate them.

**robots.txt:** used for learning about the files in a website, used for indexing by search engines.

**sitemap.xml:** used as an organized data for indexing the files.

**DNS Reconing:**
-use dnsrecon & [dnsdumpster.com](https://dnsdumpster.com/) for this purpose.
-use wafw00f for identifying the firewall

**DNS Interrogation:**
-process of enumerating DNS records of a specific domain
-provides info like IP addresses, subdomains, mail addresses etc.

**DNS Zone Transfers:**
-server admins copy or transfer their files in certain cases from one server to another.
-if misconfigured, attackers can easily target and copy the zone file from the primary DNS server providing with them with the holistic view of the company's network.

**Finding important directories through dirb:**
dirb http://target.ine.local -w /usr/share/dirb/wordlists/big.txt -X .bak,.tar.gz,.zip,.sql,.bak.zip

**Mirroring a website:**
httrack is a tool used for mirroring a website.
Usage:
httrack <website> -O <output_name>

