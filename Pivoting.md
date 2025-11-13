**Scenario:**
2 target systems are given and 1 system can be only accessed from the other target

- Gain the access of the initial system.
- calculate the subnet using chatgpt for the given target IP.
- add the subnet to route using autoroute: **run autoroute -s <IP Subnet>**
- run ARP scanner to see any other valid targets.
- ARP scanner takes subnets as RHOSTS.
- add the portforward to the second target form the first machine: **portfwd add -l <listening port> -p <target port> -r <RHOST>**
- nmap scan on the localhost to scan the ports of the second target(don't forget to specify the listener port!!).
- while exploiting the service on the second target, make sure to change the payload according to the OS of the second target.
