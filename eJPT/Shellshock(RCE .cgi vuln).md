**Enumeration:**
- Use scanner/http/apache_mod_cgi_bash_env metasploit module for checking if the target is vulnerable.

**Exploitation:**
- Use exploit/multi/http/apache_mod_cgi_bash_env_exec module for attacking the target.
- Make sure to change the TargetURI to the .cgi directory.
- Upon successful completion, you will get a reverse shell will be created.