**Enumeration:**
- Use *enum4linux* tool for enumeration.
	Usage:
		enum4linux -a target.ine.local
- For enumeration of shares, use *smbmap*.
	Usage:
		smbmap -H target.ine.local -u tom -p felipe
- Use [[Bash script for Samba anon enum]] for searching for anonymous shares (make sure to change the directories and target)

**Exploitation:**
- Use the following metasploit modules:
	(i) auxiliary/scanner/smb/smb_version
	(ii) auxiliary/scanner/smb/smb_enumshares
	(iii) auxiliary/scanner/smb/smb_ms17_010
	(iv) auxiliary/scanner/smb/smb_login
	(v) auxiliary/scanner/smb/smb_enumusers
	(vi) exploit/windows/smb/ms17_010_psexec
	(vii) exploit/windows/smb/smb_relay
	(viii) exploit/multi/samba/usermap_script
	(ix) post/windows/gather/enum_shares
	(x) post/windows/manage/enable_rdp
	(xi) is_known_pipe

**TIPS:**
- We can also use leaked NTLM hashes for logging in to a compromised user.