#!/bin/bash  
  
# Define the target and wordlist location  
TARGET="target.ine.local"  
WORDLIST="/root/Desktop/wordlists/shares.txt"  
  
# Check if the wordlist file exists  
if [ ! -f "$WORDLIST" ]; then  
echo "Wordlist not found: $WORDLIST"  
exit 1  
fi  
  
# Loop through each share in the wordlist  
while read -r SHARE; do  
echo "Testing share: $SHARE"  
smbclient //$TARGET/$SHARE -N -c "ls" &>/dev/null  
  
if [ $? -eq 0 ]; then  
echo "[+] Anonymous access allowed for: $SHARE"  
else  
echo "[-] Access denied for: $SHARE"  
fi  
done < "$WORDLIST"