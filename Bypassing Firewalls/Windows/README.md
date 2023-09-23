# Enumerating Firewall

Display rules that are off and blocks outbound traffic

```powershell
Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True
```

Display rules that allow outbound traffic

```powershell
Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True
```
