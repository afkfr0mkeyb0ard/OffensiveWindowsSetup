# OffensiveWindowsSetup
A PowerShell script to setup offensive Windows tools

### Setup
- Install from the repo
```
powershell -ep b -nop -c "$w=(New-Object Net.WebClient);IEX $w.DownloadString('https://raw.githubusercontent.com/afkfr0mkeyb0ard/OffensiveWindowsSetup/refs/heads/main/setup.ps1');"
```

- Install from your machine
```
powershell -ep b -nop -File setup.ps1
```

### List of installed tools
```
AdPEAS
AdPEAS-Light
BloodyAD
Ldapnomnom
MFASweep
Mimikatz
PowerZure
SharpHound
Sysinternals
```
