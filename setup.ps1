$installPath = $home+"\desktop\TOOLS\"
$tempPath = [System.IO.Path]::GetTempPath()

# Add Defender exclusions
Add-MpPreference -ExclusionPath $tempPath
Add-MpPreference -ExclusionPath $installPath

# Create TOOLS folder
if (-not (Test-Path -Path $installPath)) {
    New-Item -Path $installPath -ItemType Directory | Out-Null
    Write-Host "[+] Created folder $installPath"
} else {
    Write-Host "[i] Folder $installPath already exists"
}

function downloadFile {
    param (
        [string]$Url,
        [string]$Destination
    )
    Write-Host "Downloading $Url to $Destination..."
    Invoke-WebRequest -Uri $Url -OutFile $Destination
}

function installExe {
    param (
        [string]$FilePath,
        [string]$Arguments = "/silent /norestart"
    )
    Write-Host "Installing $FilePath with args: $Arguments..."
    Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -NoNewWindow
}

function installChoco {
    param (
        [string]$Package
    )
    Write-Host "Installing $Package with chocolatey"
    choco install $Package -y
}

# INSTALL DEPENDENCIES
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) 
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
  Import-Module "$ChocolateyProfile"
}
installChoco -Package "git"
refreshenv

# adPEAS
downloadFile -Url "https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS.ps1" -Destination $installPath"adPEAS.ps1"

# adPEAS-Light
downloadFile -Url "https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS-Light.ps1" -Destination $installPath"adPEAS-Light.ps1"

# bloodyAD
downloadFile -Url "https://github.com/CravateRouge/bloodyAD/releases/download/v2.1.9/bloodyAD.exe" -Destination $installPath"bloodyAD.exe"

# Certify
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/Certify.exe" -Destination $installPath"Certify.exe"

# ForgeCert
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/ForgeCert.exe" -Destination $installPath"ForgeCert.exe"

# Koh
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/Koh.exe" -Destination $installPath"Koh.exe"

# Ldapnomnom
downloadFile -Url "https://github.com/lkarlslund/ldapnomnom/releases/download/v1.5.1/ldapnomnom-windows-x64-obfuscated.exe" -Destination $installPath"ldapnomnom-windows-x64-obfuscated.exe"
downloadFile -Url "https://github.com/lkarlslund/ldapnomnom/releases/download/v1.5.1/ldapnomnom-windows-x64.exe" -Destination $installPath"ldapnomnom-windows-x64.exe"

# LockLess
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/LockLess.exe" -Destination $installPath"LockLess.exe"

# MFASweep
downloadFile -Url "https://raw.githubusercontent.com/dafthack/MFASweep/refs/heads/master/MFASweep.ps1" -Destination $installPath"MFASweep.ps1"

# Mimikatz
git clone https://github.com/ParrotSec/mimikatz.git $installPath"mimikatz"

# PowerZure
git clone https://github.com/hausec/PowerZure.git $installPath"PowerZure"

# RestrictedAdmin
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/RestrictedAdmin.exe" -Destination $installPath"RestrictedAdmin.exe"

# Rubeus
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/Rubeus.exe" -Destination $installPath"Rubeus.exe"

# SafetyKatz
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/SafetyKatz.exe" -Destination $installPath"SafetyKatz.exe"

# Seatbelt
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/Seatbelt.exe" -Destination $installPath"Seatbelt.exe"

# SharpChrome
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/SharpChrome.exe" -Destination $installPath"SharpChrome.exe"

# SharpDPAPI
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/SharpDPAPI.exe" -Destination $installPath"SharpDPAPI.exe"

# SharpDump
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/SharpDump.exe" -Destination $installPath"SharpDump.exe"

# SharpHound
downloadFile -Url https://github.com/SpecterOps/SharpHound/releases/download/v2.6.1/SharpHound-v2.6.1.zip -Destination $installPath"SharpHound.zip"
Expand-Archive -Path $installPath"SharpHound.zip" -DestinationPath $installPath"SharpHound" -Force
Remove-Item $installPath"SharpHound.zip" -Force

# SharpUp
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/SharpUp.exe" -Destination $installPath"SharpUp.exe"

# SharpWMI
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/SharpWMI.exe" -Destination $installPath"SharpWMI.exe"

# Sysinternals
New-Item -Path $installPath"Sysinternals" -ItemType Directory | Out-Null
downloadFile -Url https://live.sysinternals.com/accesschk64.exe -Destination $installPath"Sysinternals\accesschk64.exe"
downloadFile -Url https://live.sysinternals.com/ADExplorer64.exe -Destination $installPath"Sysinternals\ADExplorer64.exe"
downloadFile -Url https://live.sysinternals.com/procdump64.exe -Destination $installPath"Sysinternals\procdump64.exe"
downloadFile -Url https://live.sysinternals.com/Procmon64.exe -Destination $installPath"Sysinternals\Procmon64.exe"
downloadFile -Url https://live.sysinternals.com/PsExec64.exe -Destination $installPath"Sysinternals\PsExec64.exe"
downloadFile -Url https://live.sysinternals.com/tcpview64.exe -Destination $installPath"Sysinternals\tcpview64.exe"
