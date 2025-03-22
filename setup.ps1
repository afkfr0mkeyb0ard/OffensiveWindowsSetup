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
installChoco -Package "golang"
installChoco -Package "python"
installChoco -Package "wireshark"
installChoco -Package "nmap"
installChoco -Package "googlechrome"
installChoco -Package "firefox"
installChoco -Package "7zip.install"
installChoco -Package "notepadplusplus.install"
installChoco -Package "putty.install"
refreshenv

# adPEAS
downloadFile -Url "https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS.ps1" -Destination $installPath"adPEAS.ps1"

# adPEAS-Light
downloadFile -Url "https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS-Light.ps1" -Destination $installPath"adPEAS-Light.ps1"

# Aquatone
downloadFile -Url https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_windows_amd64_1.7.0.zip -Destination $installPath"aquatone_windows_amd64_1.7.0.zip"
Expand-Archive -Path $installPath"aquatone_windows_amd64_1.7.0.zip" -DestinationPath $installPath"aquatone" -Force
Remove-Item $installPath"aquatone_windows_amd64_1.7.0.zip" -Force

# Bettercap
go install github.com/bettercap/bettercap@latest

# bloodyAD
downloadFile -Url "https://github.com/CravateRouge/bloodyAD/releases/download/v2.1.9/bloodyAD.exe" -Destination $installPath"bloodyAD.exe"

# Certify
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/Certify.exe" -Destination $installPath"Certify.exe"

# Chisel
downloadFile -Url "https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz" -Destination $installPath"chisel_1.10.1_linux_amd64.gz"
downloadFile -Url "https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz" -Destination $installPath"chisel_1.10.1_windows_amd64.gz"

# Coercer
git clone https://github.com/p0dalirius/Coercer.git $installPath"Coercer"

# CsFalconUninstaller
git clone https://github.com/gmh5225/CVE-2022-44721-CsFalconUninstaller.git $installPath"CVE-2022-44721-CsFalconUninstaller"

# ForgeCert
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/ForgeCert.exe" -Destination $installPath"ForgeCert.exe"

# Ffuf
downloadFile -Url https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_windows_amd64.zip -Destination $installPath"ffuf_2.1.0_windows_amd64.zip"
Expand-Archive -Path $installPath"ffuf_2.1.0_windows_amd64.zip" -DestinationPath $installPath"ffuf_2.1.0" -Force
Remove-Item $installPath"ffuf_2.1.0_windows_amd64.zip" -Force

# Impacket
downloadFile -Url https://github.com/maaaaz/impacket-examples-windows/releases/download/v0.9.17/impacket-examples-windows-v0.9.17.zip -Destination $installPath"impacket-windows.zip"
Expand-Archive -Path $installPath"impacket-windows.zip" -DestinationPath $installPath"impacket-windows" -Force
Remove-Item $installPath"impacket-windows.zip" -Force

# Kerbrute
downloadFile -Url https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe -Destination $installPath"kerbrute.exe"

# Koh
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/Koh.exe" -Destination $installPath"Koh.exe"

# Ldapnomnom
downloadFile -Url "https://github.com/lkarlslund/ldapnomnom/releases/download/v1.5.1/ldapnomnom-windows-x64-obfuscated.exe" -Destination $installPath"ldapnomnom-windows-x64-obfuscated.exe"
downloadFile -Url "https://github.com/lkarlslund/ldapnomnom/releases/download/v1.5.1/ldapnomnom-windows-x64.exe" -Destination $installPath"ldapnomnom-windows-x64.exe"

# LockLess
downloadFile -Url "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/dotnet%20v4.8.1%20compiled%20binaries/LockLess.exe" -Destination $installPath"LockLess.exe"

# Mentalist
downloadFile -Url https://github.com/sc0tfree/mentalist/releases/download/v1.0/Mentalist-v1.0-Win.zip -Destination $installPath"Mentalist-v1.0-Win.zip"
Expand-Archive -Path $installPath"Mentalist-v1.0-Win.zip" -DestinationPath $installPath"Mentalist" -Force
Remove-Item $installPath"Mentalist-v1.0-Win.zip" -Force

# Mentalist_chains 
git clone https://github.com/afkfr0mkeyb0ard/Mentalist_chains.git $installPath"Mentalist_chains"

# MFASweep
downloadFile -Url "https://raw.githubusercontent.com/dafthack/MFASweep/refs/heads/master/MFASweep.ps1" -Destination $installPath"MFASweep.ps1"

# Mimikatz
git clone https://github.com/ParrotSec/mimikatz.git $installPath"mimikatz"

# Netexec
downloadFile -Url https://github.com/Pennyw0rth/NetExec/releases/download/v1.3.0/nxc.exe.zip -Destination $installPath"nxc.exe.zip"
Expand-Archive -Path $installPath"nxc.exe.zip" -DestinationPath $installPath"netexec" -Force
Remove-Item $installPath"nxc.exe.zip" -Force

# PayloadEverything
git clone https://github.com/afkfr0mkeyb0ard/PayloadEverything.git $installPath"PayloadEverything"

# PetitPotam
git clone https://github.com/topotam/PetitPotam.git $installPath"PetitPotam"

# PowerZure
git clone https://github.com/hausec/PowerZure.git $installPath"PowerZure"

# PrivescCheck
downloadFile -Url "https://raw.githubusercontent.com/itm4n/PrivescCheck/refs/heads/master/PrivescCheck.ps1" -Destination $installPath"PrivescCheck.ps1"

# Responder
git clone https://github.com/lgandx/Responder.git $installPath"Responder"

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
downloadFile -Url https://live.sysinternals.com/Listdlls64.exe -Destination $installPath"Sysinternals\Listdlls64.exe"
downloadFile -Url https://live.sysinternals.com/procdump64.exe -Destination $installPath"Sysinternals\procdump64.exe"
downloadFile -Url https://live.sysinternals.com/procexp64.exe -Destination $installPath"Sysinternals\procexp64.exe"
downloadFile -Url https://live.sysinternals.com/Procmon64.exe -Destination $installPath"Sysinternals\Procmon64.exe"
downloadFile -Url https://live.sysinternals.com/PsExec64.exe -Destination $installPath"Sysinternals\PsExec64.exe"
downloadFile -Url https://live.sysinternals.com/PsService64.exe -Destination $installPath"Sysinternals\PsService64.exe"
downloadFile -Url https://live.sysinternals.com/pssuspend64.exe -Destination $installPath"Sysinternals\pssuspend64.exe"
downloadFile -Url https://live.sysinternals.com/Sysmon64.exe -Destination $installPath"Sysinternals\Sysmon64.exe"
downloadFile -Url https://live.sysinternals.com/tcpview64.exe -Destination $installPath"Sysinternals\tcpview64.exe"

# Winpeas
downloadFile -Url "https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/winPEAS.bat" -Destination $installPath"winPEAS.bat"
downloadFile -Url "https://github.com/peass-ng/PEASS-ng/releases/download/20250216-fd69e735/winPEASx64.exe" -Destination $installPath"winPEASx64.exe"
