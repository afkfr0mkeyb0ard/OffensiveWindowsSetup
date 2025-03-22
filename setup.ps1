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

# Ldapnomnom
downloadFile -Url "https://github.com/lkarlslund/ldapnomnom/releases/download/v1.5.1/ldapnomnom-windows-x64-obfuscated.exe" -Destination $installPath"ldapnomnom-windows-x64-obfuscated.exe"
downloadFile -Url "https://github.com/lkarlslund/ldapnomnom/releases/download/v1.5.1/ldapnomnom-windows-x64.exe" -Destination $installPath"ldapnomnom-windows-x64.exe"

# MFASweep
downloadFile -Url "https://raw.githubusercontent.com/dafthack/MFASweep/refs/heads/master/MFASweep.ps1" -Destination $installPath"MFASweep.ps1"

# Mimikatz
git clone https://github.com/ParrotSec/mimikatz.git $installPath"mimikatz"

# PowerZure
git clone https://github.com/hausec/PowerZure.git $installPath"PowerZure"

# SharpHound
downloadFile -Url https://github.com/SpecterOps/SharpHound/releases/download/v2.6.1/SharpHound-v2.6.1.zip -Destination $installPath"SharpHound.zip"
Expand-Archive -Path $installPath"SharpHound.zip" -DestinationPath $installPath"SharpHound" -Force
Remove-Item $installPath"SharpHound.zip" -Force

# Sysinternals
New-Item -Path $installPath"Sysinternals" -ItemType Directory | Out-Null
downloadFile -Url https://live.sysinternals.com/accesschk64.exe -Destination $installPath"Sysinternals\accesschk64.exe"
downloadFile -Url https://live.sysinternals.com/ADExplorer64.exe -Destination $installPath"Sysinternals\ADExplorer64.exe"
downloadFile -Url https://live.sysinternals.com/procdump64.exe -Destination $installPath"Sysinternals\procdump64.exe"
downloadFile -Url https://live.sysinternals.com/Procmon64.exe -Destination $installPath"Sysinternals\Procmon64.exe"
downloadFile -Url https://live.sysinternals.com/PsExec64.exe -Destination $installPath"Sysinternals\PsExec64.exe"
