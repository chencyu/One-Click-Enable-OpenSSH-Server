#Requires -RunAsAdministrator

$SSH_Server_Need_Install = (Get-WindowsCapability -Online | Where-Object -Property "Name" -like 'OpenSSH.Server*').State -eq "NotPresent"

if ($SSH_Server_Need_Install)
{
    $OpenSSH_Server_FeatureName = (Get-WindowsCapability -Online | Where-Object -Property "Name" -like 'OpenSSH.Server*').Name
    Add-WindowsCapability -Online -Name "$OpenSSH_Server_FeatureName"
}


#region     [Download latest version of OpenSSH]
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
$request = [System.Net.WebRequest]::Create($url)
$request.AllowAutoRedirect = $false
$response = $request.GetResponse()
$file_url = $([String]$response.GetResponseHeader("Location")).Replace('tag', 'download') + '/OpenSSH-Win64.zip'
Invoke-WebRequest -Uri $file_url -OutFile "$Env:TMP\OpenSSH-Win64.zip"
if (-Not (Test-Path -Path "$Env:TMP\tmpssh")) { mkdir "$Env:TMP\tmpssh" }
Expand-Archive -Path "$Env:TMP\OpenSSH-Win64.zip" -DestinationPath "$Env:TMP\tmpssh"
if (-Not (Test-Path -Path "$Env:ProgramFiles\OpenSSH")) { mkdir "$Env:ProgramFiles\OpenSSH" }
Copy-Item "$Env:TMP\tmpssh\OpenSSH-Win64\*" "$Env:ProgramFiles\OpenSSH"
&"$Env:ProgramFiles\OpenSSH\install-sshd.ps1"
#endregion  [Download latest version of OpenSSH]


if ((Get-Service -Name sshd).status -eq "Running")
{ Stop-Service -Name sshd }

Start-Service -Name sshd

# OPTIONAL but recommended:
Set-Service -Name sshd -StartupType 'Automatic'


# There should be a firewall rule named "OpenSSH-Server-In-TCP", which should be enabled
if (-Not ((Get-NetFirewallRule -Name "*ssh*server*").Name -like "*OpenSSH*Server*"))
{
    # If the firewall does not exist, create one
    New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
}

# Set default to PowerShell 7 rather than Windows PowerShell 5.1 rather than CMD (set by default)
$DefShell = Get-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell
if (-Not $DefShell)
{
    if (Test-Path -Path "${Env:ProgramFiles}\PowerShell\7\pwsh.exe")
    { New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "${Env:ProgramFiles}\PowerShell\7\pwsh.exe" -PropertyType String -Force }
    else
    { New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "${Env:SystemRoot}\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force }
}
