#Requires -RunAsAdministrator



function Repair-Permission($file)
{
    $acl = Get-Acl "$file"
    $acl.SetAccessRuleProtection($true, $false)
    $administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators", "FullControl", "Allow")
    $systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM", "FullControl", "Allow")
    $acl.SetAccessRule($administratorsRule)
    $acl.SetAccessRule($systemRule)
    $acl | Set-Acl
}


try
{

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



    #region     [Configure OpenSSH Server Service]
    Start-Service -Name ssh-agent
    Start-Service -Name sshd
    Stop-Service -Name ssh-agent
    Stop-Service -Name sshd


    $PATH_CONTENT = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if (-Not($PATH_CONTENT.Split(';').Contains("$Env:ProgramFiles\OpenSSH")))
    {
        [Environment]::SetEnvironmentVariable("PATH", "$Env:ProgramFiles\OpenSSH;$PATH_CONTENT", "Machine")
    }


    # OPTIONAL but recommended:
    Set-Service -Name sshd -StartupType 'Automatic'



    # There should be a firewall rule named "OpenSSH-Server-In-TCP", which should be enabled
    if (-Not (Get-NetFirewallRule -Name "*sshd*"))
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



    if (-Not (Test-Path -Path "$HOME\.ssh"))
    { mkdir "$HOME\.ssh" }



    $sshd_config = "$Env:ProgramData\ssh\sshd_config"
    if (Test-Path -Path "$sshd_config")
    {
        $sshd_config_content = (Get-Content -Path "$sshd_config" -Raw)
        $sshd_config_content = $sshd_config_content.Replace("`r`n# PubkeyAuthentication yes", "`r`nPubkeyAuthentication yes")
        $sshd_config_content = $sshd_config_content.Replace("`r`nMatch Group administrators`r`n", "`r`n# Match Group administrators`r`n# ")
        Write-Output "$sshd_config_content" > "$sshd_config"
    }
    Repair-Permission "$sshd_config"



    $pubkeys = "$Env:ProgramData\ssh\administrators_authorized_keys"
    if (-Not (Test-Path -Path "$pubkeys"))
    { Write-Output "" > "$pubkeys" }
    Repair-Permission "$pubkeys"

    $pubkeys = "$HOME\.ssh\authorized_keys"
    if (-Not (Test-Path -Path "$pubkeys"))
    { Write-Output "" > "$pubkeys" }
    Repair-Permission "$pubkeys"



    Start-Service -Name ssh-agent
    Start-Service -Name sshd

    #endregion  [Configure OpenSSH Server Service]

}
catch
{
    $err_msg = $_
    Write-Warning -Message $err_msg
}
