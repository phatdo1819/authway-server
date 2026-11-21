<#
.SYNOPSIS
    Sets up a test Active Directory domain for Authway Server on a new Windows Server VM, and changes its test
    accounts for specific tests.

.DESCRIPTION
    Run it in an elevated PowerShell on a new Windows Server 2022 or 2025 VM (Desktop Experience or Server Core), and
    run it again after each restart until it says the lab is ready:

      1st run  renames the computer to DC1, then restarts
      2nd run  installs Active Directory and creates the domain lab.authway.test, then restarts
      3rd run  (log in as LAB\<the same admin account> first) installs Certificate Services so the domain
               controller offers LDAPS, creates the test accounts, checks LDAPS, and saves what to enter in Authway
               Server in C:\AuthwayLab\lab-info.txt, with the CA certificate in C:\AuthwayLab\authway-lab-ca.pem

    Running it again later is safe: it repairs the lab and shows the information again. Other actions change the
    test accounts for specific tests; see -Action.

    Only run it on a VM made for this lab. The test accounts share one password, saved in C:\AuthwayLab, and the
    script refuses to change a domain other than its own.

.PARAMETER Action
    Setup              (default) the steps above
    Info               what to enter in Authway Server, and the state of each test account
    Lock               lock erin out with wrong passwords
    HoldTest           disable bulk01 to bulk06, so the next sync holds them back (the safety limit)
    ServiceExpirySoon  the service account's password expires in 10 days, so Authway Server warns about it
    ServiceExpired     the service account must change its password, so syncs fail
    Reset              every test account and group back as it started

.PARAMETER IPAddress
    A fixed IPv4 address for the VM, set before it becomes a domain controller. The prefix length, gateway and DNS
    servers stay as they are. Leave it out on a cloud VM, and reserve the address in the cloud's console instead.

.PARAMETER IgnoreExpiry
    Go on even though this copy of Windows has expired, as preview builds do after a few months.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\authway-ad-lab.ps1 -IPAddress 192.168.100.50

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\authway-ad-lab.ps1 -Action HoldTest
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('Setup', 'Info', 'Lock', 'HoldTest', 'ServiceExpirySoon', 'ServiceExpired', 'Reset')]
    [string]$Action = 'Setup',
    [string]$DomainName = 'lab.authway.test',
    [ValidatePattern('^[A-Za-z0-9-]{1,15}$')]
    [string]$NetbiosName = 'LAB',
    [ValidatePattern('^[A-Za-z0-9-]{1,15}$')]
    [string]$ComputerName = 'DC1',
    [ipaddress]$IPAddress,
    [switch]$IgnoreExpiry
)

$ErrorActionPreference = 'Stop'

$LabDir = 'C:\AuthwayLab'
$StateFile = Join-Path $LabDir 'lab.json'
$InfoFile = Join-Path $LabDir 'lab-info.txt'
$CaFile = Join-Path $LabDir 'authway-lab-ca.pem'
$EnvFile = Join-Path $LabDir 'integration-test.env'
$OuName = 'Authway Lab'
$CaName = 'Authway Lab CA'
$Service = 'svc-authway'
$VpnGroup = 'VPN Users'
$NestedGroup = 'VPN Engineers'
$AllGroup = 'Authway Lab Accounts'
$LabPolicy = 'Authway Lab'
$SoonPolicy = 'Authway Lab service password 10 days'
$LockoutThreshold = 10
$HoldCount = 6

# The same accounts as the Samba lab, so the settings of the Go integration test carry over.
$People = @(
    @{ Sam = 'alice'; Given = 'Alice'; Surname = 'Normal'; Member = $true; Enabled = $true; MustChange = $false
        Role = 'member' }
    @{ Sam = 'bob'; Given = 'Bob'; Surname = 'Nested'; Member = $false; Enabled = $true; MustChange = $false
        Role = "member through the $NestedGroup group" }
    @{ Sam = 'carol'; Given = 'Carol'; Surname = 'Disabled'; Member = $true; Enabled = $false; MustChange = $false
        Role = 'member, disabled' }
    @{ Sam = 'dave'; Given = 'Dave'; Surname = 'Outside'; Member = $false; Enabled = $true; MustChange = $false
        Role = 'not a member' }
    @{ Sam = 'erin'; Given = 'Erin'; Surname = 'Lockout'; Member = $true; Enabled = $true; MustChange = $false
        Role = "member, for lockout tests: $LockoutThreshold wrong passwords lock it for 5 minutes" }
    @{ Sam = 'frank'; Given = 'Frank'; Surname = 'MustChange'; Member = $true; Enabled = $true; MustChange = $true
        Role = 'member, must change password at next logon' }
)
$Bulk = @(1..10 | ForEach-Object {
        @{ Sam = ('bulk{0:d2}' -f $_); Given = 'Bulk'; Surname = ('{0:d2}' -f $_); Member = $true; Enabled = $true
            MustChange = $false }
    })
$ServiceUser = @{ Sam = $Service; Given = 'Authway'; Surname = 'Service'; Member = $false; Enabled = $true
    MustChange = $false }

function Write-Step([string]$Text) {
    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Cyan
}

function Write-Done([string]$Text) {
    Write-Host "    $Text" -ForegroundColor Green
}

function Write-Warn([string]$Text) {
    Write-Host "    $Text" -ForegroundColor Yellow
}

# --- the lab password and other state, kept across restarts -------------------------------------------------------

function Test-PasswordHasName([string]$Password) {
    # Active Directory refuses a password that contains the account name or a part of its full name
    $names = @($ServiceUser) + $People + $Bulk | ForEach-Object { $_.Sam; $_.Given; $_.Surname }
    foreach ($name in $names) {
        if ($name.Length -ge 3 -and $Password.IndexOf($name, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function New-LabPassword {
    # easy to type at a VPN login: no look-alike characters, no characters that shells treat specially
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'
    $limit = 256 - (256 % $alphabet.Length)
    $random = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try {
        do {
            $chars = New-Object System.Text.StringBuilder
            $byte = New-Object byte[] 1
            while ($chars.Length -lt 12) {
                $random.GetBytes($byte)
                if ($byte[0] -lt $limit) { [void]$chars.Append($alphabet[$byte[0] % $alphabet.Length]) }
            }
            $s = $chars.ToString()
            $password = 'Lab-' + $s.Substring(0, 4) + '-' + $s.Substring(4, 4) + '-' + $s.Substring(8, 4)
        } until ($password -cmatch '[a-z]' -and $password -cmatch '[A-Z]' -and $password -match '[0-9]' -and
            -not (Test-PasswordHasName $password))
    } finally {
        $random.Dispose()
    }
    return $password
}

function Get-LabState {
    if (Test-Path $StateFile) {
        return Get-Content -Raw -Path $StateFile | ConvertFrom-Json
    }
    New-Item -ItemType Directory -Path $LabDir -Force | Out-Null
    # it holds the lab password: only Administrators and SYSTEM can open it
    & icacls.exe $LabDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warn "Couldn't limit who can open $LabDir." }
    $state = [pscustomobject]@{
        Domain     = $DomainName
        Password   = New-LabPassword
        DnsServers = @(Get-MainDnsServers)
        Created    = (Get-Date).ToString('s')
    }
    $state | ConvertTo-Json | Set-Content -Path $StateFile -Encoding UTF8
    return $state
}

function Write-TextFile([string]$Path, [string]$Text) {
    # no byte order mark and LF line ends: these files are read on Linux too
    [IO.File]::WriteAllText($Path, $Text.Replace("`r`n", "`n"), (New-Object System.Text.UTF8Encoding($false)))
}

# --- network ----------------------------------------------------------------------------------------------------------

function Get-MainInterface {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1
    if (-not $route) { throw 'This computer has no default route. Connect it to the network first.' }
    $address = Get-NetIPAddress -InterfaceIndex $route.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.AddressState -eq 'Preferred' } | Select-Object -First 1
    if (-not $address) { throw "The network adapter of the default route has no IPv4 address." }
    return [pscustomobject]@{
        Index        = $route.ifIndex
        Gateway      = $route.NextHop
        Address      = $address.IPAddress
        PrefixLength = $address.PrefixLength
        Dhcp         = ($address.PrefixOrigin -eq 'Dhcp')
    }
}

function Get-MainDnsServers {
    $main = Get-MainInterface
    return @((Get-DnsClientServerAddress -InterfaceIndex $main.Index -AddressFamily IPv4).ServerAddresses)
}

function Set-StaticAddress([ipaddress]$Address) {
    if ($Address.AddressFamily -ne 'InterNetwork') { throw "$Address isn't an IPv4 address." }
    $main = Get-MainInterface
    if ($main.Address -eq $Address.IPAddressToString -and -not $main.Dhcp) { return }
    $dns = Get-MainDnsServers
    Write-Step "Giving this computer the fixed address $Address/$($main.PrefixLength), gateway $($main.Gateway)"
    Set-NetIPInterface -InterfaceIndex $main.Index -Dhcp Disabled
    Get-NetIPAddress -InterfaceIndex $main.Index -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false
    Get-NetRoute -InterfaceIndex $main.Index -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false
    New-NetIPAddress -InterfaceIndex $main.Index -IPAddress $Address.IPAddressToString `
        -PrefixLength $main.PrefixLength -DefaultGateway $main.Gateway | Out-Null
    if ($dns) { Set-DnsClientServerAddress -InterfaceIndex $main.Index -ServerAddresses $dns }
    Write-Done 'done'
}

function Set-DnsForwarders($Ctx) {
    # the domain controller is its own DNS server now: other names go to the DNS servers it had before
    $servers = @($Ctx.State.DnsServers | Where-Object { $_ -and $_ -notlike '127.*' -and $_ -ne $Ctx.Address })
    if (-not $servers) { return }
    try {
        $forwarder = Get-DnsServerForwarder
        if ($forwarder -and $forwarder.IPAddress) { return }
        Set-DnsServerForwarder -IPAddress $servers
        Write-Step "DNS forwards other names to $($servers -join ', ')"
    } catch {
        Write-Warn "Couldn't set the DNS forwarders: $($_.Exception.Message)"
    }
}

# --- Windows ----------------------------------------------------------------------------------------------------------

function Test-WindowsCopy {
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Step "$($os.Caption), build $($os.BuildNumber), $($os.OSArchitecture)"
    if ($os.ProductType -eq 1) { throw "This is $($os.Caption). Run this script on Windows Server." }
    $license = Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction SilentlyContinue `
        -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" |
        Select-Object -First 1
    if (-not $license) { return }
    $end = $license.EvaluationEndDate
    if ($end -and $end.Year -gt 2000) {
        if ($end -lt (Get-Date)) {
            $text = "This preview of Windows expired on $($end.ToString('d MMMM yyyy')). It may restart by itself " +
                'from time to time, which makes a poor domain controller.'
            if (-not $IgnoreExpiry) { throw "$text Use a current build, or run this script with -IgnoreExpiry." }
            Write-Warn $text
        } else {
            Write-Done "This copy of Windows stops working on $($end.ToString('d MMMM yyyy'))."
        }
    }
    if ($license.GracePeriodRemaining -gt 0) {
        Write-Done ('Activation or evaluation period: {0} days left.' -f [math]::Floor($license.GracePeriodRemaining / 1440))
    }
}

# --- the domain -------------------------------------------------------------------------------------------------------

function Wait-ForDirectory {
    for ($i = 0; $i -lt 30; $i++) {
        try {
            Get-ADDomain -Server localhost | Out-Null
            return
        } catch {
            if ($i -eq 0) { Write-Host '    Waiting for Active Directory to start...' }
            Start-Sleep -Seconds 10
        }
    }
    throw "Active Directory didn't answer within 5 minutes."
}

function Get-LabContext {
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.DomainRole -lt 4) {
        throw "This computer isn't a domain controller yet. Run this script without -Action first."
    }
    if ($computer.Domain -ne $DomainName) {
        throw "This is a domain controller of $($computer.Domain), not of the lab domain $DomainName. " +
            'This script only changes its own lab domain.'
    }
    Import-Module ActiveDirectory -Verbose:$false
    Wait-ForDirectory
    $domain = Get-ADDomain
    $state = Get-LabState
    return [pscustomobject]@{
        DomainDN = $domain.DistinguishedName
        OuDN     = "OU=$OuName,$($domain.DistinguishedName)"
        Fqdn     = (Get-ADDomainController -Identity $env:COMPUTERNAME).HostName.ToLower()
        Address  = (Get-MainInterface).Address
        State    = $state
        Password = ConvertTo-SecureString $state.Password -AsPlainText -Force
    }
}

function Start-Lab {
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.DomainRole -ge 4) {
        Complete-Lab
        return
    }
    if ($computer.PartOfDomain) {
        throw "This computer is a member of $($computer.Domain). Use a new Windows Server that isn't in a domain."
    }
    Test-WindowsCopy
    if (-not (Test-Path $StateFile)) {
        Write-Host ''
        Write-Warn "This turns this computer into $ComputerName, the domain controller of a new test domain"
        Write-Warn "$DomainName, with test accounts that share one password. Only do this on a VM made for testing."
        if ((Read-Host '    Type yes to go on') -ne 'yes') { throw 'Nothing was changed.' }
    }
    $state = Get-LabState
    if ($IPAddress) {
        Set-StaticAddress $IPAddress
    } elseif ((Get-MainInterface).Dhcp) {
        Write-Warn 'This computer gets its address from DHCP. A domain controller should keep the same address:'
        Write-Warn 'run this script with -IPAddress, or reserve the address in your DHCP server or cloud console.'
    }
    if ($env:COMPUTERNAME -ne $ComputerName) {
        Write-Step "Renaming this computer to $ComputerName"
        Rename-Computer -NewName $ComputerName -Force -WarningAction SilentlyContinue
        Write-Warn 'Restarting in 15 seconds. After the restart, log in and run this script again.'
        Start-Sleep -Seconds 15
        Restart-Computer -Force
        return
    }
    Write-Step 'Installing Active Directory Domain Services'
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
    Write-Step "Creating the domain $DomainName ($NetbiosName)"
    Write-Warn "The computer restarts by itself at the end. Then log in as $NetbiosName\$env:USERNAME, with the same"
    Write-Warn 'password, and run this script again.'
    Import-Module ADDSDeployment -Verbose:$false
    Install-ADDSForest -DomainName $DomainName -DomainNetbiosName $NetbiosName -InstallDns `
        -SafeModeAdministratorPassword (ConvertTo-SecureString $state.Password -AsPlainText -Force) `
        -Force -WarningAction SilentlyContinue | Out-Null
}

function Complete-Lab {
    $ctx = Get-LabContext
    Set-DnsForwarders $ctx
    Set-LabAccounts $ctx
    Install-LabCa
    Wait-ForDcCertificate $ctx.Fqdn | Out-Null

    Write-Step "LDAPS on $($ctx.Fqdn):636"
    $remote = $null
    $problem = $null
    for ($i = 0; $i -lt 12 -and -not $remote; $i++) {
        try {
            $remote = Test-Ldaps $ctx.Fqdn
        } catch {
            $problem = $_.Exception.Message
            Start-Sleep -Seconds 5
        }
    }
    if (-not $remote) { throw "LDAPS doesn't work: $problem Restart the computer and run this script again." }
    Write-Done "works, with the certificate for $(($remote.DnsNameList | ForEach-Object { $_.Unicode }) -join ', ')"

    $ca = Export-LabCa
    Write-Done "CA certificate saved in $CaFile, valid until $($ca.NotAfter.ToString('d MMMM yyyy'))"
    Enable-NetFirewallRule -DisplayGroup 'Active Directory Domain Services' -ErrorAction SilentlyContinue

    Save-LabFiles $ctx
    Show-AccountStates $ctx
    Write-Host (Get-LabInfoText $ctx)
    Write-Host ''
    Write-Host "The lab is ready. This information is also in $InfoFile." -ForegroundColor Green
}

# --- accounts ---------------------------------------------------------------------------------------------------------

function Set-LabGroup($Ctx, [string]$Name, [string]$Description) {
    if (-not (Get-ADGroup -Filter "Name -eq '$Name'")) {
        New-ADGroup -Name $Name -SamAccountName $Name -GroupScope Global -GroupCategory Security -Path $Ctx.OuDN `
            -Description $Description
    }
}

function Set-GroupMembers([string]$Group, [string[]]$Want) {
    $have = @(Get-ADGroupMember -Identity $Group | ForEach-Object { $_.SamAccountName })
    $add = @($Want | Where-Object { $have -notcontains $_ })
    $remove = @($have | Where-Object { $Want -notcontains $_ })
    if ($add.Count) { Add-ADGroupMember -Identity $Group -Members $add }
    if ($remove.Count) { Remove-ADGroupMember -Identity $Group -Members $remove -Confirm:$false }
}

function Set-LabUser($Ctx, $Spec) {
    $sam = $Spec.Sam
    $name = "$($Spec.Given) $($Spec.Surname)"
    if (Get-ADUser -Filter "SamAccountName -eq '$sam'") {
        Set-ADAccountPassword -Identity $sam -Reset -NewPassword $Ctx.Password
    } else {
        New-ADUser -Name $name -SamAccountName $sam -UserPrincipalName "$sam@$DomainName" -GivenName $Spec.Given `
            -Surname $Spec.Surname -DisplayName $name -Path $Ctx.OuDN -AccountPassword $Ctx.Password -Enabled $true
    }
    Set-ADUser -Identity $sam -PasswordNeverExpires $false
    Set-ADUser -Identity $sam -ChangePasswordAtLogon $Spec.MustChange
    Unlock-ADAccount -Identity $sam
    if ($Spec.Enabled) { Enable-ADAccount -Identity $sam } else { Disable-ADAccount -Identity $sam }
}

function Add-PolicySubject([string]$Policy, [string]$Subject) {
    $have = @(Get-ADFineGrainedPasswordPolicySubject -Identity $Policy | ForEach-Object { $_.SamAccountName })
    if ($have -notcontains $Subject) { Add-ADFineGrainedPasswordPolicySubject -Identity $Policy -Subjects $Subject }
}

function New-LabPolicy([string]$Name, [int]$Precedence, [string]$MaxPasswordAge) {
    if (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$Name'") { return }
    New-ADFineGrainedPasswordPolicy -Name $Name -Precedence $Precedence -ComplexityEnabled $true `
        -MinPasswordLength 8 -PasswordHistoryCount 0 -MinPasswordAge '00:00:00' -MaxPasswordAge $MaxPasswordAge `
        -ReversibleEncryptionEnabled $false -LockoutThreshold $LockoutThreshold -LockoutDuration '00:05:00' `
        -LockoutObservationWindow '00:05:00' -ProtectedFromAccidentalDeletion $false
}

function Set-LabAccounts($Ctx) {
    Write-Step "Test accounts in OU=$OuName"
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$OuName'" -SearchBase $Ctx.DomainDN -SearchScope OneLevel)) {
        New-ADOrganizationalUnit -Name $OuName -Path $Ctx.DomainDN -ProtectedFromAccidentalDeletion $false
    }
    Set-LabGroup $Ctx $VpnGroup 'The VPN users of Authway Server'
    Set-LabGroup $Ctx $NestedGroup "Inside $VpnGroup, to test groups in the group"
    Set-LabGroup $Ctx $AllGroup 'Every test account, for the lab password policy'

    $everyone = @($ServiceUser) + $People + $Bulk
    foreach ($spec in $everyone) { Set-LabUser $Ctx $spec }

    $members = @($People | Where-Object { $_.Member } | ForEach-Object { $_.Sam }) +
        @($Bulk | ForEach-Object { $_.Sam }) + @($NestedGroup)
    Set-GroupMembers $VpnGroup $members
    Set-GroupMembers $NestedGroup @('bob')
    Set-GroupMembers $AllGroup @($everyone | ForEach-Object { $_.Sam })

    # A password policy of their own, rather than a change to the domain's: the Default Domain Policy would undo that.
    New-LabPolicy $LabPolicy 20 '365.00:00:00'
    Add-PolicySubject $LabPolicy $AllGroup
    Write-Done "$($everyone.Count) accounts, all with the lab password. Their passwords last 365 days, and"
    Write-Done "$LockoutThreshold wrong passwords within 5 minutes lock an account for 5 minutes."
}

# --- certificates -----------------------------------------------------------------------------------------------------

function Install-LabCa {
    Write-Step "Certificate Services, with the certificate authority $CaName"
    if (-not (Get-WindowsFeature ADCS-Cert-Authority).Installed) {
        Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Out-Null
    }
    if (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -ErrorAction SilentlyContinue) {
        Write-Done 'already set up'
        return
    }
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CACommonName $CaName -KeyLength 2048 `
        -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 10 -Force | Out-Null
    Write-Done 'installed'
}

function Get-DcCertificate([string]$Fqdn) {
    return Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and
        ($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.1' }) -and
        ($_.DnsNameList | Where-Object { $_.Unicode -eq $Fqdn })
    } | Sort-Object NotAfter -Descending | Select-Object -First 1
}

function Wait-ForDcCertificate([string]$Fqdn) {
    Write-Step 'A certificate for the domain controller, for LDAPS'
    $cert = Get-DcCertificate $Fqdn
    if (-not $cert) {
        # domain controllers ask the new certificate authority for one by themselves; this makes it happen now
        & certutil.exe -pulse | Out-Null
        for ($i = 0; $i -lt 12 -and -not $cert; $i++) {
            Start-Sleep -Seconds 10
            $cert = Get-DcCertificate $Fqdn
        }
    }
    if (-not $cert) {
        foreach ($template in 'KerberosAuthentication', 'DomainControllerAuthentication', 'DomainController') {
            try {
                Get-Certificate -Template $template -CertStoreLocation Cert:\LocalMachine\My | Out-Null
                break
            } catch {
                Write-Warn "Couldn't get a certificate from the template $($template): $($_.Exception.Message)"
            }
        }
        $cert = Get-DcCertificate $Fqdn
    }
    if (-not $cert) { throw "The domain controller didn't get a certificate. Restart it and run this script again." }
    Write-Done "valid until $($cert.NotAfter.ToString('d MMMM yyyy')), issued by $($cert.Issuer)"
    try {
        # tells Active Directory to use the newest certificate now, instead of at the next restart
        $rootDse = [ADSI]'LDAP://localhost/RootDSE'
        $rootDse.Put('renewServerCertificate', 1)
        $rootDse.SetInfo()
    } catch { }
    return $cert
}

function Test-Ldaps([string]$Fqdn) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $tcp.Connect($Fqdn, 636)
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false)
        try {
            # checks the name and the chain the way Authway Server does, with the CA trusted
            $ssl.AuthenticateAsClient($Fqdn)
            return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        } finally {
            $ssl.Dispose()
        }
    } finally {
        $tcp.Close()
    }
}

function ConvertTo-Pem([byte[]]$Der) {
    $base64 = [Convert]::ToBase64String($Der)
    $lines = for ($i = 0; $i -lt $base64.Length; $i += 64) {
        $base64.Substring($i, [Math]::Min(64, $base64.Length - $i))
    }
    return "-----BEGIN CERTIFICATE-----`n" + ($lines -join "`n") + "`n-----END CERTIFICATE-----`n"
}

function Export-LabCa {
    $ca = Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\My |
        Where-Object { $_.Subject -like "CN=$CaName,*" -and $_.Subject -eq $_.Issuer } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $ca) { throw "Couldn't find the certificate of $CaName." }
    Write-TextFile $CaFile (ConvertTo-Pem $ca.RawData)
    return $ca
}

# --- information --------------------------------------------------------------------------------------------------

function Get-LabInfoText($Ctx) {
    $password = $Ctx.State.Password
    $group = "CN=$VpnGroup,$($Ctx.OuDN)"
    $accounts = @($People | ForEach-Object { '  {0,-12} {1}' -f $_.Sam, $_.Role }) +
        @('  {0,-12} {1}' -f 'bulk01..10', 'members, for the safety limit test (-Action HoldTest)') +
        @('  {0,-12} {1}' -f $Service, 'the service account')
    return @"

Authway Server: Settings > Active Directory
  Domain controllers  $($Ctx.Fqdn)
  Connection          LDAPS (StartTLS works too)
  CA certificate      the contents of $CaFile
  Service account     $Service@$DomainName
  Password            $password
  Search base         $($Ctx.DomainDN)
  VPN users group     $group
  Username            the logon name or the user principal name. With the user principal name, users can
                      log in as alice or alice@$DomainName.

The Docker host has to reach $($Ctx.Fqdn) by that name, on port 636 for LDAPS or 389 for StartTLS.
This computer's address is $($Ctx.Address). On a cloud VM use its public address, and open those ports to the
Docker host only. Add the name to ~/authway-server/compose.override.yaml, then run docker compose up -d:

  services:
    authway-server:
      extra_hosts:
        - "$($Ctx.Fqdn):$($Ctx.Address)"

Test accounts, all with the password $password
$($accounts -join "`n")

Tests: run this script with
  -Action Lock               to lock erin out
  -Action HoldTest           to disable bulk01 to bulk0$($HoldCount): the next sync should hold them back
  -Action ServiceExpirySoon  so the service password expires in 10 days: Authway Server should warn
  -Action ServiceExpired     so the service account must change its password: syncs should fail
  -Action Reset              to put every test account back as it started
  -Action Info               to show this again, with the state of each account

The Go integration test: copy integration-test.env and authway-lab-ca.pem from $LabDir next to
the source on the Docker host, then run there
  docker run --rm --env-file integration-test.env -v "`$PWD/authway-lab-ca.pem":/ca.pem:ro \
    --add-host $($Ctx.Fqdn):$($Ctx.Address) -v "`$PWD":/src -w /src golang:1.27-alpine \
    go test -count=1 -run TestAgainstDirectory -v ./internal/directory
Add -e AUTHWAY_TEST_AD_SECURITY=starttls to test StartTLS. It locks erin out on purpose.
"@
}

function Save-LabFiles($Ctx) {
    $password = $Ctx.State.Password
    $variables = @(
        "AUTHWAY_TEST_AD_SERVERS=$($Ctx.Fqdn)"
        'AUTHWAY_TEST_AD_SECURITY=ldaps'
        'AUTHWAY_TEST_AD_CA=/ca.pem'
        "AUTHWAY_TEST_AD_BIND_USER=$Service@$DomainName"
        "AUTHWAY_TEST_AD_BIND_PASSWORD=$password"
        "AUTHWAY_TEST_AD_BASE=$($Ctx.DomainDN)"
        "AUTHWAY_TEST_AD_GROUP=CN=$VpnGroup,$($Ctx.OuDN)"
        'AUTHWAY_TEST_AD_USER=alice'
        "AUTHWAY_TEST_AD_PASSWORD=$password"
        'AUTHWAY_TEST_AD_NESTED=bob'
        'AUTHWAY_TEST_AD_DISABLED=carol'
        'AUTHWAY_TEST_AD_OUTSIDE=dave'
        'AUTHWAY_TEST_AD_MUST_CHANGE=frank'
        "AUTHWAY_TEST_AD_MUST_CHANGE_PASSWORD=$password"
        'AUTHWAY_TEST_AD_LOCK=erin'
        "AUTHWAY_TEST_AD_LOCK_TRIES=$LockoutThreshold"
        'AUTHWAY_TEST_AD_DEAD=192.0.2.1'
    )
    Write-TextFile $EnvFile (($variables -join "`n") + "`n")
    Write-TextFile $InfoFile (Get-LabInfoText $Ctx)
}

function Show-AccountStates($Ctx) {
    $members = @(Get-ADGroupMember -Identity $VpnGroup -Recursive | ForEach-Object { $_.SamAccountName })
    $users = Get-ADUser -Filter * -SearchBase $Ctx.OuDN -Properties LockedOut, pwdLastSet,
        'msDS-UserPasswordExpiryTimeComputed' | Sort-Object SamAccountName
    $rows = foreach ($user in $users) {
        $expiry = $user.'msDS-UserPasswordExpiryTimeComputed'
        if ($user.pwdLastSet -eq 0) {
            $expires = 'must change'
        } elseif (-not $expiry -or $expiry -ge [long]::MaxValue) {
            $expires = 'never'
        } else {
            $expires = [DateTime]::FromFileTime($expiry).ToString('yyyy-MM-dd HH:mm')
        }
        [pscustomobject]@{
            Username           = $user.SamAccountName
            'In VPN Users'     = $members -contains $user.SamAccountName
            Enabled            = $user.Enabled
            'Locked out'       = $user.LockedOut
            'Password expires' = $expires
        }
    }
    Write-Step 'The test accounts now'
    Write-Host ($rows | Format-Table -AutoSize | Out-String).TrimEnd()
}

# --- tests ------------------------------------------------------------------------------------------------------------

function Invoke-Lock($Ctx) {
    Write-Step 'Locking erin out with wrong passwords'
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    for ($i = 1; $i -le $LockoutThreshold + 2; $i++) {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($Ctx.Fqdn)
        $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
        $connection.Credential = New-Object System.Net.NetworkCredential('erin', "wrong password $i", $NetbiosName)
        try { $connection.Bind() } catch { } finally { $connection.Dispose() }
        if ((Get-ADUser -Identity 'erin' -Properties LockedOut).LockedOut) {
            Write-Done "Locked out after $i wrong passwords, for 5 minutes or until -Action Reset."
            return
        }
    }
    Write-Warn "erin still isn't locked out after $($LockoutThreshold + 2) wrong passwords."
}

function Invoke-HoldTest($Ctx) {
    $names = @($Bulk | Select-Object -First $HoldCount | ForEach-Object { $_.Sam })
    Write-Step "Disabling $($names -join ', ')"
    foreach ($name in $names) { Disable-ADAccount -Identity $name }
    Write-Done 'Click Sync now in Authway Server: it should disable none of them and ask you to confirm.'
    Write-Done '-Action Reset enables them again.'
}

function Invoke-ServiceExpirySoon($Ctx) {
    Write-Step "The password of $Service expires in 10 days"
    New-LabPolicy $SoonPolicy 10 '10.00:00:00'
    Add-PolicySubject $SoonPolicy $Service
    Set-ADAccountPassword -Identity $Service -Reset -NewPassword $Ctx.Password
    Set-ADUser -Identity $Service -ChangePasswordAtLogon $false
    $expiry = (Get-ADUser -Identity $Service -Properties 'msDS-UserPasswordExpiryTimeComputed').'msDS-UserPasswordExpiryTimeComputed'
    Write-Done "It expires on $([DateTime]::FromFileTime($expiry).ToString('d MMMM yyyy HH:mm'))."
    Write-Done 'Click Sync now in Authway Server: a warning about it should appear. -Action Reset puts it back.'
}

function Invoke-ServiceExpired($Ctx) {
    Write-Step "$Service must change its password"
    Set-ADUser -Identity $Service -ChangePasswordAtLogon $true
    Write-Done 'Click Sync now in Authway Server: it should fail with "its password has expired". After two failed'
    Write-Done 'syncs, a warning appears at the top of every page. -Action Reset puts it back.'
}

function Invoke-Reset($Ctx) {
    if (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$SoonPolicy'") {
        $subjects = @(Get-ADFineGrainedPasswordPolicySubject -Identity $SoonPolicy | ForEach-Object { $_.SamAccountName })
        if ($subjects -contains $Service) {
            Remove-ADFineGrainedPasswordPolicySubject -Identity $SoonPolicy -Subjects $Service -Confirm:$false
        }
    }
    Set-LabAccounts $Ctx
    Show-AccountStates $Ctx
}

# --- main -------------------------------------------------------------------------------------------------------------

try {
    switch ($Action) {
        'Setup' { Start-Lab }
        'Info' {
            $ctx = Get-LabContext
            Show-AccountStates $ctx
            Write-Host (Get-LabInfoText $ctx)
        }
        'Lock' { Invoke-Lock (Get-LabContext) }
        'HoldTest' { Invoke-HoldTest (Get-LabContext) }
        'ServiceExpirySoon' { Invoke-ServiceExpirySoon (Get-LabContext) }
        'ServiceExpired' { Invoke-ServiceExpired (Get-LabContext) }
        'Reset' { Invoke-Reset (Get-LabContext) }
    }
} catch {
    Write-Host ''
    Write-Host "Stopped: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    exit 1
}
