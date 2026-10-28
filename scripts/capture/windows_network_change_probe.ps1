param(
    [Parameter(Mandatory)][string]$DevGenPath,
    [Parameter(Mandatory)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Network-State {
    $state = [ordered]@{
        adapters = @(Get-NetAdapter -IncludeHidden | Sort-Object InterfaceGuid |
            Select-Object InterfaceGuid, InterfaceIndex, PnPDeviceID, Name, InterfaceDescription,
                InterfaceType, InterfaceAdminStatus, InterfaceOperationalStatus)
        dns = @(Get-DnsClientServerAddress | Sort-Object InterfaceIndex, AddressFamily |
            Select-Object InterfaceIndex, AddressFamily, ServerAddresses)
    }
    foreach ($store in @('ActiveStore', 'PersistentStore')) {
        $state["addresses_$store"] = @(Get-NetIPAddress -PolicyStore $store |
            Sort-Object InterfaceIndex, AddressFamily, IPAddress |
            Select-Object InterfaceIndex, AddressFamily, IPAddress, PrefixLength, Type,
                PrefixOrigin, SuffixOrigin, SkipAsSource)
        $state["interfaces_$store"] = @(Get-NetIPInterface -PolicyStore $store |
            Sort-Object InterfaceIndex, AddressFamily |
            Select-Object InterfaceIndex, AddressFamily, Dhcp, InterfaceMetric)
        $state["default_routes_$store"] = @(Get-NetRoute -PolicyStore $store |
            Where-Object DestinationPrefix -In @('0.0.0.0/0', '::/0') |
            Sort-Object InterfaceIndex, DestinationPrefix, NextHop, RouteMetric |
            Select-Object InterfaceIndex, DestinationPrefix, NextHop, RouteMetric, Protocol)
    }
    return $state
}

function Save-Result {
    $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath "$resultPath.tmp" -Encoding utf8
    Move-Item -LiteralPath "$resultPath.tmp" -Destination $resultPath -Force
}

if ((Test-Path -LiteralPath $OutputDirectory) -and @(Get-ChildItem -LiteralPath $OutputDirectory -Force).Count -ne 0) {
    throw 'probe output directory is not empty; use a fresh output directory'
}
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$resultPath = Join-Path $OutputDirectory 'result.json'
$nonce = "phantom-network-$([Guid]::NewGuid().ToString('N'))"
$instanceId = "SWD\DEVGEN\$nonce"
$address = '192.0.2.123'
$result = [ordered]@{
    nonce = $nonce; instance_id_intent = $instanceId; discovered_instance_id = $null
    stage = 'preflight'; primary_error = $null; cleanup_errors = @(); passed = $false
    baseline = $null; final = $null; baseline_pnp = @(); final_pnp = @(); adapter = $null; unicast = @()
    add_pid = $null; add_exit_code = $null; add_exit_observed = $false
    remove_pid = $null; remove_exit_code = $null; remove_exit_observed = $false
    cleanup_verified = $false; address_added = $false
}
$add = $null
$remove = $null
$launchAttempted = $false
try {
    if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
        $env:RUNNER_OS -ne 'Windows' -or $env:ImageOS -cnotin @('win25', 'win25-vs2026')) {
        throw 'probe requires a fresh GitHub-hosted Windows 2025 runner'
    }
    $system = Get-CimInstance Win32_OperatingSystem
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($system.ProductType -eq 1 -or $system.BuildNumber -ne '26100' -or
        -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'probe requires elevated Windows Server 2025 build 26100'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $DevGenPath
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,' -or
        (Get-FileHash -LiteralPath $DevGenPath -Algorithm SHA256).Hash -ne
            'ad37b38853566b750bf4b6cb21eefe771e567e6cdb9c7a79c716a0e64bd23170') {
        throw 'DevGen must be the pinned Microsoft-signed WDK 10.0.26100.6584 tool'
    }
    $result.baseline_pnp = @(Get-PnpDevice | Sort-Object InstanceId | Select-Object InstanceId, Class, Status)
    $result.baseline = Network-State
    if ($instanceId -in $result.baseline_pnp.InstanceId -or
        $address -in @($result.baseline.addresses_ActiveStore | ForEach-Object IPAddress) -or
        $address -in @($result.baseline.addresses_PersistentStore | ForEach-Object IPAddress)) {
        throw 'owned device or documentation address collides with the baseline'
    }
    $result.stage = 'provisioning'
    # Journal exact intent before launch. /wait is independent cleanup if this script dies.
    # https://learn.microsoft.com/windows-hardware/drivers/devtest/devgen-command-syntax
    Save-Result
    $addDeadline = [DateTime]::UtcNow.AddSeconds(105)
    $launchAttempted = $true
    $add = Start-Process -FilePath $DevGenPath -WindowStyle Hidden -PassThru -ArgumentList @(
        '/add', '/bus', 'SWD', '/instanceid', $nonce, '/hardwareid', '*MSLOOP', '/wait', '90000'
    ) -RedirectStandardOutput (Join-Path $OutputDirectory 'add.stdout') -RedirectStandardError (Join-Path $OutputDirectory 'add.stderr')
    $null = $add.Handle
    $result.add_pid = $add.Id
    Save-Result
    $deadline = [DateTime]::UtcNow.AddSeconds(25)
    do {
        $devices = @(Get-PnpDevice | Where-Object InstanceId -EQ $instanceId)
        if ($devices.Count -eq 1) {
            $result.discovered_instance_id = [string]$devices[0].InstanceId
            Save-Result
        }
        $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object PnPDeviceID -EQ $instanceId)
        if ($devices.Count -eq 1 -and $adapters.Count -eq 1) { break }
        if ($add.HasExited -or [DateTime]::UtcNow -ge $deadline) {
            throw 'exact owned device did not expose one network adapter within 25 seconds'
        }
        Start-Sleep -Milliseconds 500
    } while ($true)
    $adapter = $adapters[0]
    $result.adapter = $adapter | Select-Object InterfaceGuid, InterfaceIndex, PnPDeviceID,
        Name, InterfaceDescription, InterfaceType, InterfaceAdminStatus, InterfaceOperationalStatus
    Save-Result
    $hardware = @(Get-PnpDeviceProperty -InstanceId $instanceId -KeyName DEVPKEY_Device_HardwareIds)
    if ($hardware.Count -ne 1 -or '*MSLOOP' -notin @($hardware[0].Data) -or
        -not $adapter.InterfaceGuid -or $adapter.InterfaceIndex -le 0 -or
        $adapter.InterfaceIndex -in $result.baseline.adapters.InterfaceIndex -or
        $adapter.InterfaceGuid -in $result.baseline.adapters.InterfaceGuid -or
        $adapter.InterfaceIndex -in @($result.baseline.interfaces_ActiveStore | ForEach-Object InterfaceIndex) -or
        $adapter.InterfaceIndex -in @($result.baseline.interfaces_PersistentStore | ForEach-Object InterfaceIndex)) {
        throw 'new adapter ownership could not be established independently of the baseline'
    }
    $result.stage = 'type'
    if ($adapter.InterfaceType -ne 6) { throw 'owned adapter is not interface type 6' }
    $result.stage = 'up'
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $current = @(Get-NetAdapter -IncludeHidden | Where-Object PnPDeviceID -EQ $instanceId)
        if ($current.Count -ne 1 -or $current[0].InterfaceGuid -ne $adapter.InterfaceGuid -or
            $current[0].InterfaceIndex -ne $adapter.InterfaceIndex -or $add.HasExited) {
            throw 'owned adapter identity or live DevGen owner changed'
        }
        if ($current[0].InterfaceAdminStatus -eq 1 -and $current[0].InterfaceOperationalStatus -eq 1) { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'owned adapter did not become administratively and operationally UP' }
        Start-Sleep -Milliseconds 500
    } while ($true)
    $result.adapter = $current[0] | Select-Object InterfaceGuid, InterfaceIndex, PnPDeviceID,
        Name, InterfaceDescription, InterfaceType, InterfaceAdminStatus, InterfaceOperationalStatus
    $result.stage = 'address'
    $result.unicast = @(Get-NetIPAddress -PolicyStore ActiveStore |
        Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex -and $_.Type -eq 'Unicast' } |
        Select-Object InterfaceIndex, IPAddress, AddressFamily, PrefixLength, Type, AddressState, SkipAsSource)
    if (@($result.unicast | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.AddressState -eq 'Preferred' }).Count -eq 0) {
        $current = @(Get-NetAdapter -IncludeHidden | Where-Object PnPDeviceID -EQ $instanceId)
        if ($current.Count -ne 1 -or $current[0].InterfaceGuid -ne $adapter.InterfaceGuid -or
            $current[0].InterfaceIndex -ne $adapter.InterfaceIndex -or $add.HasExited) {
            throw 'owned adapter identity or live DevGen owner changed before address configuration'
        }
        # Explicit ActiveStore avoids persistence; this can disable DHCP only on this owned NIC.
        $null = New-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -IPAddress $address -AddressFamily IPv4 `
            -PrefixLength 32 -Type Unicast -SkipAsSource $true -PolicyStore ActiveStore
        $result.address_added = $true
        Save-Result
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            $result.unicast = @(Get-NetIPAddress -PolicyStore ActiveStore |
                Where-Object InterfaceIndex -EQ $adapter.InterfaceIndex |
                Select-Object InterfaceIndex, IPAddress, AddressFamily, PrefixLength, Type, AddressState, SkipAsSource)
            if (@($result.unicast | Where-Object {
                $_.IPAddress -eq $address -and $_.PrefixLength -eq 32 -and $_.Type -eq 'Unicast' -and
                $_.SkipAsSource -and $_.AddressState -eq 'Preferred'
            }).Count -eq 1) { break }
            if ($add.HasExited -or [DateTime]::UtcNow -ge $deadline) { throw 'owned /32 unicast address did not become usable' }
            Start-Sleep -Milliseconds 500
        } while ($true)
    }
    $result.stage = 'probe-complete'
}
catch { $result.primary_error = $_.ToString() }
finally {
    # Exact nonce ID also catches an incompletely installed node of an unknown class.
    try {
        if ($launchAttempted -and @(Get-PnpDevice | Where-Object InstanceId -EQ $instanceId).Count -gt 0) {
            if ($instanceId -in $result.baseline_pnp.InstanceId) { throw 'refusing removal of a baseline device' }
            $result.discovered_instance_id = $instanceId
            Save-Result
            $remove = Start-Process -FilePath $DevGenPath -WindowStyle Hidden -PassThru `
                -ArgumentList @('/remove', $instanceId) -RedirectStandardOutput (Join-Path $OutputDirectory 'remove.stdout') `
                -RedirectStandardError (Join-Path $OutputDirectory 'remove.stderr')
            $null = $remove.Handle
            $result.remove_pid = $remove.Id
            Save-Result
            if (-not $remove.WaitForExit(15000)) {
                $remove.Kill()
                $result.remove_exit_observed = $remove.WaitForExit(5000)
                if ($result.remove_exit_observed) { $result.remove_exit_code = $remove.ExitCode }
                throw 'exact-device removal process exceeded 15 seconds'
            }
            $result.remove_exit_observed = $true
            $result.remove_exit_code = $remove.ExitCode
            if ($remove.ExitCode -ne 0) { throw "exact-device removal exited $($remove.ExitCode)" }
        }
    }
    catch { $result.cleanup_errors += $_.ToString() }
    try {
        if ($add) {
            while (-not $add.WaitForExit(1000)) {
                if ([DateTime]::UtcNow -ge $addDeadline) {
                    $add.Kill()
                    $result.add_exit_observed = $add.WaitForExit(5000)
                    if ($result.add_exit_observed) { $result.add_exit_code = $add.ExitCode }
                    throw 'DevGen did not exit within its independent cleanup bound'
                }
            }
            $result.add_exit_observed = $true
            $result.add_exit_code = $add.ExitCode
            if ($add.ExitCode -ne 0) { throw "DevGen add/wait exited $($add.ExitCode)" }
        }
    }
    catch { $result.cleanup_errors += $_.ToString() }
    try {
        if ($result.baseline) {
            $deadline = [DateTime]::UtcNow.AddSeconds(15)
            do {
                $result.final_pnp = @(Get-PnpDevice | Sort-Object InstanceId | Select-Object InstanceId, Class, Status)
                $remaining = @($result.final_pnp | Where-Object InstanceId -EQ $instanceId)
                $samePnp = (ConvertTo-Json -InputObject @($result.baseline_pnp | ForEach-Object InstanceId) -Compress) -ceq
                    (ConvertTo-Json -InputObject @($result.final_pnp | ForEach-Object InstanceId) -Compress)
                $result.final = Network-State
                $same = ($result.baseline | ConvertTo-Json -Depth 12 -Compress) -ceq
                    ($result.final | ConvertTo-Json -Depth 12 -Compress)
                if ($remaining.Count -eq 0 -and $samePnp -and $same) { $result.cleanup_verified = $true; break }
                if ([DateTime]::UtcNow -ge $deadline) { throw 'exact PnP identities and network baseline restoration were not both verified' }
                Start-Sleep -Milliseconds 500
            } while ($true)
        }
    }
    catch { $result.cleanup_errors += $_.ToString() }
    $result.passed = $result.stage -eq 'probe-complete' -and -not $result.primary_error -and
        $result.cleanup_errors.Count -eq 0 -and $result.cleanup_verified -and $result.add_exit_observed
    Save-Result
    if ($remove) { $remove.Dispose() }
    if ($add) { $add.Dispose() }
}
$result | ConvertTo-Json -Depth 12
if (-not $result.passed) { exit 1 }
