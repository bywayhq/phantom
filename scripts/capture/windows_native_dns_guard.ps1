param(
    [Parameter(Mandatory)][ValidateSet('Preflight','Identity','Install','Watch','Restore','Verify')][string]$Action,
    [Parameter(Mandatory)][string]$StatePath,
    [int]$OwnerPid,
    [string]$Executable
)

$ErrorActionPreference = 'Stop'
$TargetName = '127.0.0.1.nip.io'
$DnsAddress = '127.0.0.53'

function Assert-Hosted {
    if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
        $env:RUNNER_OS -ne 'Windows' -or $env:ImageOS -ne 'win25') {
        throw 'native DNS guard requires hosted windows-2025'
    }
    $system = Get-CimInstance Win32_OperatingSystem
    if ($system.ProductType -eq 1 -or $system.BuildNumber -ne '26100') {
        throw 'native DNS guard requires Windows Server 2025 build 26100'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'native DNS guard requires an administrator'
    }
    return @{ caption = $system.Caption; build = $system.BuildNumber; product_type = $system.ProductType }
}

function Save-State($State) {
    $temporary = "$StatePath.$PID.tmp"
    $State | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporary -Encoding utf8
    Move-Item -LiteralPath $temporary -Destination $StatePath -Force
}

function Read-State {
    return Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
}

function Rules {
    return @(Get-DnsClientNrptRule | Sort-Object Name | Select-Object Name, Namespace, NameServers,
        DisplayName, Comment, DnsSecEnable, DnsSecValidationRequired, DnsSecQueryIPsecEncryption,
        DnsSecQueryIPsecRequired, DirectAccessEnabled, DirectAccessProxyName, DirectAccessProxyType,
        DirectAccessDnsServers, DirectAccessQueryIPsecEncryption, DirectAccessQueryIPsecRequired,
        IPsecCARestriction)
}

function Canonical($Value) {
    return ConvertTo-Json -InputObject @($Value) -Depth 12 -Compress
}

function Owned-Rules($State) {
    return @(Get-DnsClientNrptRule | Where-Object {
        $_.DisplayName -eq $State.nonce -and $_.Comment -eq $State.nonce -and
        (Canonical @($_.Namespace)) -eq (Canonical @($TargetName)) -and
        (Canonical @($_.NameServers)) -eq (Canonical @($DnsAddress))
    })
}

function Restore-Owned {
    $state = Read-State
    if ($state.hostname -ne $TargetName -or $state.server -ne $DnsAddress -or
        $state.nonce -notmatch '^phantom-native-dns-[0-9a-f-]{36}$') {
        throw 'NRPT restoration intent is outside the owned capture scope'
    }
    foreach ($rule in @(Owned-Rules $state)) {
        if (@($state.baseline | Where-Object { $_.Name -eq $rule.Name }).Count -ne 0) {
            throw 'refusing to remove a baseline NRPT rule'
        }
        if ($state.rule_name -and $rule.Name -ne $state.rule_name) {
            throw 'owned NRPT rule identity differs from recorded GUID'
        }
        Remove-DnsClientNrptRule -Name $rule.Name -Force
    }
    $current = @(Rules)
    if ((Canonical $current) -ne (Canonical $state.baseline)) {
        throw 'NRPT baseline differs after owned-rule removal'
    }
    $state.restored = $true
    $state.restored_at = [DateTime]::UtcNow.ToString('o')
    Save-State $state
    return @{ restored = $true; nonce = $state.nonce; rule_name = $state.rule_name; rules = $current }
}

Assert-Hosted | Out-Null

if ($Action -eq 'Preflight') {
    @{ host = (Assert-Hosted); rules = @(Rules); policy = @(Get-DnsClientNrptPolicy -Effective);
       dns_servers = @(Get-DnsClientServerAddress) } | ConvertTo-Json -Depth 12
    exit 0
}
if ($Action -eq 'Identity') {
    $signature = Get-AuthenticodeSignature -LiteralPath $Executable
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '^CN=Mozilla Corporation,') {
        throw 'Firefox Authenticode signature is not valid Mozilla Corporation'
    }
    $directory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Executable)) + [IO.Path]::DirectorySeparatorChar
    $processes = @(Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -and $_.ExecutablePath.StartsWith($directory, [StringComparison]::OrdinalIgnoreCase)
    } | Select-Object ProcessId, ParentProcessId, ExecutablePath)
    @{ status = [string]$signature.Status; subject = $signature.SignerCertificate.Subject;
       thumbprint = $signature.SignerCertificate.Thumbprint; sha256 = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash;
       staged_processes = $processes } |
        ConvertTo-Json -Depth 4
    exit 0
}

if ($Action -eq 'Watch') {
    # This process is outside the browser JobObject and outlives a Python crash.
    $ready = "$StatePath.ready"
    Set-Content -LiteralPath $ready -Value $PID -Encoding ascii
    while ($true) {
        $state = Read-State
        if ($state.restored) { exit 0 }
        $owner = Get-Process -Id $state.owner_pid -ErrorAction SilentlyContinue
        $sameOwner = $false
        if ($owner) {
            try { $sameOwner = $owner.StartTime.ToUniversalTime() -eq ([DateTime]$state.owner_start).ToUniversalTime() }
            catch {
                # The process can exit after discovery, before reading its identity.
                @{ kind = 'owner-identity-unavailable'; owner_pid = $state.owner_pid; error = $_.ToString() } |
                    ConvertTo-Json -Compress | Write-Output
            }
        }
        if (-not $sameOwner -or [DateTime]::UtcNow -ge [DateTime]::Parse($state.deadline)) { break }
        Start-Sleep -Seconds 1
    }
}

$lock = $null
$limit = [DateTime]::UtcNow.AddSeconds(20)
while (-not $lock) {
    try { $lock = [IO.File]::Open("$StatePath.lock", 'OpenOrCreate', 'ReadWrite', 'None') }
    catch [IO.IOException] {
        if ([DateTime]::UtcNow -ge $limit) { throw }
        Start-Sleep -Milliseconds 100
    }
}
try {
    if ($Action -eq 'Install') {
        if (Test-Path -LiteralPath $StatePath) { throw 'NRPT state already exists' }
        $baseline = @(Rules)
        foreach ($rule in @(Get-DnsClientNrptPolicy -Effective) + $baseline) {
            foreach ($namespace in @($rule.Namespace)) {
                if ($namespace -eq $TargetName -or $namespace -eq '.' -or
                    ($namespace.StartsWith('.') -and $TargetName.EndsWith($namespace))) {
                    throw 'an existing NRPT namespace applies to the capture hostname'
                }
            }
        }
        $owner = Get-Process -Id $OwnerPid
        $state = [pscustomobject]@{
            nonce = "phantom-native-dns-$([Guid]::NewGuid())"; hostname = $TargetName;
            server = $DnsAddress; baseline = $baseline; rule_name = $null;
            owner_pid = $OwnerPid; owner_start = $owner.StartTime.ToUniversalTime().ToString('o');
            deadline = [DateTime]::UtcNow.AddMinutes(5).ToString('o'); restored = $false; restored_at = $null;
            watchdog_pid = $null; watchdog_start = $null
        }
        Save-State $state
        $script = $PSCommandPath
        $watch = Start-Process -FilePath (Get-Process -Id $PID).Path -WindowStyle Hidden -PassThru -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-File', "`"$script`"", '-Action', 'Watch', '-StatePath', "`"$StatePath`""
        ) -RedirectStandardOutput "$StatePath.watch.stdout" -RedirectStandardError "$StatePath.watch.stderr"
        $state.watchdog_pid = $watch.Id
        $state.watchdog_start = $watch.StartTime.ToUniversalTime().ToString('o')
        Save-State $state
        $readyLimit = [DateTime]::UtcNow.AddSeconds(10)
        while (-not (Test-Path -LiteralPath "$StatePath.ready")) {
            if ($watch.HasExited -or [DateTime]::UtcNow -ge $readyLimit) { throw 'NRPT watchdog did not arm' }
            Start-Sleep -Milliseconds 100
        }
        if ([int](Get-Content -LiteralPath "$StatePath.ready") -ne $watch.Id -or $watch.HasExited) {
            throw 'NRPT watchdog readiness identity differs'
        }
        $rule = Add-DnsClientNrptRule -Namespace $TargetName -NameServers $DnsAddress -DisplayName $state.nonce -Comment $state.nonce -PassThru
        $state.rule_name = [string]$rule.Name
        Save-State $state
        if (@(Owned-Rules $state).Count -ne 1) { throw 'owned exact-name NRPT rule was not installed' }
        @{ nonce = $state.nonce; rule_name = $state.rule_name; watchdog_pid = $watch.Id;
           deadline = $state.deadline; hostname = $TargetName; server = $DnsAddress } | ConvertTo-Json
    }
    elseif (Test-Path -LiteralPath $StatePath) {
        Restore-Owned | ConvertTo-Json -Depth 12
    }
    elseif ($Action -eq 'Verify') {
        # Staging/preflight can fail before any intent or mutation exists.
        @{ restored = $true; mutation_started = $false } | ConvertTo-Json
    }
    else { throw 'NRPT state is missing during restoration' }
}
finally {
    if ($lock) { $lock.Dispose() }
}

# Join outside the state lock: the watchdog may itself be waiting to restore.
if ($Action -ne 'Install' -and (Test-Path -LiteralPath $StatePath)) {
    $state = Read-State
    if ($state.watchdog_pid -and $state.watchdog_pid -ne $PID) {
        $watch = Get-Process -Id $state.watchdog_pid -ErrorAction SilentlyContinue
        if ($watch -and $watch.StartTime.ToUniversalTime() -eq ([DateTime]$state.watchdog_start).ToUniversalTime()) {
            if (-not $watch.WaitForExit(5000)) { throw 'NRPT watchdog did not exit after restoration' }
            if ($watch.ExitCode -ne 0) { throw 'NRPT watchdog failed after restoration' }
        }
    }
    if ((Test-Path -LiteralPath "$StatePath.watch.stderr") -and
        (Get-Item -LiteralPath "$StatePath.watch.stderr").Length -ne 0) {
        throw 'NRPT watchdog reported an error; see retained watchdog stderr'
    }
}
