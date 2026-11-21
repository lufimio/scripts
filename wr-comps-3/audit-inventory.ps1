#requires -Version 5.1
<#
.SYNOPSIS
Writes a Windows listening-port inventory in audit-inventory.sh YAML format.
.EXAMPLE
.\audit-inventory.ps1 -OutputPath .\inventory.yaml
.NOTES
Run elevated for the most complete service information. TCP listeners and bound
UDP sockets are included; loopback sockets and outbound TCP connections are not.
Ports in the configured dynamic ranges are retained as YAML comments. Service
names describe every service hosted by the PID, not necessarily the individual
service that owns the socket. Collection is a best-effort snapshot.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = '.\inventory.yaml'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function ConvertTo-YamlString {
    param([AllowEmptyString()][string]$Value)
    # JSON double-quoted strings are also valid YAML scalars.
    ConvertTo-Json -InputObject $Value -Compress
}

function Get-DynamicPortRange {
    param([string]$Family, [string]$Protocol)

    $output = @(& netsh.exe interface $Family show dynamicport $Protocol 2>$null)
    $commandExitCode = $LASTEXITCODE
    # Parse numeric values rather than localized field names.
    $numbers = @($output | ForEach-Object {
        if ($_ -match '^\s*[^:]+:\s*(\d+)\s*$') { [int]$Matches[1] }
    })
    if ($commandExitCode -eq 0 -and $numbers.Count -eq 2 -and
        $numbers[0] -ge 1 -and $numbers[1] -ge 1 -and
        ($numbers[0] + $numbers[1] - 1) -le 65535) {
        return [pscustomobject]@{ Start = $numbers[0]; End = $numbers[0] + $numbers[1] - 1 }
    }

    Write-Warning "Cannot read the $Family/$Protocol dynamic range; assuming 49152-65535."
    [pscustomobject]@{ Start = 49152; End = 65535 }
}

function Get-PortIdentifiers {
    # Same explicit identifiers as the shell script, plus common Windows ports.
    $identifiers = @{
        20 = 'ftp'; 21 = 'ftp'; 22 = 'ssh'; 23 = 'telnet'; 25 = 'smtp'
        53 = 'dns'; 67 = 'dhcp'; 68 = 'dhcp'; 80 = 'http'; 88 = 'kerberos'
        110 = 'pop3'; 123 = 'ntp'; 135 = 'msrpc'; 137 = 'netbios-ns'
        138 = 'netbios-dgm'; 139 = 'netbios-ssn'; 143 = 'imap'; 161 = 'snmp'
        389 = 'ldap'; 443 = 'https'; 445 = 'smb'; 465 = 'smtps'
        587 = 'smtp-submission'; 631 = 'ipp'; 636 = 'ldaps'; 993 = 'imaps'
        995 = 'pop3s'; 2049 = 'nfs'; 3306 = 'mysql'; 3389 = 'rdp'
        5353 = 'mdns'; 5432 = 'postgresql'; 5672 = 'amqp'; 5900 = 'vnc'
        5985 = 'winrm'; 5986 = 'winrm-https'; 6379 = 'redis'
        8080 = 'http-alt'; 8443 = 'https-alt'; 9200 = 'elasticsearch'
        11211 = 'memcached'; 27017 = 'mongodb'
    }
    $result = @{}
    foreach ($port in $identifiers.Keys) {
        foreach ($protocol in 'tcp', 'udp') {
            $result["$port/$protocol"] = $identifiers[$port]
        }
    }

    # Windows equivalent of the shell script's getent services fallback.
    $servicesFile = Join-Path $env:SystemRoot 'System32\drivers\etc\services'
    if (Test-Path -LiteralPath $servicesFile) {
        foreach ($line in Get-Content -LiteralPath $servicesFile) {
            if ($line -match '^\s*([^#\s]+)\s+(\d+)/(tcp|udp)\b') {
                $key = '{0}/{1}' -f [int]$Matches[2], $Matches[3].ToLowerInvariant()
                if (-not $result.ContainsKey($key)) { $result[$key] = $Matches[1] }
            }
        }
    }
    return $result
}

function ConvertTo-PortRanges {
    param([object[]]$Rows)

    # Rows have already been combined into one label per port and protocol.
    foreach ($group in @($Rows | Group-Object Protocol, Label)) {
        $ordered = @($group.Group | Sort-Object Port)
        $start = $ordered[0].Port
        $end = $start
        foreach ($row in $ordered | Select-Object -Skip 1) {
            if ($row.Port -eq ($end + 1)) {
                $end = $row.Port
            } else {
                [pscustomobject]@{
                    Start = $start; End = $end
                    Protocol = $ordered[0].Protocol; Label = $ordered[0].Label
                }
                $start = $row.Port
                $end = $start
            }
        }
        [pscustomobject]@{
            Start = $start; End = $end
            Protocol = $ordered[0].Protocol; Label = $ordered[0].Label
        }
    }
}

function Get-InventoryYaml {
    $socketOutput = @(& netstat.exe -ano)
    if ($LASTEXITCODE -ne 0) { throw 'netstat -ano failed.' }

    $processes = @{}
    $taskOutput = @(& tasklist.exe /svc /fo csv /nh)
    if ($LASTEXITCODE -eq 0) {
        foreach ($task in @($taskOutput | ConvertFrom-Csv -Header ImageName, ProcessId, Services)) {
            if ($task.ProcessId -notmatch '^\d+$') { continue }
            $serviceNames = @($task.Services -split ',' | ForEach-Object { $_.Trim() } |
                Where-Object { $_ -and $_ -ne 'N/A' } | Sort-Object -Unique)
            $name = $task.ImageName -replace '(?i)\.exe$', ''
            if ($serviceNames.Count -gt 0) { $name = $serviceNames -join ',' }
            $processes[[int]$task.ProcessId] = $name
        }
    } else {
        Write-Warning 'tasklist /svc failed; labels will use port identifiers or unknown.'
    }

    $dynamicRanges = @{}
    foreach ($family in 'ipv4', 'ipv6') {
        foreach ($protocol in 'tcp', 'udp') {
            $dynamicRanges["$family/$protocol"] = Get-DynamicPortRange $family $protocol
        }
    }
    $identifiers = Get-PortIdentifiers
    $sockets = @(foreach ($line in $socketOutput) {
        $fields = @($line.Trim() -split '\s+')
        if ($fields.Count -lt 4) { continue }
        $protocol = $fields[0].ToLowerInvariant()
        if ($protocol -eq 'tcp') {
            if ($fields.Count -ne 5 -or $fields[3] -ne 'LISTENING') { continue }
        } elseif ($protocol -ne 'udp' -or $fields.Count -ne 4) { continue }

        if ($fields[1] -notmatch '^(\[.*\]|[^:]+):(\d+)$') { continue }
        $address = $Matches[1].Trim([char[]]'[]')
        $port = [int]$Matches[2]
        if ($port -lt 1 -or $port -gt 65535) { continue }
        $ipAddress = $null
        if (-not [System.Net.IPAddress]::TryParse($address, [ref]$ipAddress)) { continue }
        if ([System.Net.IPAddress]::IsLoopback($ipAddress)) { continue }
        if ($ipAddress.IsIPv4MappedToIPv6 -and
            [System.Net.IPAddress]::IsLoopback($ipAddress.MapToIPv4())) { continue }
        $family = 'ipv4'
        if ($ipAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $family = 'ipv6'
        }
        $ownerId = 0
        if (-not [int]::TryParse($fields[-1], [ref]$ownerId)) { continue }
        $identifier = $identifiers["$port/$protocol"]
        $name = $processes[$ownerId]
        $label = 'unknown'
        if ($name) {
            $label = $name
            if ($identifier -and $identifier -ne $name) { $label = "$name/$identifier" }
        } elseif ($identifier) { $label = $identifier }
        $range = $dynamicRanges["$family/$protocol"]
        [pscustomobject]@{
            Port = $port; Protocol = $protocol; Label = $label
            Ephemeral = ($port -ge $range.Start -and $port -le $range.End)
        }
    })

    # Deduplicate IPv4/IPv6 and combine owners so YAML never has duplicate keys.
    # If a port is dynamic for just one address family, retain its other binding
    # as an active entry as well as documenting the dynamic binding in comments.
    $rows = @(foreach ($group in @($sockets | Group-Object Port, Protocol, Ephemeral)) {
        $first = $group.Group[0]
        [pscustomobject]@{
            Port = $first.Port; Protocol = $first.Protocol; Ephemeral = $first.Ephemeral
            Label = (@($group.Group.Label | Sort-Object -Unique) -join '; ')
        }
    })

    $ip = 'unknown'
    $addresses = @(foreach ($adapter in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($adapter.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
        foreach ($unicast in $adapter.GetIPProperties().UnicastAddresses) {
            $candidate = $unicast.Address
            if (-not [System.Net.IPAddress]::IsLoopback($candidate) -and
                -not $candidate.IsIPv6LinkLocal -and
                $candidate.ToString() -ne '0.0.0.0' -and $candidate.ToString() -ne '::') {
                $candidate
            }
        }
    })
    $preferred = @($addresses | Sort-Object @{ Expression = {
        if ($_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 0 } else { 1 }
    } })
    if ($preferred.Count -gt 0) { $ip = $preferred[0].ToString() }

    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add(('{0}:' -f (ConvertTo-YamlString ([Environment]::MachineName))))
    $lines.Add(('  ip: {0}' -f (ConvertTo-YamlString $ip)))
    $active = @($rows | Where-Object { -not $_.Ephemeral })
    if ($active.Count -eq 0) { $lines.Add('  ports: {}') } else { $lines.Add('  ports:') }
    foreach ($isEphemeral in $false, $true) {
        $selected = @($rows | Where-Object { $_.Ephemeral -eq $isEphemeral })
        if ($selected.Count -eq 0) { continue }
        $prefix = '    '
        if ($isEphemeral) {
            $lines.Add('  # Listeners / bound UDP sockets in dynamic (ephemeral) port ranges:')
            $prefix = '    # '
        }
        foreach ($range in @(ConvertTo-PortRanges $selected | Sort-Object Start, Protocol)) {
            $portText = [string]$range.Start
            if ($range.End -ne $range.Start) { $portText = '{0}-{1}' -f $range.Start, $range.End }
            $key = '{0}/{1}' -f $portText, $range.Protocol
            $lines.Add(('{0}{1}: {2}' -f $prefix, (ConvertTo-YamlString $key),
                (ConvertTo-YamlString $range.Label)))
        }
    }
    return ($lines -join [Environment]::NewLine) + [Environment]::NewLine
}

$yaml = Get-InventoryYaml
$resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
[System.IO.File]::WriteAllText($resolvedOutput, $yaml, $encoding)
Write-Verbose "Inventory written to $resolvedOutput"
