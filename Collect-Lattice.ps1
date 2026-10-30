# Lattice Windows Live v0.3.0: passive local observation only.
# Requires Windows PowerShell 5.1+. No changes to policies, registry, events, firewall, or services.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('fast','security')][string]$Mode,
  [Parameter(Mandatory=$true)][string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$timer = [System.Diagnostics.Stopwatch]::StartNew()

function Sensor([string]$name, [string]$source, [scriptblock]$action) {
  $when = [DateTime]::UtcNow.ToString('o')
  try {
    $data = & $action
    return @{state='ok'; collected_at=$when; source=$source; data=$data}
  } catch {
    $msg = [string]$_.Exception.Message
    $msg = ($msg -replace '[\r\n]+',' ')
    if ($msg.Length -gt 220) { $msg = $msg.Substring(0,220) }
    # Failure is never represented as an empty / successful measurement.
    return @{state='unavailable'; collected_at=$when; source=$source; reason=$msg}
  }
}
function Flag([object]$value) {
  if ($null -eq $value) { return $null }
  # PowerShell coerces nonempty strings such as 'False' into $true; never do that.
  switch -Regex ([string]$value) {
    '^(True|Enabled|On|1)$' { return $true }
    '^(False|Disabled|Off|0)$' { return $false }
    default { return $null }
  }
}
function CountProp([object]$obj,[string]$prop) {
  if ($null -eq $obj) { return 0 }
  $a=@($obj.$prop)
  return @($a | Where-Object {$null -ne $_ -and [string]$_ -ne ''}).Count
}
function EventSummary([string]$log,[int[]]$ids,[int]$limit) {
  $from=(Get-Date).AddHours(-24)
  $filter=@{LogName=$log;StartTime=$from;Id=$ids}
  $items=@()
  try { $items=@(Get-WinEvent -FilterHashtable $filter -MaxEvents $limit -ErrorAction Stop) }
  catch {
    $id = [string]$_.FullyQualifiedErrorId
    if ($id -notlike '*NoMatchingEventsFound*') { throw }
  }
  $counter=@{}
  foreach ($id in $ids) { $counter[[string]$id]=0 }
  $recent=@()
  foreach ($event in $items) {
    $key=[string]$event.Id
    $counter[$key]=[int]$counter[$key]+1
    if ($recent.Count -lt 18) {
      $recent+=@{id=[int]$event.Id;when=$event.TimeCreated.ToUniversalTime().ToString('o');level=[string]$event.LevelDisplayName;provider=[string]$event.ProviderName}
    }
  }
  return @{window_hours=24;sample_limit=$limit;sample_count=$items.Count;truncated=($items.Count -ge $limit);counts=$counter;recent=$recent;note='Counts are bounded observations, not guaranteed complete totals. Event generation depends on audit settings.'}
}
$result=@{schema='lattice.windows.collector.v1';mode=$Mode;utc=[DateTime]::UtcNow.ToString('o');collector='Windows PowerShell';sensors=@{}}
try {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $principal=New-Object Security.Principal.WindowsPrincipal($identity)
  $result.is_admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $result.is_admin = $null }

if ($Mode -eq 'fast') {
  $result.sensors.system=Sensor 'system' 'CIM Win32_OperatingSystem / Win32_Processor' {
    $os=Get-CimInstance -ClassName Win32_OperatingSystem
    $cpus=@(Get-CimInstance -ClassName Win32_Processor)
    $avg=$null
    if ($cpus.Count -gt 0) {
      $load=($cpus|Measure-Object -Property LoadPercentage -Average).Average
      if($null -ne $load) { $avg=[math]::Round([double]$load,1) }
    }
    $mem=[double]$os.TotalVisibleMemorySize
    $free=[double]$os.FreePhysicalMemory
    $uptime=([DateTime]::Now - [DateTime]$os.LastBootUpTime).TotalSeconds
    return @{cpu_load_pct=$avg;cpu_method='Win32_Processor.LoadPercentage, sampled estimate';memory_total_bytes=[int64]($mem*1024);memory_used_bytes=[int64](($mem-$free)*1024);memory_free_bytes=[int64]($free*1024);uptime_seconds=[math]::Max(0,[math]::Floor($uptime));os_caption=[string]$os.Caption;os_build=[string]$os.BuildNumber;logical_processors=[int](($cpus|Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum)}
  }
  $result.sensors.disks=Sensor 'disks' 'CIM Win32_LogicalDisk DriveType=3' {
    $volumes=@(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { @{name=[string]$_.DeviceID;size_bytes=[int64]$_.Size;free_bytes=[int64]$_.FreeSpace} })
    return @{volumes=$volumes;count=$volumes.Count}
  }
  $result.sensors.processes=Sensor 'processes' 'Get-Process; nonprivileged process metadata only' {
    $all=@(Get-Process)
    $top=@($all | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 14 | ForEach-Object { @{pid=[int]$_.Id;name=[string]$_.ProcessName;working_set_bytes=[int64]$_.WorkingSet64;cpu_seconds=$(if($null -ne $_.CPU){[math]::Round([double]$_.CPU,1)}else{$null})} })
    return @{count=$all.Count;top_memory=$top}
  }
  $result.sensors.network=Sensor 'network' 'Get-NetTCPConnection; Get-NetAdapter (read-only)' {
    $socks=@(Get-NetTCPConnection -ErrorAction Stop)
    $counts=@{}
    foreach($s in $socks){$key=[string]$s.State;if(-not $counts.ContainsKey($key)){$counts[$key]=0};$counts[$key]++}
    $pids=@{}
    foreach($p in @(Get-Process -ErrorAction SilentlyContinue)){ $pids[[string]$p.Id]=[string]$p.ProcessName }
    $list=@($socks | Where-Object {$_.State -eq 'Listen'} | Sort-Object LocalPort | Select-Object -First 30 | ForEach-Object {
      $name=$pids[[string]$_.OwningProcess]
      @{port=[int]$_.LocalPort;address=[string]$_.LocalAddress;pid=[int]$_.OwningProcess;process=$(if($name){$name}else{'<unknown>'})}
    })
    $est=@($socks|Where-Object {$_.State -eq 'Established'}|Select-Object -First 30|ForEach-Object {
      $name=$pids[[string]$_.OwningProcess]
      @{remote=[string]$_.RemoteAddress;remote_port=[int]$_.RemotePort;pid=[int]$_.OwningProcess;process=$(if($name){$name}else{'<unknown>'})}
    })
    $adapterList=@(Get-NetAdapter -ErrorAction Stop | ForEach-Object {@{name=[string]$_.Name;status=[string]$_.Status;link_speed=[string]$_.LinkSpeed}})
    return @{total=$socks.Count;states=$counts;listening=$list;established=$est;adapters=$adapterList;bounded_lists=$true}
  }
} else {
  $result.sensors.defender=Sensor 'defender' 'Get-MpComputerStatus' {
    $d=Get-MpComputerStatus -ErrorAction Stop
    $sig=$null
    if($null -ne $d.AntivirusSignatureLastUpdated){$sig=([DateTime]$d.AntivirusSignatureLastUpdated).ToUniversalTime().ToString('o')}
    return @{antivirus_enabled=(Flag $d.AntivirusEnabled);real_time=(Flag $d.RealTimeProtectionEnabled);on_access=(Flag $d.OnAccessProtectionEnabled);antispyware_enabled=(Flag $d.AntispywareEnabled);tamper_protected=$(if($d.PSObject.Properties['IsTamperProtected']){Flag $d.IsTamperProtected}else{$null});engine_version=[string]$d.AMEngineVersion;signature_version=[string]$d.AntivirusSignatureVersion;signature_updated=$sig;quick_scan_age_days=$d.QuickScanAge;full_scan_age_days=$d.FullScanAge}
  }
  $result.sensors.asr=Sensor 'asr' 'Get-MpPreference (ASR rules, exclusion counts only)' {
    $p=Get-MpPreference -ErrorAction Stop
    $ids=@($p.AttackSurfaceReductionRules_Ids | Where-Object { $null -ne $_ });$actions=@($p.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
    $modes=@{}
    for ($i=0;$i -lt $ids.Count;$i++) {
      $k=[string]$actions[$i]
      if (-not $modes.ContainsKey($k)) {$modes[$k]=0}
      $modes[$k]++
    }
    return @{rule_count=$ids.Count;mode_counts=$modes;exclusion_path_count=CountProp $p 'ExclusionPath';exclusion_process_count=CountProp $p 'ExclusionProcess';exclusion_extension_count=CountProp $p 'ExclusionExtension';note='Exclusion values and ASR rule identifiers are intentionally not collected.'}
  }
  $result.sensors.firewall=Sensor 'firewall' 'Get-NetFirewallProfile -PolicyStore ActiveStore; Get-NetConnectionProfile; Get-NetFirewallRule -PolicyStore ActiveStore' {
    $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object { @{name=[string]$_.Name;enabled=(Flag $_.Enabled);inbound=[string]$_.DefaultInboundAction;outbound=[string]$_.DefaultOutboundAction;log_blocked=[string]$_.LogBlocked} })
    $active=@(Get-NetConnectionProfile -ErrorAction SilentlyContinue|ForEach-Object {@{network_category=[string]$_.NetworkCategory;interface_alias=[string]$_.InterfaceAlias}})
    $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {[string]$_.Enabled -eq 'True'})
    $group=@{}
    foreach($r in $rules){$key=([string]$r.Direction)+'_'+([string]$r.Action);if(-not $group.ContainsKey($key)){$group[$key]=0};$group[$key]++}
    return @{profiles=$profiles;active_networks=$active;enabled_rule_count=$rules.Count;rule_counts=$group;note='Rule counts are not proof that individual connections were blocked.'}
  }
  $result.sensors.secureboot=Sensor 'secureboot' 'Confirm-SecureBootUEFI' {
    return @{enabled=(Flag (Confirm-SecureBootUEFI -ErrorAction Stop))}
  }
  $result.sensors.tpm=Sensor 'tpm' 'Get-Tpm' {
    $t=Get-Tpm -ErrorAction Stop
    return @{present=(Flag $t.TpmPresent);ready=(Flag $t.TpmReady);enabled=(Flag $t.TpmEnabled);activated=(Flag $t.TpmActivated);managed_auth_level=[string]$t.ManagedAuthLevel}
  }
  $result.sensors.vbs=Sensor 'vbs' 'CIM Win32_DeviceGuard, root/Microsoft/Windows/DeviceGuard' {
    $v=Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    $running=@($v.SecurityServicesRunning)
    return @{vbs_status=[int]$v.VirtualizationBasedSecurityStatus;security_services_running=$running;credential_guard=$(if($null -ne $v.SecurityServicesRunning){$running -contains 1}else{$null});memory_integrity=$(if($null -ne $v.SecurityServicesRunning){$running -contains 2}else{$null});security_services_configured=@($v.SecurityServicesConfigured);code_integrity_policy_status=$v.CodeIntegrityPolicyEnforcementStatus;user_mode_code_integrity_policy_status=$v.UsermodeCodeIntegrityPolicyEnforcementStatus}
  }
  $result.sensors.bitlocker=Sensor 'bitlocker' 'Get-BitLockerVolume (no keys or recovery passwords)' {
    $volumes=@(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object { @{mount=[string]$_.MountPoint;protection=[string]$_.ProtectionStatus;volume_status=[string]$_.VolumeStatus;encryption_pct=$(if($null -ne $_.EncryptionPercentage){[int]$_.EncryptionPercentage}else{$null});lock_status=[string]$_.LockStatus} })
    return @{volumes=$volumes;count=$volumes.Count}
  }
  $result.sensors.accounts=Sensor 'accounts' 'Get-LocalUser; Get-LocalGroupMember -SID S-1-5-32-544' {
    $users=@(Get-LocalUser -ErrorAction Stop)
    $admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    return @{local_user_count=$users.Count;enabled_local_user_count=@($users|Where-Object {$_.Enabled}).Count;local_admin_group_members=$admins.Count;note='Counts only; membership does not prove effective individual access.'}
  }
  $result.sensors.hotfix=Sensor 'hotfix' 'Get-HotFix (partial update history)' {
    $all=@(Get-HotFix -ErrorAction Stop | Where-Object {$null -ne $_.InstalledOn} | Sort-Object InstalledOn -Descending)
    $last=@($all|Select-Object -First 8|ForEach-Object {@{id=[string]$_.HotFixID;installed=([DateTime]$_.InstalledOn).ToUniversalTime().ToString('o')}})
    return @{recent_hotfixes=$last;count_in_query=$all.Count;note='Get-HotFix is not a complete Windows Update or patch-compliance inventory.'}
  }
  $result.sensors.services=Sensor 'services' 'Get-Service (selected security-relevant services)' {
    $names=@('WinDefend','MpsSvc','EventLog','wuauserv','WinRM','RemoteRegistry','TermService','LanmanServer')
    $entries=@()
    foreach($n in $names) {
      $service=Get-Service -Name $n -ErrorAction SilentlyContinue
      if($null -eq $service) { $entries+=@{name=$n;state='unavailable'} }
      else { $entries+=@{name=$n;state=[string]$service.Status;start_type=[string]$service.StartType} }
    }
    return @{services=$entries;note='Reported service states only; a running service does not by itself establish remote reachability or secure configuration.'}
  }
  $result.sensors.event_channels=Sensor 'event_channels' 'Get-WinEvent -ListLog selected channels' {
    $names=@('Security','System','Microsoft-Windows-Windows Defender/Operational')
    $entries=@()
    foreach($n in $names) {
      try {
        $log=Get-WinEvent -ListLog $n -ErrorAction Stop
        $entries+=@{name=$n;available=$true;enabled=(Flag $log.IsEnabled);record_count=$log.RecordCount;maximum_bytes=[int64]$log.MaximumSizeInBytes;log_mode=[string]$log.LogMode}
      } catch { $entries+=@{name=$n;available=$false;reason='Log channel metadata inaccessible'} }
    }
    return @{channels=$entries;note='A channel being enabled does not prove specific audit subcategories produce events.'}
  }
  $result.sensors.smb=Sensor 'smb' 'Get-SmbServerConfiguration (read-only)' {
    $c=Get-SmbServerConfiguration -ErrorAction Stop
    return @{smb1_enabled=(Flag $c.EnableSMB1Protocol);smb2_enabled=(Flag $c.EnableSMB2Protocol);signing_required=(Flag $c.RequireSecuritySignature);encryption_supported=(Flag $c.EncryptData);note='Configuration observed; not proof of exposed inbound SMB reachability.'}
  }
  $result.sensors.security_events=Sensor 'security_events' 'Get-WinEvent -FilterHashtable Security, 24 h, maximum 250 matching events' {
    return (EventSummary 'Security' @(4625,4688,1102,4719,4720,4732,4698) 250)
  }
  $result.sensors.system_events=Sensor 'system_events' 'Get-WinEvent -FilterHashtable System/7045, 24 h, maximum 100' {
    return (EventSummary 'System' @(7045) 100)
  }
  $result.sensors.defender_events=Sensor 'defender_events' 'Get-WinEvent Defender/Operational 1116,1117,5007, 24 h, maximum 100' {
    return (EventSummary 'Microsoft-Windows-Windows Defender/Operational' @(1116,1117,5007) 100)
  }
}
$timer.Stop()
$result.duration_ms=[math]::Round($timer.Elapsed.TotalMilliseconds)
# Output only to a caller-chosen per-run temporary JSON file; no event payloads or credentials.
$json=$result|ConvertTo-Json -Depth 12 -Compress
[System.IO.File]::WriteAllText($OutputPath,$json,(New-Object System.Text.UTF8Encoding($false)))
