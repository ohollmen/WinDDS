# $cfgfn = ""
$cfgfn = $args[0]
# Init reg-change params
$reg_change_tmpl = @{ "FilePath" = "REG.exe"; "ArgumentList" = @("import", "C:\\file.reg"); "Verb" = "RunAs"; "PassThru" = $true; "Wait" = $true }
if ($Env:WINSETUP_CFG_NAME) { $cfgfn = $Env:WINSETUP_CFG_NAME }
# else { Write-Output "Must have Setup Filename in `$Env:WINSETUP_CFG_NAME = `"...`""; Exit }
if (-not(Test-Path -Path $cfgfn -PathType Leaf)) {
  Write-Output "Config File $cfgfn does not exist."
  Write-Output "Give config name in `$Env:WINSETUP_CFG_NAME or give it as first argument on command line."
  Exit
}
Write-Output "Using Config: $cfgfn"
$cfg = Get-Content $cfgfn | ConvertFrom-Json
if (!$cfg) { WINSETUP_CFG_NAME "Config (JSON) Not loaded"; Exit }
function serv_set {
  if (!$cfg.servs.disa -or !$cfg.servs.disa.Length) {
    Write-Output "No services to disable";
    $cfg.servs.disa = @()
  }
  foreach ($serv in $cfg.servs.disa) {
    Write-Output "Stop/Disable service: $serv"
    Set-Service -Name $serv -StartupType Disabled -Status Stopped  -Force
    # Write-Output $serv
  }
  # 
  if (!$cfg.servs.ena -or !$cfg.servs.ena.Length) {
    Write-Output "No services to enable";
    $cfg.servs.ena = @()
  }
  foreach ($serv in $cfg.servs.ena) {
    Write-Output "Start/Enable service: $serv"
    Set-Service -Name $serv -StartupType Automatic -Status Running  -Force
    # Write-Output $serv
  }
}


function reg_mod {
  # $myht = $cfg.reginfo | ConvertTo-Json | ConvertFrom-Json -AsHashTable
  $myht = $reg_change_tmpl
  $regfiles = $cfg.regchanges
  Write-Output $regfiles
  foreach ($rf in $regfiles) {
    $myht.ArgumentList[1] = $rf
    #Write-Output $myht
    $proc = Start-Process @myht
    if ($proc.ExitCode -eq 0) { Write-Output "Success Applying $rf" }
    else { Write-Output "Fail! Exit code: $($Proc.ExitCode)" }
  }
}

function user_setup {
  foreach ($u in $cfg.users) {
    $uent =  Get-LocalUser -Name $u.uname
    if ($uent) { Write-Output "User $u.uname already exists"; continue }
    Write-Output "Should create User $u.uname !"
    $password = ConvertTo-SecureString "$u.pass" -AsPlainText -Force
    New-LocalUser -Name $u.uname -Password $password -FullName $u.desc -Description $u.desc -AccountNeverExpires -PasswordNeverExpires
  }
}

function tls_ciph_mod {
  foreach ($cipher in $cfg.tls_disa) {
    Disable-TlsEccCurve -Name $cipher
  }
}

function http_auth {
  $creds = [System.Text.Encoding]::UTF8.GetBytes($cfg.htauth.user + ":" + $cfg.htauth.pass)
  $creds_b64 = [System.Convert]::ToBase64String($creds)
  $cred_hdr = "Basic " + $creds_b64
  return $cred_hdr
  
}

function http_dnload {
  $dlpath = $cfg.dlpath
  foreach ($uitem in $cfg.urls) {
    if ( ! $uitem.url) { Write-Output "No URL (skip)"; continue; }
    # $bn = (Get-Item $uitem.url ).Name
    $bn = Split-Path $uitem.url -Leaf
    $itempath = $dlpath+"\"+ $bn
    Write-Output "Save as: $itempath (Orig: $($uitem.url) )"
    # continue
    # $WebClient.DownloadFile($uitem.url, $itempath)
    if ($uitem.auth) {
      $cred_hdr = http_auth
      #Write-Output "Use creds: $cred_hdr"
      #Write-Output 
      Invoke-WebRequest -Uri $uitem.url -Headers @{"Authorization"=$cred_hdr} -OutFile $itempath
    }
    else {
      Invoke-WebRequest -Uri $uitem.url -OutFile $itempath
    }
    if ($uitem.proc) {
      Write-Output "Should proc: " + $uitem.proc
      $para = ""
      if ($uitem.args) { $para = $uitem.args }
      #$rc = $LASTEXITCODE
      & $uitem.proc $para
      Write-Output "RC=$LASTEXITCODE"
    }
  }
}
function http_cleanup {
  $dlpath = $cfg.dlpath
  foreach ($uitem in $cfg.urls) {
    if ( ! $uitem.url) { Write-Output "No URL in item for cleanup (skip)"; continue; }
    $bn = Split-Path $uitem.url -Leaf
    $itempath = $dlpath+"\"+ $bn
    # -Force
    $rc = Remove-Item -LiteralPath $itempath -Recurse
    Write-Output "Cleanup RC=$rc/$LASTEXITCODE ($bn)"
  }
}

function debug_ctx {
  $cwd = Get-Location
  Write-Output "CWD: $cwd"
}

function pkgs_unzip {
  foreach ($pkg in $cfg.unzip) {
    Write-Output "Unpacking $($pkg.src) to $($pkg.dest)"
    Expand-Archive -LiteralPath $pkg.src -DestinationPath $pkg.dest
  }
}

function ops_run {
  if (!$cfg.run) { Write-Output "Skipping run ..."; return }
  foreach ($uitem in $cfg.run) {
    if ($uitem.args) { $para = $uitem.args }
    if ($uitem.disa) { continue; }
    if ($uitem.ps) {
      $para = $uitem.cmd + " " + $uitem.args -Join " "
      Write-Output "CMD: $para"
      Invoke-Expression  "$para"
    }
    else { & $uitem.cmd $para }
    Write-Output "RC=$LASTEXITCODE"
  }
}

# Run the default operational sequence. This is someting that probably works
# 90(+)% of the time, but you may need to establish a sequence of your own
# (reorder/skip some). TODO: Make running this optional to use winsetup.p1 as
# library (not only main executable).
$cwd_orig = Get-location
if ($cfg.workdir) { Set-Location $cfg.workdir }
serv_set
# user_setup
tls_ciph_mod
# debug_ctx
http_dnload
reg_mod
pkgs_unzip
ops_run
# Do not cleanup by default.
# http_cleanup
Set-Location $cwd_orig
Exit
