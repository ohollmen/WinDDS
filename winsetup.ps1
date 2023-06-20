# ## winsetup.ps1 - WinDDS
# 
# WinDDS (Windows Data driven Setup) is a Windows setup / configuration / automation tool
# with focus on low dependencies and self-containment.
# WinDDS aims to be a poor-mans Ansible on Windows with no extra dependencies needed on any Windows PS 7 equipped OS / host.
# 
# URLs for
# - Git Repo: https://github.com/ohollmen/WinDDS
# - This PS executable: https://raw.githubusercontent.com/ohollmen/WinDDS/main/winsetup.ps1
# - Brief manual page: https://github.com/ohollmen/WinDDS/blob/main/README.md
# 
# Low dependencies - Depends only on Powershell 7 (Some features are
# powershell 5 incompatible, please make sure you are using PS version 7).
# For features see Git repo README.md.
# Usage (assume JSON config mysetup.json to reside in same directory as winsetup.ps1):
# ```
# .\winsetup.ps1 .\mysetup.json
# ```

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
if (!$cfg) { Write-Output "Setup Config '$cfgfn' (JSON) Not loaded"; Exit }
function serv_set {
  #if (!$cfg.servs) { $cfg.servs = @{} }
  if (!$cfg.servs) { Write-Output "No services to enable / disable"; return; }
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
  if (!$cfg.regchanges) { Write-Output "Skipping regchanges ..."; return }
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
  if (!$cfg.users) { Write-Output "Skipping users addition ..."; return }
  foreach ($u in $cfg.users) {
    $uent =  Get-LocalUser -Name $u.uname
    if ($uent) { Write-Output "User $u.uname already exists"; continue }
    Write-Output "Should create User $u.uname !"
    $password = ConvertTo-SecureString "$u.pass" -AsPlainText -Force
    New-LocalUser -Name $u.uname -Password $password -FullName $u.desc -Description $u.desc -AccountNeverExpires -PasswordNeverExpires
  }
}

function tls_ciph_mod {
  if (!$cfg.tls_disa) { Write-Output "Skipping TLS cipher disablement ..."; return }
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
  if (!$cfg.urls) { Write-Output "Skipping URL downloads ..."; return }
  $dlpath = $cfg.dlpath
  foreach ($uitem in $cfg.urls) {
    if ($uitem.disa) { continue; }
    if ( ! $uitem.url) { Write-Output "No URL (skip)"; continue; }
    # $bn = (Get-Item $uitem.url ).Name
    if ($uitem.saveas) { $bn = $uitem.saveas }
    else { $bn = Split-Path $uitem.url -Leaf }
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
  if (!$cfg.cleanup) { Write-Output "Skipping download cleanup ..."; return }
  $dlpath = $cfg.dlpath
  foreach ($uitem in $cfg.urls) {
    if ($uitem.disa) { continue; }
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
  if (!$cfg.unzip) { Write-Output "Skipping UNZIP ..."; return }
  foreach ($pkg in $cfg.unzip) {
    if ($pkg.disa) { continue; }
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
function sys_unhide {
  if (!$cfg.unhide) { Write-Output "Skipping unhide ..."; return }
  $exp_adv_key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
  Set-ItemProperty $exp_adv_key Hidden 1
  Set-ItemProperty $exp_adv_key HideFileExt 0
  Set-ItemProperty $exp_adv_key ShowSuperHidden 1
  # Avoid disruption, alow take effect after next reboot
  # Stop-Process -processname explorer
}
# WIP: Import and/or associate cert with service
# path (e.g.): RDP: /namespace:\\root\\cimv2\\TerminalServices, 
function cert_setup {
  if (!$cfg.certs) { Write-Output "Skipping certs setup ..."; return }
  foreach ($c in $cfg.certs) {
    # Check need to import
    if ($c.pfxfn && $c.csl) { Import-PfxCertificate -FilePath $c.pfxfn -CertStoreLocation $c.csl }
    # Check need to associate (wmic)
    if ($c.thumbprint) { }
  }
}
function gp_apply {
  if (!$cfg.gp) { Write-Output "No LGP config - Skipping Group Policy setup/import ..."; return }
  $exe = $cfg.gp.lgpoexe # || 'lgpo.exe'
  if (!$exe) { Write-Output "Must have LGPO executable configured (missing). Skipping LGP import"; return }
  $bdir = $cfg.gp.basedir
  if (!$bdir) { Write-Output "No basedir for LGP import. Skipping LGP import"; return }
  # Remove old policies before applying new
  if ($cfg.gp.rmpol) {
    Remove-Item -LiteralPath C:\Windows\System32\GroupPolicy -Recurse -Force
    Remove-Item -LiteralPath C:\Windows\System32\GroupPolicyUsers -Recurse -Force
  }
  & gpupdate.exe /force
  $items = @(
    #[pscustomobject]
    @{impopt='/s';relfn='\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf'}
    #[pscustomobject]
    @{impopt='/ac';relfn='\DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\audit.csv'}
    #[pscustomobject]
    @{impopt='/m';relfn='\DomainSysvol\GPO\Machine\registry.pol'}
    #[pscustomobject]
    @{impopt='/u';relfn='\DomainSysvol\GPO\User\registry.pol'}
  )
  foreach ($it in $items) {
    # $cfg.gp.lgpoexe + " " +
    #$para =  $it.impopt + " " + "$bdir" + $it.relfn
    #$fpath = "'"+$bdir+$it.relfn+"'"
    $fpath = $bdir+$it.relfn
    #$para = @($it.impopt, "'"+$bdir+$it.relfn+"'")
    $para = @($it.impopt, $fpath)
    #Write-Output $cmd
    & $exe $para
  }
  & gpupdate.exe /force
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
sys_unhide
gp_apply
Set-Location $cwd_orig
Exit
