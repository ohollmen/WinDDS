# ## winsetup.ps1 - WinDDS
# 
# WinDDS (Windows Data driven Setup) is a Windows setup / configuration / automation tool
# with focus on low dependencies and self-containment. It uses Powershell (version 7) to carry out routine tasks in Windows.
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
    if ($uent) { Write-Output "User $($u.uname) already exists"; continue }
    Write-Output "Should create User $($u.uname) !"
    $password = ConvertTo-SecureString $u.pass -AsPlainText -Force
    New-LocalUser -Name $u.uname -Password $password -FullName $u.desc -Description $u.desc -AccountNeverExpires -PasswordNeverExpires
    if ($u.group) { Add-LocalGroupMember -Group $u.group -Member $u.uname }
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
# Import and/or associate cert with services (RDP, WinRM)
# Parameters for "import to Windows Certificate Store" step / node
# - pfxfn - for -FilePath (Should be only used in import step)
# - csl - CertStoreLocation for import-op ( typical: 'Cert:\LocalMachine\My' )
# - pass - password of PFX Private key (Should be only used in import step)
# - tp - Expected SHA1 hash thumbprint of PFX certificate (for verification or association)
# Parameters for rdp/einrm association step
# - rdp - Associate cert with RDP service (Use in rdp assoc step only)
# - winrm - Associate cert with WinRM service (Use in winrm assoc. step only)
# - tp - Thummbprint of Certificate to associate with (rdp or winrom) service
# path (e.g.): RDP: /namespace:\\root\\cimv2\\TerminalServices,
function cert_setup {
  if (!$cfg.certs) { Write-Output "Skipping certs setup ..."; return }
  $wmic_tmpl = @{ "FilePath" = "wmic.exe"; "ArgumentList" = @("/namespace:\\root\cimv2\TerminalServices", "PATH", "Win32_TSGeneralSetting", "Set", "");
    "Verb" = "RunAs"; "PassThru" = $true; "Wait" = $true }
  $winrm_tmpl = @{ "FilePath" = "winrm"; "ArgumentList" = @("create", "winrm/config/Listener?Address=*+Transport=HTTPS", "@{CertificateThumbprint=''}");
    "Verb" = "RunAs"; "PassThru" = $true; "Wait" = $true }
  foreach ($c in $cfg.certs) {
    $cert = $null
    $tp = $null
    # Check need to import
    if ($c.pfxfn -and $c.csl) {
      Write-Output "pfxfn: $($c.pfxfn), pass: $($c.pass), $($c.csl)"
      if ($c.pass) { $cert = Import-PfxCertificate -FilePath $c.pfxfn -Password (ConvertTo-SecureString -String $c.pass -AsPlainText -Force) -CertStoreLocation $c.csl }
      else { $cert = Import-PfxCertificate -FilePath $c.pfxfn -CertStoreLocation $c.csl }
      $tp = $cert.Thumbprint
      # Check/Verify against 
      if ($c.tp -and ($c.tp -ne $tp)) { Write-Output "Expected cert thumbprint $($c.tp) does not match discovered value $($tp)"; continue }
    }
    # Check need to associate (wmic)
    if ($c.rdp) {
      $tp = $c.tp
      $wmic_tmpl.ArgumentList[4] = "SSLCertificateSHA1Hash='$tp'"
      # Effectively: wmic /namespace:\\root\cimv2\TerminalServices PATH Win32_TSGeneralSetting Set SSLCertificateSHA1Hash="$tp"
      $proc = Start-Process @wmic_tmpl
      if ($proc.ExitCode -eq 0) { Write-Output "Success Associating cert with Thumbprint $tp to RDP Service" }
      else { Write-Output "Fail! Exit code: $($Proc.ExitCode)" }
    }
    # WinRM Service
    # https://stackoverflow.com/questions/74178953/winrm-configuration-on-https-port
    # The PS 5 (?) address "winrm/config/Listener" causes problems
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/new-wsmaninstance?view=powershell-7.4
    if ($c.winrm) {
    $selset = @{ Transport = "HTTPS"; Address = "*"; }
    # Opt(val): Hostname="HOST";
    $valset = @{ CertificateThumbprint = "$tp"; }
    # Need to rm listener before assoc'ing cert. Should disable HTTP (permanently) ?
    Get-ChildItem -Path WSMan:\localhost\Listener | Where-Object { $_.Keys -contains "Transport=HTTPS" } | Remove-Item -Recurse -Force
    # Listener* ?
    # Remove-Item -Path WSMan:\localhost\Listener -Recurse -Force
    # Need try{..} catch{..} ?
    # PS7: Do not use: -ResourceURI
    # Note: -Authentication here (Basic,Default(wsman,default), Digest, Kerberos, Negotiate, CredSSP, ClientCertificate) may matter to e.g. ansible.
    # Enable-PSRemoting does not need to be required
    # PS 7.3 manual (but get error about URL notation, Note: per example Hostname = $SubjectName ... given to New-LegacySelfSignedCert -SubjectName ... where
    # [string]$SubjectName = $env:COMPUTERNAME,):
    # New-WSManInstance winrm/config/Listener -SelectorSet @{Transport='HTTPS'; Address='*'} -ValueSet @{Hostname="HOST";CertificateThumbprint="XXXXXXXXXX"}
    #$winrm_tmpl.ArgumentList[2] = "@{CertificateThumbprint=""$tp""}" # winrm version requires PS param (!)
    # To work PS7 version of New-WSManInstance requires repeating selectorset in 2 forms (!, see below)
    New-WSManInstance "winrm/config/Listener?Address=*+Transport=HTTPS" -SelectorSet $selset -ValueSet $valset
    Get-ChildItem -Path WSMan:\localhost\Listener | Where-Object { $_.Keys -contains "Transport=HTTPS" }
    # This might terminate remote runner like ansible (!)
    Write-Output "Please run 'Restart-Service WinRM' (and optional Start-Sleep -s 25) to make new WinRM Cert effective"
    # Way to verify: winrm enumerate winrm/config/Listener (shows tp associated w. winrm service). Also see: winrm get winrm/config
    }
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
# Find files and apply an action to them.
# Parameters:
# - paths - One or more paths under which the find operations are ran
# - patt - filename pattern on files to match during find
# - act - action label (See options below)
# Supported actions (values of "act": "...") are:
# - print - Print name
# - rm - Remove
function findact {
  if (!$cfg.findact) { Write-Output "Skipping find / action tasks (None present)"; return }
  $arr = $cfg.findact
  foreach ($i in $arr) {
    $paths = $i.paths
    $patt  = $i.patt # E.g. *.junk
    $act   = $i.act
    if ($i.disa) { Write-Output "Find by pattern '$patt' disabled (skip...)"; continue }
    Write-Output "Find files in paths $paths by pattern '$patt' for action $act"
    foreach ($path in $paths) {
      # Stage 1: Find (To test in shell use: | ConvertTo-Json | more . Also params: -Depth N, -Include, -Exclude
      # Write-Output "Get-ChildItem -Path $path -Filter ""$patt"" -Recurse -ErrorAction SilentlyContinue -Force"
      # -Depth 30
      $items = Get-ChildItem -Path $path -Filter "$patt" -Recurse -ErrorAction SilentlyContinue -Force # | ConvertTo-Json 
      #return
      # Stage 2: 
      # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item?view=powershell-7.4
      foreach ($i in $items) {
        $ok = ""
        if     ($act -eq "rm")    {
          Remove-Item -Path $i.FullName -ErrorVariable ok -ErrorAction SilentlyContinue;
          if (!$ok) { $ok = "Deletion OK" }
          Write-Output "Ran deletion on $($i.FullName): message=$ok"
        } # Also -Force
        elseif ($act -eq "print") { Write-Output $i.FullName } # ToString()
        else { Write-Output "Action '$act' not supported" }
      }
    }
  }
}
# Uninstall Windows Feature or Application Package or ...
# Note: Only $type feature properly tested (TODO: test others, commands should be right)
function uninst {
  if (!$cfg.uninst) { Write-Output "Skipping uninstalls (None present)"; return }
  foreach ($i in $cfg.uninst) {
    $name = $i.name # name for the one of many types supported
    $type = $i.type
    if ($i.disa) { Write-Output "Skip uninstall of '$name'"; continue }
    if ($type -eq 'feature')        { Uninstall-WindowsFeature -Name $name }
    # Note -FeatureName (except.)
    # Also both -PackageName -FeatureName
    elseif ($type -eq 'optfeature') { Disable-WindowsOptionalFeature -Online -FeatureName $name }
    elseif ($type -eq 'capability') { Remove-WindowsCapability -Name $name }
    elseif ($type -eq 'app')        { Remove-App -Identity $name }
    # Remove .msix or .appx packages (See also: -AllUsers)
    elseif ($type -eq 'apppkg')     { Remove-AppxProvisionedPackage -PackageName $name }
    # Remove-AppxPackage -Package '$name'
    else { Write-Output "Uninstall for component type '$type' not supported" }
  }
}
# Run the default operational sequence. This is someting that probably works
# 90(+)% of the time, but you may need to establish a sequence of your own
# (reorder/skip some). TODO: Make running this optional to use winsetup.p1 as
# library (not only main executable).
$cwd_orig = Get-location
if ($cfg.workdir) { Set-Location $cfg.workdir }
Write-Output "Running Powershell $($PSVersionTable.PSVersion)"
serv_set
user_setup
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
cert_setup
findact
uninst
Set-Location $cwd_orig
Exit
