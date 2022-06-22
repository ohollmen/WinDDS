# WinDDS - Run Windows Setup Chores in a Data Driven Way

WinDDS (DDS=Data Driven Setup) allows running a wide variety of pre-defined setup operations on Windows host using a JSON Configuration file
to describe what modifications need to be performed.
Setup Program (`winsetup.ps1`) is written in Windows PowerShell and should require zero
dependencies to run (The utility can download and install further
dependencies to run more complex setup operations).

Typically these setup operations are run on a (Bare Metal or VM) system
after OS Installation (or "bare" VM instance bring-up). The high level objective of operations could be e.g. SW Installations, perform OS Security hardening, Adding Extra User Accounts etc.

## Supported "Activity Patterns"

The activities currently supported are:

- Disabling or Enabling Windows Services
- Create Additional User Accounts on the System
- Modify (disable) TLS ciphers on the system
- Download files from HTTP(S) URLs (Basic Auth supported)
- Modify Windows Registry by providing "Registry Patches" (exported from
  regedit GUI or dumped with "reg" command line utility)
- Unzip (ZIP) packages (e.g. downloaded from URLs) to configured destination locations
- Run (Setup) Commands on System (e.g. using installers or data files
  downloaded from URLs)
- Cleanup files downloaded from HTTP(s) sources

## JSON Configuration

Brief introduction to JSON config contained config keys (The data that drives
the setup).

- **dlpath** - Download destination path for items in `urls`
- **workdir** - The "current working directory" (CWD) to change to for the duration
  of script run (default: keep CWD where script is invoked and do not change
  directory)
- **urls** - Array of JSON download URL Objects with following properties:
  - **url** - URL to download from
  - **proc** - Processing of downloaded articact after download completes (Note: the processing can be also alternatively done using ops in "run" section)
  - **args** - Array of Arguments for "proc" processing command
  - **auth** - Boolean flag to use HTTP Basic auth credentials (from "htauth" section)
- **htauth** - HTTP(S) authentication credentials:
  - **user** - Username
  - **pass** - Password
- **regchanges** - Array of filenames (*.reg) for registry changes. All these files will be run (by reg.exe) to apply changes to registry
- **tls_disa** - TLS ciphers to disable
- **servs** - Section (Object) to enable/disable services with respective 2 lists (arrays):
  - **ena** - Array of services to stop and disable
  - **disa** - Array of services to start and enable
- **users** - Array of users (Objects) to create with properties:
  - **uname** - Username for account
  - **pass** - Password
  - **desc** - Description for account
- **reginfo** - Meta information for powershell command to apply registry changes
  (just keep tis as-is)
- **unzip** - List of files (Array of file items) to unzip:
  - **src** - Path to ZIP file to unzip
  - **dest** - Destination directory to unip file to
- **run** - Set of setup commands (array of operation objects) to run:
  - **cmd** - Command executable to run (w. basename or absolute path, NO ARGS !)
  - **args** - Array of arguments to pass to command executable
  - **disa** - Disable this command (e.g. temporarily, keep as example, etc.)
  - **ps** - Flag for command being a Powershell command/function call (+args), not an system level executable call
  
## Starting Setup

### Downloading Script and Config

The first step is to get the `winsetup.ps1` and setup config (JSON) to your windows box. The files could originate from (e.g):

- Git - in case your Windows box already has Git Installed
- Windows network drive (if your box already has network drives mounted)
- HTTP(S) URL, i.e. a web server (e.g. Apache or NginX Web server hosting static content, Artifactory, Box, Google Drive, etc ...)

Example of Downloading script with Powershell:

```
Invoke-WebRequest -Uri "https://myserv.corp.com/scripts/winsetup.ps1" -OutFile "winsetup.ps1"
```

Example of Downloading script with curl (must have CURL installed):

```
curl -u "myusername:secret" -L "https://myserv.corp.com/scripts/winsetup.ps1" -O
```

Download JSON config in similar manner.


### Setup Env variable for Config name and Run

Setup config filename in Powershell environment and run setup:

```
# Configure config filename in PS environment
$Env:WINSETUP_CFG_NAME = "C:\Users\mrsmith\postinstall.conf.json"
# Launch setup !
.\winsetup.ps1
```

### Using and Customizing Script

At current state the library of operations is mixed together with
calling sequence operations in one file. Ideally the library and calling
sequence should be separated (for ease of distribution and minimizing number of files, the current solution is good though).

If needed, customize the operations equence at the bottom of the script to fit
your use-case. On the other hand to disable/skip certain operation it is usually
enough to leave respecive JSON config empy (e.g. empty array).


