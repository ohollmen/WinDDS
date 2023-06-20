# WinDDS - Run Windows Setup Chores in a Data Driven Way

WinDDS (DDS=Data Driven Setup) allows running a wide variety of pre-defined setup operations on Windows host using a
JSON Configuration file to describe what modifications need to be performed.
Setup Program (`winsetup.ps1`) is written in Windows PowerShell and should require zero
dependencies to run (The utility can download and install further
dependencies to run more complex setup operations).

Typically these setup operations are run on a (Bare Metal or VM) system after OS Installation
(or "bare" VM instance bring-up). The high level objective of operations could be e.g. SW
Installations, perform OS Security hardening, Adding Extra User Accounts etc.

## Supported "Activity Patterns"

The activities currently supported are:

- Disabling or Enabling Windows Services
- Create Additional User Accounts on the System
- Modify (disable) TLS ciphers on the system
- Download files from HTTP(S) URLs (Basic Auth supported)
- Modify Windows Registry by providing "Registry Patches" (exported from
  regedit GUI or dumped with "reg.exe" command line utility)
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
  - **url** - URL to download a file from. File is saved to path given in "dlpath" config setting
    with same file basename that appears in URL.
  - **proc** - Processing of downloaded artifact after download completes (Note: the processing can be also
      alternatively done using ops in "run" section)
  - **args** - Array of Arguments for "proc" processing command
  - **auth** - Boolean flag to use HTTP Basic auth credentials (from "htauth" section)
  - Note: There can currently be only one set of Basic Auth credentials
- **htauth** - HTTP(S) authentication credentials:
  - **user** - Basic Auth Username
  - **pass** - Basic Auth Password
- **regchanges** - Array of filenames (*.reg) for registry changes. All these files will be run (by reg.exe) to
  apply changes to registry
- **tls_disa** - TLS ciphers to disable
- **servs** - Section (Object) to enable/disable services with respective 2 lists (arrays):
  - **ena** - Array of services to stop and disable
  - **disa** - Array of services to start and enable
- **users** - Array of users (Objects) to create with properties:
  - **uname** - Username for Local Windows account
  - **pass** - Password for Local Windows account
  - **desc** - Description for account
- **reginfo** - Meta information for powershell command to apply registry changes
  (just keep this unaltered / as-is)
- **unzip** - List of files (Array of file items) to unzip:
  - **src** - Path to ZIP file to unzip
  - **dest** - Destination directory to unzip file to
  - Note: When developing the config for automation, verify that
unzip "dest" directory works as you expected
- **run** - Set of setup commands or Powershell functions to run (array of operation objects):
  - **cmd** - Command executable to run (w. basename or absolute path,
NOT including args ! For "args" see below) or name of Powershell function
to call (There will never be Path part to this)
  - **args** - Array of arguments to pass to command executable
  - **disa** - Disable this command (e.g. temporarily, keep as example, etc.)
  - **ps** - Flag for command being a Powershell command/function call (+args), not an system level executable call
- **gp** - Apply Group Policy from a directory tree using LGPO.exe utility
  - **lgpoexe** - The full path (including filename) of LGPO.exe group policy utility
  - **basedir** - The path of group policies directory (typically GUID form strings with surrounding "curlies")
  - **rmpol** - Flag for removing all policies from global policy directorries before applying new policies from "basedir".

## Starting Setup

### Downloading Script and Config

The first step is to get the `winsetup.ps1` and setup config (JSON) to your windows box. The files could originate from (e.g):

- Git - in case your Windows box already has Git Installed
- Windows network drive (if your box already has network drives mounted)
- HTTP(S) URL, i.e. a web server (e.g. Apache or NginX Web server hosting static content, Artifactory, Box, Google Drive, etc ...)

Example of Downloading script with Powershell:

```
# Directly from GitHub
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ohollmen/WinDDS/main/winsetup.ps1" -OutFile "winsetup.ps1"
# From your local (e.g. intranet) webserver
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
# OR ... just simply pass config as $args[0]
.\winsetup.ps1 C:\Users\mrsmith\postinstall.conf.json
```

### Using and Customizing Script

At current state the library of operations is mixed together with
calling sequence operations in one file. Ideally the library and calling
sequence should be separated (for ease of distribution and minimizing number of files,
the current solution is good though).

If needed, customize the operations sequence at the bottom of the script to fit
your use-case. On the other hand to disable/skip certain operation it is usually
enough to leave respective JSON config empty (e.g. empty array), which
means no operations are run for that section.

### Creating a "Setup Bundle"

To make your automation runnable "modularly", it pays off to place your setup configs in multiple JSON files as opposed to single monolithic file.
This way ou can run a "single aspect" of your setup automation in isolation ("modularly"). You could alternatively create a monolitic wrapper (PS) script
to "run" all JSON files in "single shot".

"Setup Bundles" are a way to package your complete automation which often consists of:
- Registry "patch" files (*.reg)
- Group Policies exported (by "LGPO.exe", from a proto-type machine) that are importable (Either directory tree or dir tree packaged into a ZIP file) by winsetup "gp" (group policy) task type
- The winsetup JSON setup files (typically more than one)
- Misc executable binaries (*.exe) needed to carry out tasks within setup automation
- Misc other files (text, scripts, config files, ...)

Suggestions / ways to create "Setup Bundles":
- Zip-up Exported Policies directory tree into a ZIP files (which will then be zipped into an outer Zip file - a Zip within a Zip) to keep the number of files down
  - During setup the Zip can be unzipped on-the-fly (as part of setup)
- Create a manifest (e.g. manifest.txt) file listing all the files (as relative filenames or glob patterns)
- It is a good idea to to create the bundle on Linux or MacOS computer as these OSs have superior tools (such as make, zip, unzip, xargs) for automating the "Setup Bundle" zip creation
  (You should probably should use make+Makefile for this)
- Document your bundle by explaining the
  - Unzipping of the bundle
  - way to run the single or multiple commands to run various automations contained in a bundle.
- Test the bundle (following the documentation) before making it available to users.

## TODO
- Make usable as library
- Add "does not exist" guards on each operation handler (to not have even arrays for ops)
- Research/learn/use a good (built-in) CL arg parsing toolkit to parametrize launching from CL and provide more options / flexibility
