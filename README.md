# Tachyon-Detours
Detour based utilities to connect WLM 14 to Tachyon

The goal is to be compatible with existing third party servers using static patched binaries

## Components
 - **Draal**: An executable that starts a process and patches it's import table
 - **Zathras**: A rerouting DLL that makes the client connect to our server, amongst other things
 - **Epsilon3**: A DLL that manages one instance of the server (starting and stopping) tied to the clients lifecycle.

## Draal
Draal creates processes in SUSPENDED mode, and then patches it's import table.
You can specify in a configuration file which dlls to remove and which to add.
Draal is compatible with COM invocations since it passes through the working directory of the target process and the command line arguments it receives.

### Features
- [x] exe import table add imports
- [x] exe import table remove imports
- [x] argument passthrough & workdir (for COM invocations) 
- [x] config file


## Zathras
Zathras is the backbone of Tachyon.
It disarms the client and allows it to connect to local servers.

### Features
- [X] Signature check bypass for ppcrlbin & msnmsgr.exe
- [X] msnmsgr.exe firewall check redirect
- [X] Disable SSL & redirect to localhost (with whitelist support)
- [X] ppcrlbin registry URL redirect
- [X] identityCRL environment patch
- [X] identityCRL WebAuthUrl redirect
- [X] Contacts COM Server redirection to another CLSID

```
- Zathras is Zathras, pronounced Zathras.
- Zathras using detours dll also
- Zathras helps with Tachyon operations.
- Zathras works great machine
- No one listens to Zathras...
```

## Epsilon3
Small DLL that handles starting and stopping the server with the client.

### Features
- [x] Manage one instance of the server

## Building
You need Visual Studio 2019 with Windows XP Build Tools (v140) installed and C++ support.
