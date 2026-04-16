# Tachyon-Detours
Detour based utilities to connect WLM 14 to Tachyon.
They are made to be compatible with other third party servers.

## Components
 - **Zathras**: DLL that allows msnmsgr.exe & wlcomm.exe to connect to Tachyon
 - **Draal**: EXE runtime patcher, injects & remove dlls from exe import table
 - **Epsilon3**: DLL that manages a single instance of the server using the clients lifecycle (start & stop)

## Zathras
Zathras is the backbone of Tachyon.
It disarms the client and allows it to connect to local servers.

### Features
- [X] Signature check bypass for ppcrlbin & msnmsgr.exe
- [X] msnmsgr.exe firewall check redirect 
- [X] Disable SSL & redirect to localhost (with exception support)
- [X] ppcrlbin registry URL redirect
- [X] identityCRL environment patch
- [X] identityCRL WebAuthUrl redirect 
- [X] wlmcomm.exe COM Redirect

```
- Zathras is Zathras, pronounced Zathras.
- Zathras using detours dll also
- Zathras helps with Tachyon operations.
- Zathras works great machine
- No one listens to Zathras...
```

## Draal
Draal is the first stage, it crates the process and modify it's import table.

### Features
- [x] exe import table add imports
- [x] exe import table remove imports
- [x] argument passthrough & workdir (for COM invocations) 
- [x] config file

## Epsilon3
Small DLL that handles starting and stopping the server with the client.

### Features
- [x] Manage one instance of the server
## Building

You need Visual Studio 2019 with Windows XP Build Tools (v140) installed and C++ support.
