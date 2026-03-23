# Tachyon-Detours
Detour based utilities to connect WLM 14 to Tachyon.
They are made to be compatible with other third party servers.

## Components
 - **Zathras**: DLL that allows msnmsgr.exe & wlcomm.exe to connect to Tachyon
 - **Draal**: EXE bootstrapper

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
Draal is a WIP exe that will start and monitor both msnmsgr.exe and Tachyon.exe

### Features
- [ ] msnmsgr.exe import table patch
- [ ] tachyon.exe start
- [ ] Monitoring

## Building

You need Visual Studio 2019 with Windows XP Build Tools (v140) installed and C++ support.
