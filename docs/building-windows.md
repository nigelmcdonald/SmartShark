# Building SmartShark on Windows

SmartShark is a Wireshark plugin, so it is built inside a Wireshark source build. The plugin DLL only loads into a Wireshark that matches it exactly: the same Wireshark version, the same Qt version and a compatible MSVC toolchain.

Current target: **Wireshark 4.6.0** with **Qt 6.9.3**, built with **MSVC 14.44** (Visual Studio 2022).

## 1. Tools

| Tool | Notes |
|---|---|
| Visual Studio 2022 (Community or Build Tools) | "Desktop development with C++" workload, including "C++ CMake tools for Windows". Provides MSVC, CMake and Ninja. |
| Python 3 | From python.org. |
| Git | From git-scm.com. |
| WinFlexBison 2.5.25 | Portable zip from https://github.com/lexxmark/winflexbison/releases. Unzip it; no install needed. |
| Qt 6.9.3, MSVC 2022 64-bit | Installed with [aqtinstall](https://github.com/miurahr/aqtinstall), no Qt account needed (see below). |

By default the scripts expect everything under `D:\SmartShark-dev`:

```
D:\SmartShark-dev\
  Qt\6.9.3\msvc2022_64\     Qt
  tools\winflexbison\       win_flex.exe, win_bison.exe
  wireshark\                Wireshark source at tag v4.6.0
  wslibs\                   third-party libraries (CMake downloads these)
  build\                    build output
  tmp\                      build temp files
```

To use other locations, set `SMARTSHARK_DEV` (or the individual variables at the top of `scripts\dev-env.cmd`) before running the scripts.

### Qt with aqtinstall

```
py -3 -m venv D:\SmartShark-dev\tools\aqt-venv
D:\SmartShark-dev\tools\aqt-venv\Scripts\python -m pip install aqtinstall
D:\SmartShark-dev\tools\aqt-venv\Scripts\aqt install-qt windows desktop 6.9.3 win64_msvc2022_64 -O D:\SmartShark-dev\Qt -m qt5compat qtmultimedia qtimageformats
```

### Wireshark source

```
git clone --depth 1 --branch v4.6.0 https://gitlab.com/wireshark/wireshark.git D:\SmartShark-dev\wireshark
```

## 2. Configure

```
scripts\configure.cmd
```

This creates a directory junction from `wireshark\plugins\epan\smartshark` to this repository's `plugin\` folder, then runs CMake with `-DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/smartshark`. The first run downloads Wireshark's third-party library bundle (about 640 MB).

**Known issue (November 2026):** docbook.org no longer serves `docbook-5.0.1.zip`, which Wireshark 4.6.0 downloads for its documentation tools, so configure fails with `Unable to download docbook-5.0.1.zip`. The Internet Archive has an identical copy (SHA-256 `7af9df452410e035a3707883e43039b4062f09dc2f49f2e986da3e4c0386e3c7`, the hash Wireshark pins). Put it in `wireshark\_download\` and configure again:

```
curl -L -o D:\SmartShark-dev\wireshark\_download\docbook-5.0.1.zip "https://web.archive.org/web/2024id_/https://docbook.org/xml/5.0.1/docbook-5.0.1.zip"
```

## 3. Build

```
scripts\build.cmd
```

The first build also compiles the Wireshark libraries the plugin links against, which takes a while. Later builds only rebuild the plugin. The result is `build\run\plugins\4.6\epan\smartshark.dll`.

## 4. Install for testing

Copy the DLL into your personal Wireshark plugin folder (no admin rights needed):

```
scripts\install.cmd
```

This copies `smartshark.dll` to `%APPDATA%\Wireshark\plugins\4.6\epan\`. Restart Wireshark, then check **Help > About Wireshark > Plugins** for `smartshark.dll`, and look for **Tools > SmartShark**.

## Common pitfalls

- Running the scripts from Git Bash sets `MSYSTEM`, which makes Wireshark's CMake assume an MSYS2 build and skip the Windows library bundle. `dev-env.cmd` clears it.
- Do not name a batch variable `LINK`: the MSVC linker reads `%LINK%` as extra command-line input.
