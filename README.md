# davigeek's server manager v1.0

C++ program (made for ubuntu/linux but also windows) that manages all your minecraft server folders installed in a certain directory, via an http-served web interface.

## build

needs a C++17 compiler and CMake 3.16+

> cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

> cmake --build build --config Release

## run

> ./build/servermanager --dir /your/path/to/servers --port 8080

then open `http://<server-ip>:8080` from any device on your network.

## where things are stored

- settings: `~/.config/servermanager/config.json` (on Windows `%APPDATA%\servermanager`; override with the `SERVERMANAGER_HOME` environment variable)
- per-server settings (loader, version, memory, java): `~/.config/servermanager/servers/<server name>.json`
- remembered options: `~/.config/servermanager/detected.json`, so a server keeps its loader and version if its files later stop telling it what it is

## notes

- curseforge mod downloading needs a free API key (console.curseforge.com), added in settings.

> [!CAUTION]
> !! there is no login. anyone on your network can open the page, so don't port-forward it to the internet. !!
