<div align="center">

# Telegram Proxy

A local MTProto/WSS proxy for Telegram Desktop on Windows

[Русский](README.ru.md) | [**English**](README.md)

![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?style=flat-square)
![Architecture](https://img.shields.io/badge/architecture-x64-555555?style=flat-square)
![Transport](https://img.shields.io/badge/transport-MTProto%20%2B%20WSS-26A5E4?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-2EA44F?style=flat-square)

</div>

## Overview

Telegram Proxy creates a local endpoint at `127.0.0.1:15444` and forwards Telegram Desktop traffic using MTProto over secure WebSocket connections.

The application prepares direct connections to Telegram's primary data centers in advance to reduce connection time and latency. If a direct route is unavailable, it automatically switches to a fallback WSS route.

## Architecture

```text
Telegram Desktop
       |
       | MTProto, 127.0.0.1:15444
       v
Telegram Proxy
       |
       | WSS / TLS
       v
Telegram infrastructure
```

Most traffic is routed directly to Telegram infrastructure. Fallback WSS endpoints are used only when a direct connection cannot be established.

## Quick start

1. Download the repository using **Code → Download ZIP**.
2. Extract the archive into a separate folder.
3. Run `telegram.bat`.
4. Confirm that you want to add the proxy in Telegram Desktop.

Running `telegram.bat` again does not create a second process. Use `stop.bat` to stop the proxy.

### Connection settings

| Setting | Value |
| --- | --- |
| Type | MTProto |
| Server | `127.0.0.1` |
| Port | `15444` |
| Secret | added automatically |

## Security and encryption

The proxy accepts connections only from the current computer and does not expose its port to the external network. It does not request account credentials, store messages, or log connection contents.

AES obfuscation is part of the MTProto transport used by the proxy. The external connection is protected with TLS/WSS, while application-level data encryption is handled by Telegram Desktop.

No diagnostic log is created by default. If you need one, stop the regular process and run:

```bat
src\telegram-proxy.exe --port 15444 --log
```

## Troubleshooting

| Problem | Solution |
| --- | --- |
| Telegram takes a long time to connect | Run `stop.bat`, then run `telegram.bat` again |
| Port `15444` is already in use | Close the application using it or change the port in `telegram.bat` |
| Telegram does not offer to add the proxy | Open the link from `telegram.bat` again or enter the settings manually |
| Diagnostics are required | Stop the proxy and run the EXE with the `--log` option |

Latency and availability depend on your ISP, region, and current network routing.

## Project structure

```text
telegram-proxy/
├── src/
│   ├── main.c
│   └── telegram-proxy.exe
├── LICENSE.txt
├── README.md
├── README.ru.md
├── stop.bat
└── telegram.bat
```

| File | Purpose |
| --- | --- |
| `telegram.bat` | starts the proxy and opens the proxy settings in Telegram Desktop |
| `stop.bat` | stops the local proxy process |
| `src/telegram-proxy.exe` | ready-to-run application for Windows x64 |
| `src/main.c` | application source code |
| `LICENSE.txt` | MIT License text |

## System requirements

- Windows 10 or Windows 11 x64;
- Telegram Desktop;
- network access.

## License

This project is distributed under the [MIT License](LICENSE.txt).

Copyright (c) 2026 itzalexdev.
