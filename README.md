# CloudPanel Log Viewer

A simple, interactive Python-based command-line tool to view and analyze CloudPanel logs in a human-readable format with IP geolocation support.

## Features

- **Interactive Navigation** - Easy menu-driven interface with back/quit options at every step
- **Multiple Log Types** - View PHP, Nginx, and Varnish Cache logs
- **Human-Readable Output** - Parsed log entries displayed with labeled fields
- **IP Geolocation** - Automatically shows country and city for each IP address using [seeip.org](https://seeip.org) API
- **Color-Coded Output** - Status codes and log levels are color-coded for quick identification
- **Server IP Filter** - Option to filter out requests from the server's own public IP
- **Multi-User Support** - Browse logs from any user on the system

## Requirements

- Python 3.x
- `sudo` privileges (required to read log files)
- CloudPanel installed with logs in `/home/{user}/logs/`

## Installation

1. Download the script:
```bash
curl -o cloudpanel-log-viewer.py https://raw.githubusercontent.com/gabirosca/cloudpanel-log-viewer/main/cloudpanel-log-viewer.py
```

2. Make it executable:
```bash
chmod +x cloudpanel-log-viewer.py
```

3. (Optional) Move to a directory in your PATH for global access:
```bash
sudo mv cloudpanel-log-viewer.py /usr/local/bin/cloudpanel-log-viewer
```

## Usage

Run with sudo:
```bash
sudo python3 cloudpanel-log-viewer.py
```

Or if installed globally:
```bash
sudo cloudpanel-log-viewer
```

## Navigation

| Key | Action |
|-----|--------|
| `1-9` | Select option |
| `b` | Go back to previous menu |
| `q` | Quit |
| `f` | Toggle server IP filter |

## Example Output

```
──────────────────────────────────────────────────
Entry #1
──────────────────────────────────────────────────
  Remote Address:  8.8.8.8 (United States, Los Angeles)
  Time Local:      19/Jan/2026:01:52:06 +0200
  Method:          GET
  Request Path:    /
  Protocol:        HTTP/2.0
  Status Code:     200
  Bytes Sent:      1234
  User Agent:      Mozilla/5.0...
```

## Color Coding

**Status Codes:**
- 🟢 Green: 2xx (Success)
- 🔵 Cyan: 3xx (Redirect)
- 🟡 Yellow: 4xx (Client Error)
- 🔴 Red: 5xx (Server Error)

**Log Files:**
- 🟢 Green: Current logs (`access.log`, `error.log`, `purge.log`)
- ⚫ Dimmed: Rotated logs with date suffix

## License

MIT License - feel free to use and modify as needed.

---

## Support

If you find this tool useful, consider buying me a coffee!


[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/gabrielrosca)
