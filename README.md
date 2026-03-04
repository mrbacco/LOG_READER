# LOG_READER

Offline log reader with CLI + web UI.

Supported log types:
- `syslog-rfc3164`
- `syslog-rfc5424`
- `cef`
- `leef`
- `access` (Apache/Nginx)
- `json`
- `netflow`
- `ipfix`

CLI:
```powershell
python .\syslog_reader.py -f .\INDUSTRY_LOGS.log --type netflow,ipfix
python .\syslog_reader.py -f .\INDUSTRY_LOGS.log --level err,warning
```

Web app:
```powershell
python .\syslog_web.py
```
Open `http://127.0.0.1:8000` and use the `Types` filter field.
