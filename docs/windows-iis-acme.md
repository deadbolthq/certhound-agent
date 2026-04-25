# Windows + IIS: ACME HTTP-01 setup

This is a known gotcha when running ACME HTTP-01 renewal on Windows behind IIS. If you're seeing renewal failures with a 404 from your ACME provider on the challenge URL, this is almost certainly the cause.

## The problem

Let's Encrypt verifies HTTP-01 challenges by fetching:

```
http://yourdomain.com/.well-known/acme-challenge/<token>
```

The `<token>` is a long random string with **no file extension**. IIS's static file handler refuses to serve files without a registered MIME type and returns 404 (technically 404.3 — "MIME type not configured"). The agent wrote the file correctly; IIS just won't serve it.

## The fix

Drop a scoped `web.config` into the challenge directory that maps the empty extension to `text/plain` and overrides the static file handler to serve everything in the folder:

**Path:** `C:\inetpub\wwwroot\.well-known\acme-challenge\web.config`

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <staticContent>
      <remove fileExtension="." />
      <mimeMap fileExtension="." mimeType="text/plain" />
    </staticContent>
    <handlers>
      <clear />
      <add name="StaticFile" path="*" verb="GET" modules="StaticFileModule" resourceType="Either" requireAccess="Read" />
    </handlers>
  </system.webServer>
</configuration>
```

The `<remove>` element prevents a duplicate-mapping error if anything upstream already defines an empty-extension mapping. This is scoped to just the challenge directory, so it doesn't affect the rest of your site.

## Writing the file from PowerShell

PowerShell here-strings can get garbled when pasted over RDP. The most reliable method is line-by-line ASCII writes:

```powershell
$path = "C:\inetpub\wwwroot\.well-known\acme-challenge\web.config"

Set-Content -Path $path -Value '<?xml version="1.0" encoding="utf-8"?>' -Encoding Ascii
Add-Content -Path $path -Value '<configuration>' -Encoding Ascii
Add-Content -Path $path -Value '  <system.webServer>' -Encoding Ascii
Add-Content -Path $path -Value '    <staticContent>' -Encoding Ascii
Add-Content -Path $path -Value '      <remove fileExtension="." />' -Encoding Ascii
Add-Content -Path $path -Value '      <mimeMap fileExtension="." mimeType="text/plain" />' -Encoding Ascii
Add-Content -Path $path -Value '    </staticContent>' -Encoding Ascii
Add-Content -Path $path -Value '    <handlers>' -Encoding Ascii
Add-Content -Path $path -Value '      <clear />' -Encoding Ascii
Add-Content -Path $path -Value '      <add name="StaticFile" path="*" verb="GET" modules="StaticFileModule" resourceType="Either" requireAccess="Read" />' -Encoding Ascii
Add-Content -Path $path -Value '    </handlers>' -Encoding Ascii
Add-Content -Path $path -Value '  </system.webServer>' -Encoding Ascii
Add-Content -Path $path -Value '</configuration>' -Encoding Ascii

iisreset
```

## Verifying the fix

Drop a fake extensionless file and fetch it:

```powershell
"test-content" | Out-File "C:\inetpub\wwwroot\.well-known\acme-challenge\test-no-ext" -Encoding ASCII -NoNewline

# From outside (replace with your hostname):
# curl http://yourdomain.com/.well-known/acme-challenge/test-no-ext
# Expect: test-content
```

If you get `test-content`, you're good. Clean up:

```powershell
Remove-Item "C:\inetpub\wwwroot\.well-known\acme-challenge\test-no-ext"
```

Then trigger a renewal:

```powershell
Restart-Service CertHoundAgent

# Watch logs
$latest = Get-ChildItem "C:\ProgramData\CertHound\logs\*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Get-Content $latest.FullName -Tail 30 -Wait
```

## Common failure modes

**Still 404 after dropping the web.config?**
Check the IIS log files at `C:\inetpub\logs\LogFiles\W3SVC1\` for the substatus code. `404.3` = MIME type issue (the web.config didn't take effect — try `iisreset`). `404.0` = file missing entirely.

**500 Internal Server Error?**
The web.config has invalid XML or refers to a locked configuration section. Curl from `http://localhost/...` on the VM itself — IIS returns detailed errors for loopback requests, including the line and HRESULT. Most common: `0x8007000d` ("Configuration file is not well-formed XML") meaning a paste mangled the file. Use the line-by-line write above.

**Challenge passes locally but fails from Let's Encrypt?**
Port 80 isn't reachable from the public internet. Check your firewall, security group, and (for home NAT) router port forwarding. Test with `curl http://yourdomain.com/.well-known/acme-challenge/test-no-ext` from a network *outside* your VM/host — phone hotspot is a quick way.

## Future: this should be automatic

Tracked in the polish backlog: the agent should auto-drop this `web.config` on first HTTP-01 renewal when running on Windows. Until then, this manual step is required.
