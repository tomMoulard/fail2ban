# Fail2ban plugin for traefik

[![Build Status](https://github.com/tomMoulard/fail2ban/actions/workflows/main.yml/badge.svg)](https://github.com/tomMoulard/fail2ban/actions/workflows/main.yml)

This plugin is an implementation of a Fail2ban instance as a middleware
plugin for Traefik. It can optionally integrate with Cloudflare's firewall to block IPs at the edge.

## Middleware

After installing the plugin, it can be configured through a Middleware, e.g.:

```yml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: fail2ban-test
spec:
  plugin:
    fail2ban:
      logLevel: DEBUG
      denylist:
        ip: 127.0.0.1
```

## Cloudflare Integration

The plugin can optionally use Cloudflare's API to block IPs at the edge. When enabled, IPs will be blocked using Cloudflare's firewall rules instead of just locally.

To use this feature, you need to:
1. Create a Cloudflare API token with the `Zone:Permissions:Access: Apps and Policies: Edit` permission
2. Get your Zone ID from the Cloudflare dashboard
3. Configure the plugin with your Cloudflare credentials

Example configuration with Cloudflare:

```yml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: fail2ban-cloudflare
spec:
  plugin:
    fail2ban:
      cloudflare:
        enabled: true
        apiToken: "your-cloudflare-api-token"
        zoneId: "your-cloudflare-zone-id"
        ipHeader: "CF-Connecting-IP"  # or "X-Forwarded-For"
        maxRetries: 3  # number of retries for API calls
        retryDelay: 1  # delay between retries in seconds
      persistencePath: "/data/blocked-ips.json"
      allowlist:
        # Important: When using Cloudflare, make sure to allowlist their IPs
        ip: "173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22"
      rules:
        bantime: "3h"
        findtime: "10m"
        maxretry: 4
        enabled: true
```

### Cloudflare Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `enabled` | Enable Cloudflare integration | `false` |
| `apiToken` | Cloudflare API token | `""` |
| `zoneId` | Cloudflare Zone ID | `""` |
| `ipHeader` | Header to get real IP from (`CF-Connecting-IP` or `X-Forwarded-For`) | `"CF-Connecting-IP"` |
| `maxRetries` | Maximum number of retries for API calls | `3` |
| `retryDelay` | Delay between retries in seconds | `1` |

### Important Notes

1. When using Cloudflare integration, you must allowlist Cloudflare's IP ranges to prevent blocking their IPs.
2. The `ipHeader` setting is important as requests will come from Cloudflare's IPs. Use `CF-Connecting-IP` (recommended) or `X-Forwarded-For`.
3. API calls include retries with exponential backoff to handle temporary failures.
4. If the Cloudflare API calls fail, the plugin will log the error but continue operating locally.

## Configuration

Please note that the allowlist and denylist functionality described below can
_only_ be used _concurrently_ with Fail2ban functionality (if you are looking
for a way to allowlist or denylist IPs without using any of the Fail2ban
logic, you might want to use a different plugin.)

### Allowlist
You can allowlist some IP using this:
```yml
testData:
  allowlist:
    files:
      - "tests/test-ipfile.txt"
    ip:
      - "::1"
      - "127.0.0.1"
```

Where you can use some IP in an array of files or directly in the
configuration.

If you have a single IP, this: `ip: 127.0.0.1` should also work.

### Denylist
Like allowlist, you can denylist some IP using this:
```yml
testData:
  denylist:
    files:
      - "tests/test-ipfile.txt"
    ip:
      - "::1"
      - "127.0.0.1"
```

Where you can use some IP in an array of files or directly in the
configuration.

Please note that Fail2ban logs will _only_ be visible when Traefik's log level
is set to `DEBUG`.

## Fail2ban
We plan to use all default fail2ban configuration but at this time only a
few features are implemented:
```yml
testData:
  rules:
    urlregexps:
    - regexp: "/no"
      mode: block
    - regexp: "/yes"
      mode: allow
    bantime: "3h"
    findtime: "10m"
    maxretry: 4
    enabled: true
    statuscode: "400,401,403-499"
```

Where:
 - `findtime`: is the time slot used to count requests (if there is too many
requests with the same ip in this slot of time, the ip goes into ban). You can
use 'smart' strings: "4h", "2m", "1s", ...
 - `bantime`: correspond to the amount of time the IP is in Ban mode.
 - `maxretry`: number of request before Ban mode.
 - `enabled`: allow to enable or disable the plugin (must be set to `true` to
enable the plugin).
 - `urlregexp`: a regexp list to block / allow requests with regexps on the url
 - `statuscode`: a comma separated list of status code (or range of status
codes) to consider as a failed request.

#### URL Regexp
Urlregexp are used to defined witch part of your website will be either
allowed, blocked or filtered :
- allow : all requests where the url match the regexp will be forwarded to the
backend without any check
- block : all requests where the url match the regexp will be stopped

##### No definitions

```yml
testData:
  rules: {}
```

By default, fail2ban will be applied.

##### Multiple definition

```yml
testData:
  rules:
    urlregexps:
    - regexp: "/whoami"
      mode: allow
    - regexp: "/do-not-access"
      mode: block
```

In the case where you define multiple regexp on the same url, the order of
process will be :
1. Block
2. Allow

In this example, all requests to `/do-not-access` will be denied and all
requests to `/whoami` will be allowed without any fail2ban interaction.

#### Status code
When this configuration is set (i.e., `statuscode` is not empty), the plugin
will wait for the request to be completed and check the status code of the
response. If the status code is in the list of status codes, the request will
be considered as a failed request.

Note that the request is considered completed when the response is back sent to the
plugin, therefore, the request went through the middleware, traefik, to the backend,
and back to the middleware.

<details>
<summary>Here is a little schema to explain the process</summary>

```mermaid
sequenceDiagram
    actor C as Client
    participant A as Middleware
    participant B as Backend
    C->>A: Request
    A->>B: Request
    B->>A: Response
    A->>A: Check status code
    critical [Check status code]
    option Invalid status code
        A--X C: Log error
    option valid status code
        A->>C: Log error
    end
```

</details>

#### Schema
First request, IP is added to the Pool, and the `findtime` timer is started:
```
A |------------->
  ↑
```

Second request, `findtime` is not yet finished thus the request is fine:
```
A |--x---------->
     ↑
```

Third request, `maxretry` is now full, this request is fine but the next wont.
```
A |--x--x------->
        ↑
```

Fourth request, too bad, now it's jail time, next request will go through after
`bantime`:
```
A |--x--x--x---->
           ↓
B          |------------->
```

Fifth request, the IP is in Ban mode, nothing happen:
```
A |--x--x--x---->
B          |--x---------->
              ↑
```

Last request, the `bantime` is now over, another `findtime` is started:
```
A |--x--x--x---->            |------------->
                             ↑
B          |--x---------->
```

## How to dev

```bash
$ docker compose up
```

# Authors
| Tom Moulard | Clément David | Martin Huvelle | Alexandre Bossut-Lasry |
|-------------|---------------|----------------|------------------------|
|[![](https://github.com/tomMoulard/fail2ban/blob/main/.assets/gopher-tom_moulard.png)](https://tom.moulard.org)|[![](https://github.com/tomMoulard/fail2ban/blob/main/.assets/gopher-clement_david.png)](https://github.com/cledavid)|[![](https://github.com/tomMoulard/fail2ban/blob/main/.assets/gopher-martin_huvelle.png)](https://github.com/nitra-mfs)|[![](https://github.com/tomMoulard/fail2ban/blob/main/.assets/gopher-alexandre_bossut-lasry.png)](https://www.linkedin.com/in/alexandre-bossut-lasry/)|
