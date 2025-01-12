# Fail2ban plugin for traefik

[![Build Status](https://github.com/tomMoulard/fail2ban/actions/workflows/main.yml/badge.svg)](https://github.com/tomMoulard/fail2ban/actions/workflows/main.yml)

This plugin is an implementation of a Fail2ban instance as a middleware
plugin for Traefik.

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

<details>
<summary>Add the middleware to an ingressroute</summary>

```yml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: simplecrd
  namespace: default
spec:
  entryPoints:
    - web
  routes:
  - match: Host(`fail2ban.localhost`)
    kind: Rule
    middlewares:
    - name: fail2ban-test
    services:
    ...
```

</details>

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

## Notifications

The fail2ban middleware supports sending notifications through multiple channels when ban/unban events occur. The following notification channels are supported:

- Telegram
- Discord Webhooks  
- Email (SMTP)
- Custom Webhooks

### Channel-Specific Features

#### Telegram
- Supports HTML formatting
- Full template customization
- Supports all template variables

#### Discord
- Uses embedded message format
- Customizable webhook username and avatar
- Configurable title
- Fields: IP Address, Ban Duration
- Red color for ban events, green for unban events
- Timestamp display

#### Email
- HTML email format
- Customizable subject line
- Supports all template variables
- Maintains persistent SMTP connection
- TLS support

#### Custom Webhooks
- Configurable HTTP method
- Custom headers support
- Full template customization
- JSON payload format

### Template Variables

The following variables are available for template customization (except Discord):

- `{{.IP}}` - The IP address that triggered the event
- `{{.Message}}` - Event message/reason
- `{{.Timestamp}}` - Event timestamp (format: "2006-01-02 15:04:05")
- `{{.Duration}}` - Ban duration (only available for ban events)

### Default Templates

If no custom templates are provided, these defaults will be used:


### Configuration

Notifications can be configured in the middleware config:

```yml
testData:
  notifications:
    # List of event types to notify on (ban, unban)
    allowedTypes: ["ban", "unban"]
    
    # Telegram configuration
    telegram:
      enabled: true
      botToken: "your-bot-token" 
      chatId: "your-chat-id"
      templates:
        ban: "🚫 IP Ban Alert\nIP: {{.IP}}\nReason: {{.Message}}"
        unban: "✅ IP Unban Alert\nIP: {{.IP}}"

    # Discord webhook configuration  
    discord:
      enabled: true
      webhookUrl: "your-webhook-url"
      title: "🚫 IP Ban Details"
      username: "Fail2Ban Bot"
      avatarUrl: "https://example.com/avatar.png"

    # Email configuration
    email:
      enabled: true
      server: "smtp.example.com"
      port: 587
      username: "user@example.com" 
      password: "password"
      from: "from@example.com"
      to: "to@example.com"
      templates:
        ban: "{{.IP}} banned for {{.Duration}}"
        unban: "{{.IP}} unbanned"

    # Custom webhook configuration
    webhook:
      enabled: true
      url: "https://example.com/webhook"
      method: "POST"
      headers:
        Authorization: "Bearer token"
      templates:
        ban: "IP {{.IP}} has been banned"
        unban: "IP {{.IP}} has been unbanned"
```

### Templates

Each notification channel supports customizable message templates using Go template syntax. The following variables are available:

- `{{.IP}}` - The IP address that triggered the event
- `{{.Message}}` - Event message/reason
- `{{.Timestamp}}` - Event timestamp
- `{{.Duration}}` - Ban duration (only available for ban events)

If no custom templates are provided, default templates will be used for each event type:

```yml
# Default Ban Template
🚫 IP Ban Alert
IP: {{.IP}}
Reason: {{.Message}}
Time: {{.Timestamp.Format "2006-01-02 15:04:05"}}
Duration: {{.Duration}}

# Default Unban Template
✅ IP Unban Alert
IP: {{.IP}}
Reason: {{.Message}}
Time: {{.Timestamp.Format "2006-01-02 15:04:05"}}

# Default Notice Template
ℹ️ Notice
IP: {{.IP}}
Message: {{.Message}}
Time: {{.Timestamp.Format "2006-01-02 15:04:05"}}
```

## How to dev

```bash
$ docker compose up
```

# Authors
| Tom Moulard | Clément David | Martin Huvelle | Alexandre Bossut-Lasry |
|-------------|---------------|----------------|------------------------|
|[![](https://github.com/tomMoulard/fail2ban/blob/main/.assets/gopher-tom_moulard.png)](https://tom.moulard.org)|[![](https://github.com/tomMoulard/fail2ban/blob/main/.assets/gopher-clement_david.png)](https://github.com/cledavid)|[![](https://github.com/tomMoulard/fail2ban/blob/main/.assets/gopher-martin_huvelle.png)](https://github.com/nitra-mfs)|[![](https://github.com/tomMoulard/fail2ban/blob/main/.assets/gopher-alexandre_bossut-lasry.png)](https://www.linkedin.com/in/alexandre-bossut-lasry/)|
