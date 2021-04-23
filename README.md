# Fail2ban plugin for traefik

[![Build Status](https://travis-ci.com/tomMoulard/fail2ban.svg?branch=main)](https://travis-ci.com/tomMoulard/fail2ban)

This plugin is a small implementation of a fail2ban instance as a middleware
plugin for Traefik.

## Configuration
### Whitelist
You can whitelist some IP using this:
```yml
testData:
  whitelist:
    files:
      - "tests/test-ipfile.txt"
    ip:
      - "::1"
      - "127.0.0.1"
```

Where you can use some IP in an array of files or directly in the config.

### Blacklist
Like whitelist, you can blacklist some IP using this:
```yml
testData:
  blacklist:
    files:
      - "tests/test-ipfile.txt"
    ip:
      - "::1"
      - "127.0.0.1"
```

Where you can use some IP in an array of files or directly in the config.

### Configuration debug
In order to check if the configuration is correct, there should be some logs
on stdout like:
```
Fail2Ban_config: 2020/12/27 22:40:04 restricted.go:51: Whitelisted: '127.0.0.2/32'
Fail2Ban_config: 2020/12/27 22:40:04 restricted.go:51: Blacklisted: '127.0.0.3/32'
Fail2Ban_config: 2020/12/27 22:40:04 restricted.go:51: Bantime: 3h0m0s
Fail2Ban_config: 2020/12/27 22:40:04 restricted.go:51: Findtime: 3h0m0s
Fail2Ban_config: 2020/12/27 22:40:04 restricted.go:51: Ports range from 0 to 8000
Fail2Ban_config: 2020/12/27 22:40:04 restricted.go:51: FailToBan Rules : '{Xbantime:3h0m0s Xfindtime:3h0m0s Xurlregexp:[localhost:5000/whoami] Xmaxretry:4 Xenabled:true Xports:[0 8000]}'
Fail2Ban: 2020/12/27 22:40:04 restricted.go:52: Plugin: FailToBan is up and running
```

## Fail2ban
We plan to use all [default fail2ban configuration]() but at this time only a
few features are implemented:
```yml
testData:
  rules:
    urlregexps:
    - regexp: "/no"
      mode: block
    - regexp: "/yes"
      mode: allow
    - regexp: "/whoami"
      mode: filter
    bantime: "3h"
    findtime: "10m"
    maxretry: 4
    enabled: true
    ports: "80:443"
```

Where:
 - `findtime`: is the time slot used to count requests (if there is too many
requests with the same ip in this slot of time, the ip goes into ban). You can
use 'smart' strings: "4h", "2m", "1s", ...
 - `bantime`: correspond to the amount of time the IP is in Ban mode.
 - `maxretry`: number of request before Ban mode.
 - `enabled`: allow to enable or disable the plugin (must be set to `true` to
enable the plugin).
 - `urlregexp`: a regexp list to block / allow / filter requests with regexps on the url
 - `ports`: filter requests by port range

#### URL Regexp
Urlregexp are used to defined witch part of your website will be either allowed, blocked or filtered :
- allow : all requests where the url match the regexp will be forwarded to the backend without any check
- block : all requests where the url match the regexp will be stopped

##### Minimal

```yml
testData:
  rules:
    urlregexps:
    - regexp: "/admin*"
      mode: block
    bantime: "3h"
    findtime: "10m"
    maxretry: 4
    enabled: true
    ports: "80:443"
```

The minimal definition will be a wildcard `*` and fail2ban will be applied in all matching urls.

##### No definitions

```yml
testData:
  rules:
    bantime: "3h"
    findtime: "10m"
    maxretry: 4
    enabled: true
    ports: "80:443"
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
    bantime: "3h"
    findtime: "10m"
    maxretry: 4
    enabled: true
    ports: "80:443"
```

In the case where you define multiple regexp on the same url, the order of process will be :
1. Allow
2. Block

In this example, all requets to `/whoami` will be denied.

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

## Dev `traefik.yml` configuration file for traefik

```yml
pilot:
  token: [REDACTED]

experimental:
  devPlugin:
    goPath: /home/${USER}/go
    moduleName: github.com/tommoulard/fail2ban

entryPoints:
  http:
    address: ":8000"
    forwardedHeaders:
      insecure: true

api:
  dashboard: true
  insecure: true

providers:
  file:
    filename: rules-fail2ban.yaml
```

## How to dev
```bash
$ docker run -d --network host containous/whoami -port 5000
# traefik --configfile traefik.yml
```

# Authors
| Tom Moulard | Clément David | Martin Huvelle | Alexandre Bossut-Lasry |
|-------------|---------------|----------------|------------------------|
|[![](img/gopher-tom_moulard.png)](https://tom.moulard.org)|[![](img/gopher-clement_david.png)](https://github.com/cledavid)|[![](img/gopher-martin_huvelle.png)](https://github.com/nitra-mfs)|[![](img/gopher-alexandre_bossut-lasry.png)](https://www.linkedin.com/in/alexandre-bossut-lasry/)|
