# Fail2ban plugin for traefik

[![Build Status](https://travis-ci.com/tomMoulard/fail2ban.svg?branch=main)](https://travis-ci.com/tomMoulard/fail2ban)

This plugin is a small implementation of a fail2ban instance as a widdleware
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

## Fail2ban
We plan to use all [default fail2ban configuration]() but at this time only a
few features are implemented:
```yml
testData:
  rules:
    bantime: "3h"
    findtime: "10m"
    maxretry: 4
    enabled: true
```

Where:
 - `findtime`: is the time slot used to count requests (if there is too many
requests with the same ip in this slot of time, the ip goes into ban). You can
use 'smart' strings: "4h", "2m", "1s", ...
 - `bantime`: correspond to the amount of time the IP is in Ban mode.
 - `maxretry`: number of request before Ban mode.
 - `enabled`: allow to enable or disable the plugin (must be set to `true` to
enable the plugin).

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
# traefik --config-file traefik.yml
```
