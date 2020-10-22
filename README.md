# Fail2ban plugin for traefik

[![Build Status](https://travis-ci.com/tomMoulard/fail2ban.svg?branch=main)](https://travis-ci.com/tomMoulard/fail2ban)

This plugin allow to change on the fly header's value of a request.

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
