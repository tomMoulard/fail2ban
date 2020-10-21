# Header transformation plugin for traefik

[![Build Status](https://travis-ci.com/tomMoulard/htransformation.svg?branch=main)](https://travis-ci.com/tomMoulard/htransformation)

This plugin allow to change on the fly header's value of a request.

## Dev `traefik.yml` configuration file for traefik

```yml
pilot:
  token: [REDACTED]

experimental:
  devPlugin:
    goPath: /home/tm/go
    moduleName: github.com/tommoulard/htransformation

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
    filename: rules-htransformation.yaml
```

## How to dev
```bash
$ docker run -d --network host containous/whoami -port 5000
# traefik --config-file traefik.yml
```
