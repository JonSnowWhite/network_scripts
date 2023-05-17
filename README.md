# network_scripts
Some scripts for network stuff like proxies. All scripts are meant to be self-contained and can be started as a docker container.

# Content
Currently, this repository contains

- [x] echo: A simple TCP echo server
- [x] proxy: A simple proxy server hardcoded for one domain
- [x] record frag proxy: A proxy server that fragments client hello's
- [ ] socksv4 functionality in proxy
- [ ] socksv5 functionality in proxy
- [ ] tcp fragmentation in proxy
- [ ] other circumvention techniques for http and tls in proxy
- [ ] quic functionality?

# Usage
## Prerequisites
For running the scripts from docker:
- Docker
- Docker-compose

For running the python scripts standalone:

- python3

## Docker
For example:
```bash
docker-compose up echo
```

## Scripts
```bash
python3 echo.py
```

Have fun!