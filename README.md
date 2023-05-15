# network_scripts
Some scripts for network stuff like proxies. All scripts are meant to be self-contained and can be started as a docker container.

# Content
Currently, this repository contains

- [x] echo: A simple TCP echo server
- [x] proxy: A simple proxy server hardcoded for one domain
- [ ] record frag proxy: A proxy server that fragments client hello's
- 

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