# rinetd-uv - Internet Redirection Server

rinetd-uv is a modernized implementation of the rinetd internet redirection server, rewritten to use the libuv event loop library.

https://github.com/marcin-gryszkalis/rinetd-uv

Originally by Thomas Boutell and Sam Hocevar. Rewritten to libuv by Marcin Gryszkalis with help from contributors and LLMs.

This implementation maintains backward compatibility with the original rinetd configuration format while providing significantly improved performance through modern event-driven I/O.

Released under the terms of the GNU General Public License, version 2 or later.

## Run

```
docker pull marcingryszkalis/rinetd-uv

docker run --rm marcingryszkalis/rinetd-uv:latest --version

docker run \
   --rm \
   --name rinetd-uv \
   --ulimit nofile=65000 \
   --publish 127.0.0.1:8080:8080 \
   --publish 127.0.0.1:53535:53535/udp \
   --volume ./rinetd-uv.conf:/etc/rinetd-uv.conf:ro \
   marcingryszkalis/rinetd-uv
```

