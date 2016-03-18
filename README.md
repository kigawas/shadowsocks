shadowsocks-learning
===========

Shadowsocks with comments which are helpful to understand its structure.

This code is only used for learning Python.

## Project structure

1. `asyncdns.py`: Handling DNS requests.
2. `common.py`: Wrapping some functions to make them easier to use.
  - `ord`,`chr` to convert between `int` and `char` just like `C`. The default `ord` and `chr` functions in `Python` have been replaced.
  - `socket.inet_pton`, `socket.inet_ntop` to convert IP string and network bytes. If `socket` does not have the 2 functions (e.g. Before `Python 2.3`), the author implemented them.

  > Notice that `socket.inet_pton` can handle IPV4 and IPV6 addresses, yet `socket.inet_aton` cannot handle IPV6.
  
  - `parse_header`, `pack_addr` network utility functions.
  - `IPNetwork` class which saves IP addresses with prefixes.
3. `daemon.py`: Make Shadowsocks run as a daemon in *NIX.
4. `encrypt.py`: Encrypt/Decrypt Shadowsocks's protocol to circumvent GFW
5. `eventloop.py`: Use `select`,`epoll`, `kqueue` to multiplex I/O
6. `local.py`: Client code using SOCKS to set up a proxy and transfer packets.
7. `lru_cache.py`: LRU cache for DNS caching in `asyncdns.py`.
8. `manager.py`: A config manager.
9. `server.py`: Server code requesting remote sites and sending back responses to clients.
10. `shell.py`: Prompting and handling configs in shell.
11. `tcprelay.py`: Connecting remote servers by TCP.
12. `udprelay.py`: Connecting remote servers by UDP.
