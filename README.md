shadowsocks-learning
===========

Shadowsocks with comments which are helpful to understand its structure.

This code is only used for learning Python.

## Project structure

1. `asyncdns.py`: Handling DNS requests.
2. `common.py`: Wrapping some functions to make them easier to use.
  - `ord`,`chr` to convert between `int` and `char` just like C. The default `ord` and `chr` functions in Python have been replaced.
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

The core modules are `asyncdns.py`, `eventloop.py`, `tcprelay.py`, `udprelay.py`. `local.py` and `server.py` are just wrapping them up.


## Evolution of Shadowsocks
At first, Shadowsocks only uses [*substitution cypher*](https://en.wikipedia.org/wiki/Substitution_cipher) to cypher the packets, which is thought to be very **unsafe**. In addition, in the early version of Shadowsocks, there are only 2 core modules: `local.py` and `server.py`. Due to its concision, we take [this](https://github.com/kigawas/shadowsocks-learning/tree/8c5c40915ea8fbd22a0f1a6a9596010565118b35) version as an example to explain the underground mechanism of Shadowsocks.

Firstly, we check the `local.py`.
We can see the author build a table to make substitutions of ASCII characters.
```python
def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)
    table = [c for c in string.maketrans('', '')]
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table
```

Then comes a TCP Server with multi-threading. You can find a usage at [here](https://docs.python.org/2/library/socketserver.html#asynchronous-mixins).
```python
class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass
```
