# shadowsocks-learning

Shadowsocks with comments which are helpful to understand its structure.

This repository should **only** be used for learning Python.

## Project structure

1. `asyncdns.py`: Handling DNS requests.

2. `common.py`: Wrapping some functions to make them easier to use.

  - `ord`, `chr` to convert between `int` and `char` just like C. The default `ord` and `chr` functions in Python have been replaced.
  - `socket.inet_pton`, `socket.inet_ntop` to convert IP string and network bytes. If `socket` does not have the two functions (e.g. Before Python 2.3), the author implemented them.

  > Notice that `socket.inet_pton` can handle IPV4 and IPV6 addresses, yet `socket.inet_aton` cannot handle IPV6.

  - `parse_header`, `pack_addr` network utility functions.
  - `IPNetwork` class which saves IP addresses with prefixes.

3. `daemon.py`: Make Shadowsocks run as a daemon in *NIX.

4. `encrypt.py`: Encrypt/Decrypt Shadowsocks's protocol to circumvent the firewall.

5. `eventloop.py`: Use `select`,`epoll`, `kqueue` to multiplex I/O

6. `local.py`: Client code using SOCKS to set up a proxy and transfer packets.

7. `lru_cache.py`: LRU cache for DNS caching in `asyncdns.py`.

8. `manager.py`: A config manager.

9. `server.py`: Server code requesting remote sites and sending back responses to clients.

10. `shell.py`: Prompting and handling configs in shell.

11. `tcprelay.py`: Connecting remote servers by TCP.

12. `udprelay.py`: Connecting remote servers by UDP.

The core modules are `asyncdns.py`, `eventloop.py`, `tcprelay.py`, and `udprelay.py`. `local.py` and `server.py` are just wrapping them up.

## Evolution of Shadowsocks

At first, Shadowsocks only uses [_substitution cypher_](https://en.wikipedia.org/wiki/Substitution_cipher) to cypher the packets, which is thought to be very **unsafe**. In addition, in the early version of Shadowsocks, there are only 2 core modules: `local.py` and `server.py`. Due to its concision, we take [this](https://github.com/kigawas/shadowsocks-learning/tree/8c5c40915ea8fbd22a0f1a6a9596010565118b35) version as an example to explain the underground mechanism of Shadowsocks.

### Local module in early version

Firstly, we check the `local.py`. We can see the author build a table to make substitutions of ASCII characters.

```python
def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)  # here we can get 2 unsigned long long integers
    table = [c for c in string.maketrans('', '')]
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table
```

Then comes a TCP Server with multi-threading. You can find a usage at [the official doc](https://docs.python.org/2/library/socketserver.html#asynchronous-mixins).

```python
class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass
```

Now we can see the core class of `local.py`, it implemented a SOCKS5 server and transfer packets following SOCKS5 protocol. Let's take a glance at it.

```python
class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = sock.recv(4096)  # recv data from browser
                    if len(data) <= 0:  # add len to fix bug
                        break
                    if remote.sendall(self.encrypt(data)) is not None:
                        # encrypt and send them all
                        # to remote SS server
                        break
                if remote in r:
                    data = remote.recv(4096)  # recv data from remote SS server
                    if len(data) <= 0:  # add len to fix bug
                        break
                    if sock.sendall(self.decrypt(data)) is not None:
                        # decrypt and send them all to browser
                        break
        finally:
            sock.close()
            remote.close()
```

In this function, the author uses `select` to support I/O multiplexing. `select.select`'s [signature](https://docs.python.org/2/library/select.html#select.select) is `select.select(rlist, wlist, xlist[, timeout])`, here our server just need to use `rlist` to wait until ready for reading `sock` and `remote`. The `sock` connects user's web browser as a proxy and the `remote` connects a shadowsocks server which is located beyond the firewall.

Then comes functions related to ciphering and deciphering. The author uses [`string.translate`](https://docs.python.org/2/library/string.html#string.translate) to encrypt and decrypt data. Notice that it is very **unsafe** to do so. You can find more information about cryptography on [Wikipedia](https://en.wikipedia.org/wiki/Cryptography#Modern_cryptography).

```python
def encrypt(self, data):
    return data.translate(encrypt_table)

def decrypt(self, data):
    return data.translate(decrypt_table)

def send_encrypt(self, sock, data):
    sock.send(self.encrypt(data))
```

The last function in class `Socks5Server` comes at last!:laughing: It is also the longest function and seems to be a little frustrating.:open_mouth:

```python
def handle(self):
    try:
        data = self.rfile.read(2)
        self.rfile.read(ord(data[1]))
        self.wfile.write("\x05\x00")
        data = self.rfile.read(4)
        mode = ord(data[1])
        if mode != 1:
            logging.warn('mode != 1')
            return
        addrtype = ord(data[3])
        addr_to_send = data[3]
        if addrtype == 1:  # IPV4 address
            addr_ip = self.rfile.read(4)  # read IP
            addr = socket.inet_ntoa(addr_ip)  # convert it to a string like "192.168.0.1"
            addr_to_send += addr_ip
        elif addrtype == 3:  # domain name
            addr_len = self.rfile.read(1)  # read length
            addr = self.rfile.read(ord(addr_len))  # read domain name
            addr_to_send += addr_len + addr
        else:
            logging.warn('addr_type not support')
            # not support
            return
        addr_port = self.rfile.read(2)  # read port
        addr_to_send += addr_port
        # now, addr_to_send  == ATYP + dest IP + port or ATYP + length + domain name + port
        # if you visit google.com, domain name will be google.com and port will be 443
        port = struct.unpack('>H', addr_port)  #  convert unsigned short bytes to (port,) in Python
        try:
            reply = "\x05\x00\x00\x01"  # VER REP RSV ATYP
            reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 0)  # binding 0.0.0.0
            self.wfile.write(reply)
            # reply immediately
            if '-6' in sys.argv[1:]:
                remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((SERVER, REMOTE_PORT))
            self.send_encrypt(remote, addr_to_send)
            logging.info('connecting %s:%d' % (addr, port[0]))
        except socket.error, e:
            logging.warn(e)
            return
        self.handle_tcp(self.connection, remote)
    except socket.error, e:
        logging.warn(e)
```

Because `Socks5Server` inherits [`SocketServer.StreamRequestHandler`](https://docs.python.org/2/library/socketserver.html#SocketServer.StreamRequestHandler), the function `handle` must be overridden to handle requests from clients which are thought to be users' browsers. At the first two lines, our SOCKS5 server receive a connecting request from a client. You can find the protocol at [RFC1928](https://www.ietf.org/rfc/rfc1928.txt).

At the first two lines:

```python
data = self.rfile.read(2)
self.rfile.read(ord(data[1]))
```

They read data from client like:

VER | NMETHODS | METHODS
--- | -------- | -------
1   | 1        | 1-255

- VER means SOCKS version, here should be 0x05
- NMETHODS is the length of METHODS
- METHODS is a list of verifications. 0x00 means no verifications.

After the server received the request, the code `self.wfile.write("\x05\x00")` responds like:

VER | METHODS
--- | -------
1   | 1

- VER should be 0x05
- METHODS should be 0x00 without verifications.

After the handshaking stage, the client can send requests to our server. The request format is:

VER | CMD | RSV  | ATYP | DST ADDR | DST PORT
--- | --- | ---- | ---- | -------- | --------
1   | 1   | 0x00 | 1    | Variable | 2

- VER means SOCKS version, here should be 0x05
- CMD means command

  - 0x01: CONNECT
  - 0x02: BIND
  - 0x03: UDP forwarding

- RSV means reserved, now it is 0x00
- ATYPE means address type

  - 0x01: IPV4 address, DST ADDR will be 4 bytes
  - 0x03: domain name, the first byte in DST ADDR indicates the length, and the rest will be the domain name (without \0)
  - 0x04: IPV6 address, DST ADDR will be 16 bytes

- DST ADDR means destination address
- DST PORT means destination port

Then,

```python
reply = "\x05\x00\x00\x01"  # VER REP RSV ATYP
reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 0)  # binding 0.0.0.0:0, in my personal opinion, this is meaningless since you connected server, you've already known its IP and port.
self.wfile.write(reply)
```

Now our server replies to user's browser. Correspondingly, the server's response format is:

VER | REP | RSV  | ATYP | BND ADDR | BND PORT
--- | --- | ---- | ---- | -------- | --------
1   | 1   | 0x00 | 1    | Variable | 2

- VER means SOCKS version, here should be 0x05
- REP means reply

  - 0x00: succeeded

- RSV means reserved, now it is 0x00
- ATYPE means address type

  - 0x01: IPV4 address, DST ADDR will be 4 bytes
  - 0x03: domain name, the first byte in DST ADDR indicates the length, and the rest will be the domain name (without \0)
  - 0x04: IPV6 address, DST ADDR will be 16 bytes

- BND ADDR means bound address
- BND PORT means bound port

### Server module in early version

Just like `local.py`, `server.py` also follows the same structure. The function `get_table` and class `ThreadingTCPServer` are nothing different. And `Socks5Server` is even simpler than its local version due to there is no need to handle SOCKS5 protocol. Let's check out the codes!:laughing:

```python
class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:  # recv data from local
                    data = sock.recv(4096)
                    if len(data) <= 0:
                        break
                    if remote.sendall(self.decrypt(data)) is not None:
                        # we need to decrypt them and send them to destination server (e.g. google.com)
                        break
                if remote in r:  # recv data from destination server
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    if sock.sendall(self.encrypt(data)) is not None:
                        # we need to encrypt them to circumvent the firewall and send them back to local
                        break
        finally:
            sock.close()
            remote.close()

    def encrypt(self, data):
        return data.translate(encrypt_table)

    def decrypt(self, data):
        return data.translate(decrypt_table)

    def handle(self):
        try:
            sock = self.connection
            # as mentioned before, the address is like
            # ATYP + dest IP + port or ATYP + length + domain name + port
            addrtype = ord(self.decrypt(sock.recv(1)))
            if addrtype == 1:  # dest IP + port
                addr = socket.inet_ntoa(self.decrypt(self.rfile.read(4)))
            elif addrtype == 3:  # length + domain name + port
                addr = self.decrypt(self.rfile.read(ord(self.decrypt(sock.recv(1)))))
            else:
                # not support
                logging.warn('addr_type not support')
                return
            port = struct.unpack('>H', self.decrypt(self.rfile.read(2)))
            try:
                logging.info('connecting %s:%d' % (addr, port[0]))
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((addr, port[0]))
                # assuming client wants to visit google.com:
                # addr == google.com and port[0] == 443
            except socket.error, e:
                # Connection refused
                logging.warn(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error, e:
            logging.warn(e)
```

Server side's `sock` and `remote` are diffenrent from client's `sock` and `remote`. Actually, `remote` in `local.py` connects to `sock` in `server.py`, and `sock` in `local.py` connects to a browser while `remote` in `server.py` connects to destination sites (e.g. google.com). Due to Shadowsocks' elaborate design, the same class functions elegantly in different side.

```
Client                                  Server
+-------------------+                   +-------------------+
|                   |                   |                   |
|      sock         |                   |      sock         |
|                   |        +---------->                   |
|                   |        |          |                   |
+-------------------+        |          +-------------------+
|                   |        |          |                   |
|     remote        |        |          |      remote       |
|                   +--------+          |                   |
|                   |                   |                   |
+-------------------+                   +-------------------+
```
