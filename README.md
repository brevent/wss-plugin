SIP003 plugin for shadowsocks, based on WebSocket.

## Build

### install `libwebsockets` 3.2.0+, recommend latest stable

Refer [libwebsockets](https://github.com/warmcat/libwebsockets).

### build

```bash
cmake -B build
cmake --build build
```

## Usage

### Client

`ss-local -c xxx.json`

```json
{
  "server": "xxx",
  "server_port": 443,
  "method": "none",
  "local_address": "0.0.0.0",
  "local_port": 1080,
  "plugin": "/path/to/wss-plugin-client",
  "plugin_opts": "tls;host=xxx;path=/xxx;mux=0"
}
```

### Server

There is unnecessary to specify `tls`, `host`, `path`:
- `tls`, use behind nginx, plugin server doesn't support tls.
- `host`, use behind nginx, plugin server support any host.
- `path`, use behind nginx, plugin server support any path.

```json
{
    "server":"127.0.0.1",
    "server_port":3448,
    "timeout":60,
    "method":"none",
    "plugin": "/path/to/wss-plugin-server",
    "plugin_opts": "mux=0"
}
```

### Compatible

Should compatible with `mux=0` with [v2ray-plugin](https://github.com/shadowsocks/v2ray-plugin/).
