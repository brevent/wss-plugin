SIP003 plugin for shadowsocks, based on WebSocket.

## Build

### install `libwebsockets`

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

Not implement yet, use [v2ray-plugin](https://github.com/shadowsocks/v2ray-plugin/).
