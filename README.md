# TeleDDNS Server

Simple DDNS API server with Starlette Admin webapp for management.

Features:
* The best client for this server is [TeleDDNS](https://github.com/tmshlvck/teleddns), although DDNS over HTTP(S) protocol is implemented to largest extent I could manage and I am committed to support any other cliets that may have issues sending updates to this API.
* This server explects to work with one or more Knot DNS 3.x servers with the [TeleAPI](This is a server for) connectors

## Deployment

Install & configure Knot:
```
apt-get install knot
```

Deploy TeleAPI:
```
git clone https://github.com/tmshlvck/teleapi.git
cd teleapi
cargo build --release
sudo cp target/release/teleapi /usr/local/bin/
cat <<EOF >etc/teleapi.yaml
---
listen: 127.0.0.1
listen_port: 8586
apikey: "abcd1234"
commands:
- endpoint: "/zonewrite"
  write_file: "/var/lib/knot/{zonename}.zone"
  user: knot
  group: knot
  mode: 0o644
- endpoint: "/configwrite"
  write_file: "/etc/knot/knot-ddnsm-test.conf"
  user: knot
  group: knot
  mode: 0o644
- endpoint: "/zonereload"
  shell: "/usr/sbin/knotc zone-reload {zonename}"
- endpoint: "/zonecheck"
  shell: "/usr/bin/kzonecheck /var/lib/knot/{zonename}.zone"
- endpoint: "/configreload"
  shell: "/usr/sbin/knotc reload"
EOF
sudo cp teleapi.service /etc/systemd/system/teleapi.service
sudo systemctl daemon-reload
sudo systemctl enable teleapi
sudo systemctl restart teleapi
```

Build and deploy Podman container:
```
podman build -f Dockerfile -t teleddns-server:0.1
podman run --network=host -e ADMIN_PASSWORD=xyz1234 --name teleddns-server teleddns-server:0.1
```

Reset admin password:
```
podman exec -it teleddns-server /bin/bash
```