# TeleDDNS Server

Simple DDNS API server with Starlette Admin webapp for management.

Features:
* The best client for this server is [TeleDDNS](https://github.com/tmshlvck/teleddns), although DDNS over HTTP(S) protocol is implemented to largest extent I could manage and I am committed to support any other cliets that may have issues sending updates to this API.
* This server works with one or more Knot DNS 3.x servers with the [TeleAPI](https://github.com/tmshlvck/teleapi) connector.
* There is a Starlette Admin webapp at `/admin` that can be used to manually mange DNS records and trigger Knot config and zone synchronization.

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

To build, deploy, install and inspect logs of the Podman container run
the following as `root`:
```
mkdir /srv/teleddns-server
podman build -f Dockerfile -t teleddns-server:0.1
podman run -d --network=host -v /srv/teleddns-server:/data --name teleddns-server -e ROOT_PATH="/ddns" teleddns-server:0.1
podman logs teleddns-server
podman generate systemd teleddns-server >/etc/systemd/system/teleddns-server.service
systemctl daemon-reload
systemctl enable teleddns-server
```

Reset admin password to `xyz123`:
```
podman exec -e ADMIN_PASSWORD=xyz123 -it teleddns-server teleddns_server
```

Create NGINX proxy and use Certbot to create SSL certificate for the domain. The DDNS update protocol uses Basic Authentication that transmits passwords as plain-text and therefore it would be absolutely insecure and prone to all kinds of MITM attacks without HTTPS.

Add proxy section to your NGINX site (i.e. `/etc/nginx/sites-enabled/default`):
```
server {
...
  location /ddns/ {
    proxy_pass http://localhost:8000/;
    proxy_http_version 1.1;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_redirect off;
    proxy_buffering off;
  }
...
}
```

## Use guide

Before the server can accept updates few things need to be configured: