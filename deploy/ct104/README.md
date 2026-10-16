# CT104 icloud-mcp: host parts

Installed on the LXC host CT104 (not in the image). Pattern after Michel's CT219 setup, written anew.

| File | Goes to | Does |
|---|---|---|
| `icloud-mcp-egress.sh` | `/usr/local/sbin/` | DOCKER-USER rules: app only to DNS + Apple `17.0.0.0/8` on 443/993/587, tunnel only to Cloudflare 7844/443, app port 8000 only from the gateway CT103 |
| `icloud-mcp-egress.service` | `/etc/systemd/system/` | applies the rules after Docker starts |
| `icloud-mcp-access-certs.sh` + `.service` + `.timer` | `/usr/local/sbin/`, `/etc/systemd/system/` | hourly copy of the Cloudflare Access team keys into the data volume (`OWNER_ACCESS_CERTS_FILE=/data/access-certs.json`) |

```sh
install -m 0755 deploy/ct104/*.sh /usr/local/sbin/
install -m 0644 deploy/ct104/*.service deploy/ct104/*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now icloud-mcp-egress.service icloud-mcp-access-certs.timer
```

Check: from inside the app container `example.com:443` must fail and `imap.mail.me.com:993` must connect;
`journalctl -k | grep icloud-mcp-` shows what was dropped.

`.env` additions for this setup: `MCP_BIND=192.168.1.191`, `MCP_EXTRA_ALLOWED_HOSTS=192.168.1.191:8000`,
`OWNER_ACCESS_TEAM_DOMAIN=schieder.cloudflareaccess.com`, `OWNER_ACCESS_AUD=<AUD of the Access app>`,
`OWNER_ACCESS_EMAILS=moritz@schieder.org`, `OWNER_ACCESS_CERTS_FILE=/data/access-certs.json`,
`CONTACTS_ALLOW_EMAIL_CHANGES=false`, `LOG_LEVEL=WARNING`.
