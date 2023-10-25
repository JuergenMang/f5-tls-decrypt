# F5 Decrypt TLS

This repository provides a script that creates a pre master-secret log file for Wireshark to decrypt TLS traffic. It works with all TLS versions even TLSv1.3 traffic could be decrypted hassle-free.

The `gensecrets-tls.pl` script extracts the tls session keys from a tcpdump written by the F5 sslprovider. Therefore the dump and the script must be executed on the f5 itself.

- The script handles any number of TLS flows and autodetecs the TLS versions.
- The dump must include the complete tls handshakes.
- The `gensecrets-tls.pl` works only with F5 v15 or above (special tcpdump version).

## Dump

1. Enable ssl provider: `tmsh modify sys db tcpdump.sslprovider value enable`
2. Run tcpdump: `tcpdump -nni 0.0:nnnp -s0 --f5 ssl:v -vvv -w /tmp/dump.pcap <filter>`
3. Disable ssl provider: `tmsh modify sys db tcpdump.sslprovider value disable`

### Create the PMS file

1. Extract session secrets from dump: `./gensecrets-tls.pl /tmp/dump.pcap > /tmp/dump.pms`

## Wireshark

1. Enable F5 TLS (Analyze → Enabled Protocols)
2. Configure `dump.pms` as (Pre-)Master-Secret log filename (Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename)
3. TLS Traffic should now be decrypted (formerly application data packets are shown in cleartext)

## F5 SSL provider format

- Values conatining only zeros can be ignored.
- The secrets could occur in different packets.

### TLS < 1.3

#### In Wireshark

```
F5 Ethernet Trailer Protocol
- F5 TLS
-- Master Secret: <master_secret>
-- Client Random: <client_random>
```

#### In tcpdump

```
MS:<master_secret>
CR:<client_random>
```

### TLS 1.3

#### In Wireshark

```
F5 Ethernet Trailer Protocol
- F5 TLS
-- Early Traffic Secret: <early_secret>
-- Client Handshake Traffic Secret: <client_handshake_secret>
-- Server Handshake Traffic Secret: <server_handshake_secret>
-- Client Application Traffic Secret: <client_traffic_secret>
-- Server Application Traffic Secret: <server_traffic_secret>
-- Client Random: <client_random>
```

#### In tcpdump

```
1.3CR:<client_random>
1.3ES:<early_secret>
1.3HSC:<client_handshake_secret>
1.3HSS:<server_handshake_secret>
1.3APPC:<client_traffic_secret>
1.3APPS:<server_traffic_secret>
```

## .pms file format

### TLS < 1.3

```
CLIENT_RANDOM <client_random> <master_secret>
```

### TLS 1.3

```
CLIENT_EARLY_TRAFFIC_SECRET <client_random> <early_secret>
CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <client_handshake_secret>
SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <server_handshake_secret>
CLIENT_TRAFFIC_SECRET_0 <client_random> <client_traffic_secret>
SERVER_TRAFFIC_SECRET_0 <client_random> <server_traffic_secret>
```
`<client_random>` is always the same

## References

- [K05822509: Decrypting HTTP/3 over QUIC with Wireshark](https://support.f5.com/csp/article/K05822509) - decrypts not all flows
- [dev/central: Decrypting TLS traffic on BIG-IP](https://devcentral.f5.com/s/articles/Decrypting-TLS-traffic-on-BIG-IP) - does not work for TLS 1.3
- [Decrypt with tcpdump --f5 ssl](https://clouddocs.f5.com/training/community/adc/html/class4/module1/lab10.html) - does not work for TLS 1.3
- [Decrypt SSL with iRule](https://clouddocs.f5.com/training/community/adc/html/class4/module1/lab12.html#decrypt-ssl-with-irule)
- [Decrypting TLS traffic on BIG-IP](https://community.f5.com/t5/technical-articles/decrypting-tls-traffic-on-big-ip/ta-p/280936)
