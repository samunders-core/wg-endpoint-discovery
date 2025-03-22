Implementation of https://www.jordanwhited.com/posts/wireguard-endpoint-discovery-nat-traversal using https://redbean.dev

Bob's firewall (or their ISP's) learns addresses only for a few seconds after first Bob's packet is sent. Solution is to restart Bob's VPN client:

```mermaid
sequenceDiagram
    participant A as Alice @ Linux
    participant S as VPN server
    participant B as Bob @ Windows

    A->>S: GET /other-online-peers
    S->>A: 200 []

    A->>S: GET /other-online-peers
    S->>A: 200 []
    
    B->>S: GET /other-online-peers
    S->>B: 200 [{"pubkey":"alice_key", "endpoint":"alice_ip_address:port_X", "allowed_ips":"address/bitmask"}]
    Note over B: wg set vpn1 peer alice_key persistent-keepalive 13 endpoint alice_ip_address:port_X allowed-ips address/bitmask
    Note over B: netsh advfirewall firewall add rule name=redbean_healthcheck protocol=tcp dir=in localip=bob_ip_address localport=8080 action=allow

    loop every 13 seconds
        A->>S: GET /other-online-peers
        S->>A: 200 [{"pubkey":"bob_key", "endpoint":"bob_ip_address:port_1", "allowed_ips":"address/bitmask"}]
        Note over A: wg set vpn1 peer bob_key persistent-keepalive 13 endpoint bob_ip_address:port_1 allowed-ips address/bitmask
        loop 3x
            A->>B: GET /healthcheck
            Note over A,B: No response due to Bob's firewall (or their ISP's)
            A->>S: POST /notify/bob
            S->>B: POST /failed/alice
            B->>S: 200 {"count": 1}  // and 2 and 3
            S->>A: 200 {"count": 1}  // and 2 and 3
        end
        Note over B: VPN client restart because Alice failure count is 3
    end
    
    B->>S: GET /other-online-peers
    S->>B: 200 [{"pubkey":"alice_key", "endpoint":"alice_ip_address:port_X", "allowed_ips":"address/bitmask"}]
    Note over B: Notice no change in endpoint value

    A->>S: GET /other-online-peers
    S->>A: 200 [{"pubkey":"bob_key", "endpoint":"bob_ip_address:port_2", "allowed_ips":"address/bitmask"}]
    Note over A: wg set vpn1 peer bob_key persistent-keepalive 13 endpoint bob_ip_address:port_2 allowed-ips address/bitmask (Notice new endpoint port is reported)

    A->>B: GET /healthcheck
    B->>A: {"count": 1} // and 2 and 3 and ...

    B->>A: GET /healthcheck
    A->>B: {"count": 1} // and 2 and 3 and ...
```

# Example Wireguard configuration

Every peer needs unique last component in address (from range 2 to 254, both inclusive). Examples below are **NOT** usable without replacing `<REDACTED>` with correct values!

## Central node

    [Interface]
    Address = 192.168.7.1
    ListenPort = 51820
    PrivateKey = <REDACTED>
    PostUp = /etc/wireguard/redbean.com -d -l 192.168.7.1 192.168.7.1
    PostDown = /usr/bin/pkill -f 'ape.* /etc/wireguard/redbean.com' &

    [Peer]
    PublicKey = paste peer's PUBLIC key here
    AllowedIPs = 192.168.7.5/32

    [Peer]
    ...

## Windows Peer

    [Interface]
    Address = 192.168.7.5
    PrivateKey = <REDACTED>
    # everything below is common for all Windows peers
    PostUp = C:\Windows\System32\redbean.com -d -l 192.168.7.5 192.168.7.1
    PostDown = C:\Windows\System32\redbean.com terminate

    [Peer]
    PublicKey = paste central node's PUBLIC key here
    Endpoint = paste public address or domain name of central node goes here, with :51820 appended
    AllowedIPs = 192.168.7.0/24
    PersistentKeepalive = 13

## Linux Peer

    [Interface]
    Address = 192.168.7.5
    PrivateKey = <REDACTED>
    # everything below is common for all Linux peers
    PostUp = /etc/wireguard/redbean.com -d -l 192.168.7.5 192.168.7.1
    PostDown = /usr/bin/pkill -f 'ape.* /etc/wireguard/redbean.com' || true

    [Peer]
    PublicKey = paste central node's PUBLIC key here
    Endpoint = paste public address or domain name of central node goes here, with :51820 appended
    AllowedIPs = 192.168.7.0/24
    PersistentKeepalive = 13

### TODOs

- test restart condition is correctly detected
- generate config files
- UI
- logs