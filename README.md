Work in progress

Implementation of https://www.jordanwhited.com/posts/wireguard-endpoint-discovery-nat-traversal using https://redbean.dev

Bob's firewall (or their ISP's) learns addresses only for a few seconds after first Bob's packet is sent. Solution is to restart Bob's VPN client:

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as VPN server
    participant B as Bob

    A->>S: GET /online-peers
    S->>A: 200 [alice_key]

    A->>S: GET /online-peers
    S->>A: 200 [alice_key]
    
    B->>S: GET /online-peers
    S->>B: 200 [alice_key, bob_key]
    
    loop every 13 seconds
        A->>S: GET /online-peers
        S->>A: 200 [alice_key, bob_key]
        A->>S: GET /peer/bob_key
        S->>A: 200 {"endpoint":"bob_ip_address:port_1", "allowed_ips":"address/bitmask", "hands_shaken_at":"unix_timestamp"}
        A->>A: wg set vpn1 peer bob_key persistent-keepalive 13 endpoint bob_ip_address:port_1 allowed-ips address/bitmask
        A->>B: GET /statusz
        Note over A,B: No response due to Bob's firewall (or their ISP's)
    end
    
    loop every 13 seconds
        B->>S: GET /online-peers
        S->>B: 200 [alice_key, bob_key]
        B->>S: GET /peer/alice_key
        S->>B: 200 {"endpoint":"alice_ip_address:port_X", "allowed_ips":"address/bitmask", "hands_shaken_at":"unix_timestamp"}
        B->>B: wg set vpn1 peer alice_key persistent-keepalive 13 endpoint alice_ip_address:port_X allowed-ips address/bitmask
        B->>A: GET /statusz
        Note over A,B: No response since A's traffic did not pass through yet. Solution: restart Bob's VPN client
    end
    B->>B: VPN client restart

    loop every 13 seconds
        A->>S: GET /online-peers
        S->>A: 200 [alice_key, bob_key]
        A->>S: GET /peer/bob_key
        Note right of A: Notice new endpoint port is reported
        S->>A: 200 {"endpoint":"bob_ip_address:port_2", "allowed_ips":"address/bitmask", "hands_shaken_at":"unix_timestamp"}
        A->>A: wg set vpn1 peer bob_key persistent-keepalive 13 endpoint bob_ip_address:port_2 allowed-ips address/bitmask
        A->>B: GET /statusz
        B->>A: 200 KPI lines
    end

    loop every 13 seconds
        B->>S: GET /online-peers
        S->>B: 200 [alice_key, bob_key]
        B->>S: GET /peer/alice_key
        Note left of B: Notice no change in endpoint value
        S->>B: 200 {"endpoint":"alice_ip_address:port_X", "allowed_ips":"address/bitmask", "hands_shaken_at":"unix_timestamp"}
        B->>B: wg set vpn1 peer alice_key persistent-keepalive 13 endpoint alice_ip_address:port_X allowed-ips address/bitmask
        B->>A: GET /statusz
        A->>B: 200 KPI lines
    end
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