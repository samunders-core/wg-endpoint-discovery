Implementation of https://www.jordanwhited.com/posts/wireguard-endpoint-discovery-nat-traversal

Unfortunately Bob's firewall (or their ISP's) learns addresses only for a few seconds after first Bob's packet is sent. Solution is to restart Bob's VPN client:

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
