#!/usr/bin/env roundup

before() {
    for app in ape chmod mkdir mv; do
      ln -fs /bin/$app "$(pwd)"
    done
}

lookup() {	# regex; like grep, but prints first match on success, everything when failed
    awk -v "PATT=$*" '$0 ~ PATT {found=1;lines=$0;exit} lines {lines=lines""RS""$0;next} {lines=$0} END {printf(lines);exit(1-found)}'
}

after() {
    kill %1 || true
    pkill -INT -f 'redbean.com 127.0.0.1' || true
    rm -f ape chmod mkdir mv wg
}

mock_online_peers() {
    (
        echo '#!/bin/sh'
        echo '[ ! "$*" = "show all dump" ] && echo "Not implemented: $0 $*" >&2 && exit 1'
        echo "echo 'vpn1	private_key	manager_public_key	1234	off'"
        echo "echo 'vpn1	offline_peer_public_key	(none)	(none)	10.10.10.1/32	42	0	0	13'"
        echo "echo 'vpn1	online_peer_public_key	(none)	9.8.7.6:1234	10.10.10.2/32	1731099015	9351784	3698984	13'"
    ) > wg
    chmod +x wg
    PATH=$(pwd) ./redbean.com 127.0.0.1 &
    sleep 1
    kill -0 $!
}

it_excludes_itself_from_served_online_peers() {
    mock_online_peers
    OUTPUT="$(curl http://localhost:8080/online-peers)"
    [ "$OUTPUT" = "online_peer_public_key" ]
    OUTPUT="$(curl -H 'Accept: application/json' http://localhost:8080/online-peers)"
    [ "$OUTPUT" = '["online_peer_public_key"]' ]
}

it_serves_endpoint() {
    (
        echo '#!/bin/sh'
        echo '[ ! "$*" = "show all dump" ] && echo "Not implemented: $0 $*" >&2 && exit 1'
        echo "echo 'vpn1	private_key	manager_public_key	1234	off'"
        echo "echo 'vpn1	offline_peer_public_key	(none)	(none)	10.10.10.1/32	42	0	0	13'"
        echo "echo 'vpn1	online_peer_public_key	(none)	9.8.7.6:1234	10.10.10.2/32	1731099015	9351784	3698984	13'"
    ) > wg
    chmod +x wg
    PATH=$(pwd) ./redbean.com 127.0.0.1 &
    sleep 1
    OUTPUT="$(curl http://localhost:8080/endpoint/manager_public_key)"
    [ "$OUTPUT" = "$(ip -o route get 1.1.1.1 | awk '{print $7}'):1234" ]
    OUTPUT="$(curl -H 'Accept: application/json' http://localhost:8080/endpoint/manager_public_key)"
    [ "$OUTPUT" = '{"endpoint":"'"$(ip -o route get 1.1.1.1 | awk '{print $7}'):1234"'","ping_failures":{}}' ]
    OUTPUT="$(curl http://localhost:8080/endpoint/offline_peer_public_key)"
    echo "$OUTPUT" | lookup "404 Peer not seen yet"
    OUTPUT="$(curl -H 'Accept: application/json' http://localhost:8080/endpoint/offline_peer_public_key)"
    echo "$OUTPUT" | lookup '{"error":"Peer not seen yet"}'
    OUTPUT="$(curl http://localhost:8080/endpoint/online_peer_public_key)"
    [ "$OUTPUT" = "9.8.7.6:1234 allowed-ips 10.10.10.2/32 # latest-handshake=1731099015" ]
    OUTPUT="$(curl -H 'Accept: application/json' http://localhost:8080/endpoint/online_peer_public_key)"
    [ "$OUTPUT" = '{"allowed_ips":"10.10.10.2/32","endpoint":"9.8.7.6:1234","hands_shaken_at":"1731099015","ping_failures":{}}' ]
    [ "$OUTPUT" = '{"allowed_ips":"10.10.10.2'"${CI:+\\}"'/32","endpoint":"9.8.7.6:1234","hands_shaken_at":"1731099015"}' ]
    # backslash above is cosmopolitan/redbean bug
}

