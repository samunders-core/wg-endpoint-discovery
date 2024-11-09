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
    /usr/bin/pkill -INT -f 'ape ./redbean.com 127.0.0.1' || true
    rm -f ape chmod mkdir mv wg
}

it_requires_its_address_as_argument() {
    ! OUTPUT="$(timeout 3 ./redbean.com < /dev/null 2>&1)"
    echo "$OUTPUT" | lookup "Malformed manager address provided as first argument: "
}

#it_accepts_port_as_optional_second_argument() {
#    false
#}

it_requires_wireguard_installation() {
    ! OUTPUT="$(env --ignore-environment "PATH=$(pwd)" /usr/bin/timeout 3 ./redbean.com 127.0.0.1 < /dev/null 2>&1)"
    echo "$OUTPUT" | lookup "wg lookup failed: " 
}

it_excludes_itself_from_served_online_peers() {
    (
        echo '#!/bin/sh'
        echo '[ ! "$*" = "show all dump" ] && echo "Not implemented" >&2 && exit 1'
        echo "echo 'vpn1	private_key	manager_node_public_key	1234	off'"
        echo "echo 'vpn1	offline_peer_public_key	(none)	(none)	10.10.10.1/32	42	0	0	13'"
        echo "echo 'vpn1	online_peer_public_key	(none)	9.8.7.6:1234	10.10.10.2/32	1731099015	9351784	3698984	13'"
    ) > wg
    chmod +x wg
    PATH=$(pwd) ./redbean.com 127.0.0.1 &
    sleep 1
    OUTPUT="$(curl http://localhost:8080/online-peers)"
    [ "$OUTPUT" = "online_peer_public_key" ]
}

it_serves_endpoint() {
    (
        echo '#!/bin/sh'
        echo '[ ! "$*" = "show all dump" ] && echo "Not implemented" >&2 && exit 1'
        echo "echo 'vpn1	private_key	manager_node_public_key	1234	off'"
        echo "echo 'vpn1	offline_peer_public_key	(none)	(none)	10.10.10.1/32	42	0	0	13'"
        echo "echo 'vpn1	online_peer_public_key	(none)	9.8.7.6:1234	10.10.10.2/32	1731099015	9351784	3698984	13'"
    ) > wg
    chmod +x wg
    PATH=$(pwd) ./redbean.com 127.0.0.1 &
    sleep 1
    OUTPUT="$(curl http://localhost:8080/endpoint/manager_node_public_key)"
    [ "$OUTPUT" = "$(ip -o route get 1.1.1.1 | awk '{print $7}'):1234" ]
    OUTPUT="$(curl http://localhost:8080/endpoint/offline_peer_public_key)"
    echo "$OUTPUT" | lookup "404 Peer not seen yet"
    OUTPUT="$(curl http://localhost:8080/endpoint/online_peer_public_key)"
    [ "$OUTPUT" = "9.8.7.6:1234 allowed-ips 10.10.10.2/32" ]
}

it_serves_status_as_key_and_numeric_value_pairs() {
    ln -s /bin/false wg
    PATH=$(pwd) ./redbean.com 127.0.0.1 &
    sleep 1
    OUTPUT="$(curl http://localhost:8080/statusz)"
    [ -n "$OUTPUT" ]
    echo "$OUTPUT" | awk '/^$/{next} $1 !~ /[0-9a-zA-Z_.]+:/ || $2 !~ /[0-9]+/{f=NR} END{exit f}'
}
