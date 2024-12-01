#!/usr/bin/env roundup

before() {
    # for app in ape awk basename chmod cut egrep grep head mkdir mv sed tr xdg-mime xdg-open; do
    for app in ape chmod mkdir mv; do
      ln -fs /bin/$app "$(pwd)"
    done
    (
        echo '#!/bin/sh'
        echo 'echo "Default browser: opening $*" >&2'
    ) > xdg-open  # x-www-browser 
    chmod +x xdg-open  # x-www-browser
}

lookup() {	# regex; like grep, but prints first match on success, everything when failed
    awk -v "PATT=$*" '$0 ~ PATT {found=1;lines=$0;exit} lines {lines=lines""RS""$0;next} {lines=$0} END {printf(lines);exit(1-found)}'
}

after() {
    kill %1 || true
    pkill -INT -f 'ape ./redbean.com 127.0.0.' || true
    rm -rf ape chmod manager mkdir mv wg
}

mock_manager_and_online_peer() {
    mkdir -p manager
    for app in ape chmod mkdir mv; do
      ln -fs /bin/$app "$(pwd)/manager"
    done
    (
        echo '#!/bin/sh'
        echo '[ ! "$*" = "show all dump" ] && echo "Not implemented: $0 $*" >&2 && exit 1'
        echo "echo 'vpn1	private_key	manager_public_key	1234	off'"
        echo "echo 'vpn1	offline_peer_public_key	(none)	(none)	10.10.10.1/32	42	0	0	13'"
        echo "echo 'vpn1	online_peer_public_key	(none)	9.8.7.6:1234	127.0.0.1/32	1731099015	9351784	3698984	13'"
    ) > manager/wg  # for test purposes allowed ips of online peer points to manager
    chmod +x manager/wg
    PATH="$(pwd)/manager" ./redbean.com --strace -l 127.0.0.1 -l 127.0.0.27 127.0.0.1 &
    sleep 1
    kill -0 $!
} 
 
mock_wg_show_interfaces() {
    (
        echo '#!/bin/sh'
        echo '[ ! "$*" = "show interfaces" ] && echo "Not implemented: $0 $*" >&2 && exit 1'
        echo "echo 'vpn1'"
    ) > wg 
    chmod +x wg
}

it_pings_peers_on_heartbeat() { 
    mock_manager_and_online_peer 
    mock_wg_show_interfaces
    OUTPUT="$(timeout 3 env PATH="$(pwd)" ./redbean.com -p 9090 127.0.0.27 8080 1000)"
    # assert ping
    false
}

it_pings_peers_even_after_manager_goes_offline() {
    # fail online-peers
    # mock wg show all dump
    # fetch endpoints
    # assert ping
    false
}