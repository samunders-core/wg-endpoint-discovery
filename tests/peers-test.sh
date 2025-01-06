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

lookup() { # [awk_options] regex [regex ...]; like grep, but prints all first matches on success, everything when failed
  ! set +"${-//[^x]/}" > /dev/null 2> /dev/null || RESTORE_TRACING="set -x"
  CMDS='
    BEGIN { delete PATT[0] }
    BEGINFILE { if (FILENAME != "" && FILENAME != "-") { PATT[length(PATT)] = FILENAME; nextfile } }
    function matchesAny(text) { for (i in PATT) if (text ~ PATT[i]) { delete PATT[i]; return 1 } }
    { allLines = allLines "" RS "" $0 }
    matchesAny($0) { matched = matched "" RS "" $0 }
    0 == length(PATT) { exit }
    END { system(length(PATT) ? "date >&2" : "true"); printf(length(PATT) ? "Seen " NR " lines since " START "\n" : "") > "/dev/stderr"; print(length(PATT) ? allLines : matched); exit(length(PATT)) }
  '
  for (( COUNT=$#;COUNT>0;COUNT-- )); do
    [ ! "${!COUNT#-F}" = "${!COUNT}" -o ! "${!COUNT#-v}" = "${!COUNT}" -o "${!COUNT}" = "--" ] && {
      gawk -v "START=$(date)" "${@:1:$COUNT}" "$CMDS" "${@:$((COUNT+1))}" '-'
      return $?
    }
  done # explicit gawk due to use of length(...) function
  gawk -v "START=$(date)" "$CMDS" "$@" '-'
  RV=$?
  $RESTORE_TRACING
  return $RV
}

after() {
    kill %1 || true
    pkill -INT -f 'redbean.com -X' || true
    rm -rf ape chmod ip manager mkdir mv wg xdg-open
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
        echo "echo 'vpn1	online_peer_public_key	(none)	9.8.7.6:1234	127.0.0.27/32	1731099015	9351784	3698984	13'"
    ) > manager/wg  # for test purposes allowed ips of online peer points to manager; there should be 127.0.0.1 but that's where peer is bound and X-Client-Address would cause it to be ignored
    chmod +x manager/wg
    PATH="$(pwd)/manager" ./redbean.com -X -l 127.0.0.1 -l 127.0.0.27 127.0.0.1 2>&1 | sed -re 's/^/MANAGER /' &
    sleep 1
    kill -0 $!
} 
 
mock_wg_show_interfaces_and_set_peer() {
    (
        echo '#!/bin/sh'
        echo '[ "$*" = "show interfaces" ] && echo "vpn1" && exit 0'
        echo '[ "$*" = "set vpn1 peer online_peer_public_key persistent-keepalive 13 endpoint 9.8.7.6:1234 allowed-ips 127.0.0.27/32" ] && exit 0'
        echo '[ ! "$*" = "show vpn1 transfer" ] && echo "Not implemented: $0 $*" >&2 && exit 1'
        echo "echo 'offline_peer_public_key	0	1332'"
        echo "echo 'online_peer_public_key	9351784	3698984'"
    ) > wg
    chmod +x wg
}

mock_ip_route_replace() {
    (
        echo '#!/bin/sh'
        echo '[ ! "$*" = "route replace 127.0.0.27 dev lo scope link" ] && echo "Not implemented: $0 $*" >&2 && exit 1'
        echo "exit 0"
    ) > ip
    chmod +x ip
}

mock_online_peer() {
    mkdir -p peer
    for app in ape chmod mkdir mv; do
      ln -fs /bin/$app "$(pwd)/peer"
    done
    (
        echo '#!/bin/sh'
        echo 'echo "Not implemented: $0 $*" >&2 && exit 1'
    ) > peer/wg
    chmod +x peer/wg
    PATH="$(pwd)/peer" ./redbean.com -X 127.0.0.27 2>&1 | sed -re 's/^/ONLINE_PEER /' &
    sleep 1
    kill -0 $!
}

mock_wg_show_all_dump() {
    (
        echo '#!/bin/sh'
        echo '[ ! "$*" = "show all dump" ] && echo "Not implemented: $0 $*" >&2 && exit 1'
        echo "echo 'vpn1	private_key	manager_public_key	1234	off'"
        echo "echo 'vpn1	offline_peer_public_key	(none)	(none)	10.10.10.1/32	42	0	0	13'"
        echo "echo 'vpn1	online_peer_public_key	(none)	9.8.7.6:1234	127.0.0.27/32	1731099015	9351784	3698984	13'"
    ) > wg
    chmod +x wg
}

it_pings_peers_on_heartbeat() { 
    mock_manager_and_online_peer
    mock_wg_show_interfaces_and_set_peer
    mock_ip_route_replace
    timeout 3 env PATH="$(pwd)" ./redbean.com -X -p 9090 127.0.0.27 8080 1000 2>&1 | sed -re 's/^/PEER /' | lookup \
      '9351784 bytes received, 3698984 bytes sent' \
      'Fetch[(]http://127[.]0[.]0[.]27:8080/statusz[)] 200: pid:.*statuszrequests: 1' \
      '9351784 bytes received, 3698984 bytes sent' \
      'Fetch[(]http://127[.]0[.]0[.]27:8080/statusz[)] 200: pid:.*statuszrequests: 2' \
      '9351784 bytes received, 3698984 bytes sent' \
      'Fetch[(]http://127[.]0[.]0[.]27:8080/statusz[)] 200: pid:.*statuszrequests: 3'
}

it_pings_peers_even_after_manager_goes_offline() {
    return  # FIXME: fetch_endpoint
    mock_online_peer
    mock_wg_show_all_dump
    timeout 3 env PATH="$(pwd)" ./redbean.com -X -p 9090 127.0.0.27 8080 1000 2>&1 | sed -re 's/^/PEER /' | lookup \
      '9351784 bytes received, 3698984 bytes sent' \
      'Fetch[(]http://127[.]0[.]0[.]27:8080/statusz[)] 200: pid:.*statuszrequests: 1' \
      '9351784 bytes received, 3698984 bytes sent' \
      'Fetch[(]http://127[.]0[.]0[.]27:8080/statusz[)] 200: pid:.*statuszrequests: 2' \
      '9351784 bytes received, 3698984 bytes sent' \
      'Fetch[(]http://127[.]0[.]0[.]27:8080/statusz[)] 200: pid:.*statuszrequests: 3'
}
