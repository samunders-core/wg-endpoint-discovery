#!/usr/bin/env roundup

mksymlinks() {  # dir name ...
    DIR="$1" && shift
    mkdir -p "$DIR"
    for app in "$@"; do
      ln -fs /bin/$app "$DIR"
    done
}

before() {
    # for app in ape awk basename chmod cut egrep grep head mkdir mv sed tr xdg-mime xdg-open; do
    mksymlinks "$(pwd)" ape chmod mkdir mv
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
    rm -rf ape chmod ip manager mkdir mv peer redbean.counts.sqlite3* wg xdg-open
}

start_peer() {  # bind_address name
  NAME="$1" && shift
  env DB_PATH=./redbean.counts.sqlite3.$NAME PATH="${WITH_PATH:-$(pwd)}" ./redbean.com -X "$@" 2>&1 | sed -re "s/^/$NAME /" &
  sleep 1
  kill -0 $!    
}

start_manager() {
    mksymlinks "$(pwd)/manager" ape chmod mkdir mv
    tee manager/wg > /dev/null <<'EOF' && chmod +x "$_"
        #!/bin/sh
        [ "$*" = "show interfaces" ] && echo "vpn1" && exit 0
        [ ! "$*" = "show all dump" ] && echo "Not implemented: $0 $*" >&2 && exit 1
        echo 'vpn1	private_key	manager_public_key	1234	off'
        echo 'vpn1	offline_peer_public_key	(none)	(none)	10.10.10.1/32	42	0	0	13'
        echo 'vpn1	online_peer_public_key	(none)	9.8.7.6:1234	127.0.0.27/32	1731099015	9351784	3698984	13'
EOF
    WITH_PATH="$(pwd)/manager" start_peer MANAGER -l 127.0.0.254 -l 127.0.0.1 "$@" 127.0.0.1
} 
 
mock_wg_show_interfaces_and_set_peer() {
    tee wg > /dev/null <<'EOF' && chmod +x "$_"
        #!/bin/sh
        [ "$*" = "show interfaces" ] && echo "vpn1" && exit 0
        [ "$*" = "set vpn1 peer online_peer_public_key persistent-keepalive 13 endpoint 9.8.7.6:1234 allowed-ips 127.0.0.27/32" ] && exit 0
        [ "$*" = "show vpn1 transfer" ] && echo -e 'offline_peer_public_key	0	1332\nonline_peer_public_key	9351784	3698984' && exit 0
        [ ! "$*" = "show all dump" ] && echo "Not implemented: $0 $*" >&2 && exit 1
        echo 'vpn1	private_key	manager_public_key	1234	off'
        echo 'vpn1	offline_peer_public_key	(none)	(none)	127.0.0.99/32	42	0	0	13'
        echo 'vpn1	online_peer_public_key	(none)	9.8.7.6:1234	127.0.0.27/32	1731099015	9351784	3698984	13'
EOF
}

mock_ip_route_replace() {
    tee ip > /dev/null <<'EOF' && chmod +x "$_"
        #!/bin/sh
        [ ! "$*" = "route replace 127.0.0.27 dev lo scope link" ] && echo "Not implemented: $0 $*" >&2 && exit 1
        exit 0
EOF
}

it_pings_peers_on_heartbeat() {
    start_manager
    mock_wg_show_interfaces_and_set_peer
    start_peer ONLINE_PEER -l 127.0.0.27 127.0.0.254
    mock_ip_route_replace
    timeout 3 env PATH="$(pwd)" HEARTBEAT_SECONDS=1 ./redbean.com -X -l 127.0.0.42 127.0.0.254 2>&1 | sed -re 's/^/PEER /' | lookup \
      '9351784 bytes received, 3698984 bytes sent' \
      'Fetch[(]http://127.0.0.27:8080/healthcheck) 200: [{]"count":1}' \
      '9351784 bytes received, 3698984 bytes sent' \
      'Fetch[(]http://127.0.0.27:8080/healthcheck) 200: [{]"count":2}' \
      '9351784 bytes received, 3698984 bytes sent' \
      'Fetch[(]http://127.0.0.27:8080/healthcheck) 200: [{]"count":3}'
}

mock_online_peer() {
    mksymlinks "$(pwd)/peer" ape chmod mkdir mv
    tee peer/wg > /dev/null <<'EOF' && chmod +x "$_"
        #!/bin/sh
        [ "$*" = "show interfaces" ] && echo "vpn1" && exit 0
        echo "Not implemented: $0 $*" >&2 && exit 1
EOF
    WITH_PATH="$(pwd)/peer" start_peer ONLINE_PEER -l 127.0.0.27 127.0.0.254
}

it_pings_all_local_known_peers_even_after_manager_goes_offline() {
    start_manager \
      -e 'unix.sigaction(unix.SIGALRM, unix.exit, unix.SA_RESETHAND)' \
      -e 'unix.setitimer(unix.ITIMER_REAL, 0, 0, 3, 0)'  # 3-seconds delayed exit
    mock_wg_show_interfaces_and_set_peer
    start_peer ONLINE_PEER -l 127.0.0.27 127.0.0.254
    mock_ip_route_replace
    timeout 3 env PATH="$(pwd)" HEARTBEAT_SECONDS=1 ./redbean.com -X -l 127.0.0.42 127.0.0.254 2>&1 | sed -re 's/^/PEER /' | lookup \
      '9351784 bytes received, 3698984 bytes sent' \
      'Fetch[(]http://127.0.0.27:8080/healthcheck) 200: [{]"count":1}' \
      'Fetch[(]http://127.0.0.254:8080/other-online-peers) failed: connect[(]127.0.0.254:8080) error: Connection refused' \
      'Fetch[(]http://127.0.0.99:8080/healthcheck) failed: connect[(]127.0.0.99:8080) error: Connection refused' \
      'Fetch[(]http://127.0.0.27:8080/healthcheck) 200: [{]"count":2}' \
      'Fetch[(]http://127.0.0.254:8080/other-online-peers) failed: connect[(]127.0.0.254:8080) error: Connection refused' \
      'Fetch[(]http://127.0.0.99:8080/healthcheck) failed: connect[(]127.0.0.99:8080) error: Connection refused' \
      'Fetch[(]http://127.0.0.27:8080/healthcheck) 200: [{]"count":3}'
}

# it_accepts_anything_to_allow_vpn_restarts_as_optional_second_argument() {
#     false
# }

# it_restarts_windows_vpn_client_upon_repeated_ping_failure() {
#     false
# }