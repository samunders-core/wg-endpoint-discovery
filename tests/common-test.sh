#!/usr/bin/env roundup

before() {
    for app in ape chmod mkdir mv; do
      ln -fs /bin/$app "$(pwd)"
    done
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
    rm -f ape chmod mkdir mv redbean.counts.sqlite3* wg
}

it_requires_manager_address_as_argument() {
    ! OUTPUT="$(timeout 3 ./redbean.com -X < /dev/null 2>&1)"
    echo "$OUTPUT" | lookup "Malformed manager address provided as first argument: "
}

it_requires_wireguard_installation() {
    ! OUTPUT="$(env --ignore-environment "PATH=$(pwd)" /usr/bin/timeout 3 ./redbean.com -X 127.0.0.1 < /dev/null 2>&1)"
    echo "$OUTPUT" | lookup "commandv[(][)] failed: No such file or directory 'wg'" 
}

start_peer() {
  PATH=$(pwd) ./redbean.com -X -l "$1" 127.0.0.1 &
  sleep 1
  kill -0 $!    
}

mock_peers() {
    tee wg > /dev/null <<'EOF' && chmod +x "$_"
        #!/bin/sh
        [ "$*" = "show interfaces" ] && echo "vpn1" && exit 0
        [ ! "$*" = "show all dump" ] && echo "Not implemented: $0 $*" >&2 && exit 1
        echo 'vpn1	private_key	manager_public_key	1234	off'
        echo 'vpn1	offline_peer_public_key	(none)	(none)	127.0.0.42/32	42	0	0	13'
        echo 'vpn1	online_peer_public_key1	(none)	9.8.7.6:1234	127.0.0.1/32	1731099015	9351784	3698984	13'
        echo 'vpn1	online_peer_public_key2	(none)	9.8.7.6:2345	127.0.0.66/32	1731099015	9351784	3698984	13'
EOF
    DB_PATH=./redbean.counts.sqlite3.manager start_peer 127.0.0.1
    DB_PATH=./redbean.counts.sqlite3.online_peer start_peer 127.0.0.66
}

it_excludes_itself_from_served_peers() {
    mock_peers
    OUTPUT="$(curl http://127.0.0.1:8080/other-online-peers)"
    [ "$OUTPUT" = '[{"allowed_ips":"127.0.0.66\/32","endpoint":"9.8.7.6:2345","pubkey":"online_peer_public_key2"}]' ]
    
    OUTPUT="$(curl http://127.0.0.66:8080/other-online-peers)"
    [ "$OUTPUT" = '[]' ]
}

it_serves_healthcheck_as_number_of_invocations() {
    ln -s /bin/false wg
    start_peer 127.0.0.1
    OUTPUT="$(curl http://localhost:8080/healthcheck)"
    [ "$OUTPUT" = '{"count":1}' ]
}

mock_wg_show_interfaces_and_showconf() {
    tee wg > /dev/null <<'EOF' && chmod +x "$_"
        #!/bin/sh
        [ "$*" = "show interfaces" ] && echo "vpn1" && exit 0
        [ ! "$*" = "showconf vpn1" ] && echo "Not implemented: $0 $*" >&2 && exit 1
        cat <<'CFG'
        [Interface]
        ListenPort = 35869
        PrivateKey = private_key
        
        [Peer]
        PublicKey = manager_public_key
        AllowedIPs = 10.10.10.1/24
        Endpoint = 9.8.7.6:1234
        PersistentKeepalive = 13
        CFG
EOF
}

it_serves_config_with_redacted_private_key() {
    mock_wg_show_interfaces_and_showconf
    start_peer 127.0.0.1
    curl http://localhost:8080/config | cat -n | lookup \
        '1[[:space:]]+[[]Interface[]]' \
        '2[[:space:]]+ListenPort = 35869' \
        '3[[:space:]]+PrivateKey = <REDACTED>' \
        '4' \
        '5[[:space:]]+[[]Peer[]]' \
        '6[[:space:]]+PublicKey = manager_public_key' \
        '7[[:space:]]+AllowedIPs = 10.10.10.1/24' \
        '8[[:space:]]+Endpoint = 9.8.7.6:1234' \
        '9[[:space:]]+PersistentKeepalive = 13'
}