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
    rm -f ape chmod mkdir mv wg
}

it_requires_manager_address_as_argument() {
    ! OUTPUT="$(timeout 3 ./redbean.com -X < /dev/null 2>&1)"
    echo "$OUTPUT" | lookup "Malformed manager address provided as first argument: "
}

#it_accepts_port_as_optional_second_argument() {
#    false
#}

it_requires_wireguard_installation() {
    ! OUTPUT="$(env --ignore-environment "PATH=$(pwd)" /usr/bin/timeout 3 ./redbean.com -X 127.0.0.1 < /dev/null 2>&1)"
    echo "$OUTPUT" | lookup "commandv[(][)] failed: No such file or directory 'wg'" 
}

it_serves_status_as_key_and_numeric_value_pairs() {
    ln -s /bin/false wg
    PATH=$(pwd) ./redbean.com -X 127.0.0.1 &
    sleep 1
    OUTPUT="$(curl http://localhost:8080/statusz)"
    [ -n "$OUTPUT" ]
    echo "$OUTPUT" | awk '/^$/{next} $1 !~ /[0-9a-zA-Z_.]+:/ || $2 !~ /[0-9]+/{f=NR} END{exit f}'
}

mock_wg_show_interfaces_and_showconf() {
    (
        echo '#!/bin/sh'
        echo '[ "$*" = "show interfaces" ] && echo "vpn1" && exit 0'
        echo '[ ! "$*" = "showconf vpn1" ] && echo "Not implemented: $0 $*" >&2 && exit 1'
        echo "echo '[Interface]'"
        echo "echo 'ListenPort = 35869'"
        echo "echo 'PrivateKey = private_key'"
        echo "echo ''"
        echo "echo '[Peer]'"
        echo "echo 'PublicKey = manager_public_key'"
        echo "echo 'AllowedIPs = 10.10.10.1/24'"
        echo "echo 'Endpoint = 9.8.7.6:1234'"
        echo "echo 'PersistentKeepalive = 13'"
    ) > wg
    chmod +x wg
    PATH=$(pwd) ./redbean.com -X --strace 127.0.0.1 &
    sleep 1
    kill -0 $!
}

it_serves_config_with_redacted_private_key() {
    mock_wg_show_interfaces_and_showconf
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