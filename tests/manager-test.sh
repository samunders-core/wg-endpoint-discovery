#!/usr/bin/env roundup

before() {
    for app in ape chmod mkdir mv; do
      ln -fs /bin/$app "$(pwd)"
    done
    tee wg > /dev/null <<'EOF' && chmod +x "$_"
        #!/bin/sh
        [ "$*" = "show interfaces" ] && echo "vpn1" && exit 0
        [ ! "$*" = "show all dump" ] && echo "Not implemented: $0 $*" >&2 && exit 1
        echo 'vpn1	private_key	manager_public_key	1234	off'
        echo 'vpn1	offline_peer_public_key	(none)	(none)	127.0.0.42/32	42	0	0	13'
        echo 'vpn1	online_peer_public_key1	(none)	9.8.7.6:1234	127.0.0.1/32	1731099015	9351784	3698984	13'
        echo 'vpn1	online_peer_public_key2	(none)	9.8.7.6:2345	127.0.0.66/32	1731099015	9351784	3698984	13'
EOF
}

after() {
    kill %1 || true
    pkill -INT -f 'redbean.com -X -l 127.' || true
    rm -f ape chmod mkdir mv redbean.counts.sqlite3* wg
}

start_peer() {
  PATH=$(pwd) ./redbean.com -X -l "$1" 127.0.0.1 &
  sleep 1
  kill -0 $!    
}

it_relays_failure_notification() {
    DB_PATH=./redbean.counts.sqlite3.manager start_peer 127.0.0.1
    DB_PATH=./redbean.counts.sqlite3.online_peer start_peer 127.0.0.66
    OUTPUT="$(curl -d '' http://127.0.0.1:8080/notify/127.0.0.66)"  # A=curl -> B=127.0.0.1 -> C=127.0.0.66
    [ "$OUTPUT" = '{"count":1}' ]

    OUTPUT="$(curl -d '' http://127.0.0.66:8080/notify/127.0.0.42)"  # A=curl -> B=127.0.0.66 -> C=127.0.0.42
    [ "$OUTPUT" = '{"error":"Fetch(http:\/\/127.0.0.42:8080\/failed\/127.0.0.1) failed: connect(127.0.0.42:8080) error: Connection refused"}' ]

    DB_PATH=./redbean.counts.sqlite3.offline_peer start_peer 127.0.0.42
    OUTPUT="$(curl -d '' http://127.0.0.66:8080/notify/127.0.0.42)"  # A=curl -> B=127.0.0.66 -> C=127.0.0.42
    [ "$OUTPUT" = '{"count":1}' ]
}

