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

it_requires_manager_address_as_argument() {
    ! OUTPUT="$(timeout 3 ./redbean.com < /dev/null 2>&1)"
    echo "$OUTPUT" | lookup "Malformed manager address provided as first argument: "
}

#it_accepts_port_as_optional_second_argument() {
#    false
#}

it_requires_wireguard_installation() {
    ! OUTPUT="$(env --ignore-environment "PATH=$(pwd)" /usr/bin/timeout 3 ./redbean.com 127.0.0.1 < /dev/null 2>&1)"
    echo "$OUTPUT" | lookup "commandv[(][)] failed: No such file or directory 'wg'" 
}

it_serves_status_as_key_and_numeric_value_pairs() {
    ln -s /bin/false wg
    PATH=$(pwd) ./redbean.com 127.0.0.1 &
    sleep 1
    OUTPUT="$(curl http://localhost:8080/statusz)"
    [ -n "$OUTPUT" ]
    echo "$OUTPUT" | awk '/^$/{next} $1 !~ /[0-9a-zA-Z_.]+:/ || $2 !~ /[0-9]+/{f=NR} END{exit f}'
}
