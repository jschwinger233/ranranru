#!/usr/bin/env bash
# usage: log-adder [target-bin] [script]

# script example:
# rpc/transform.go:53, start transform
# rpc/transform.go:59, end transform
# store/etcdv3/node.go:120, start doGet, ListPodNodes
# store/etcdv3/node.go:125, end doGet, ListPodNodes

while IFS=, read loc log cond; do
    addr=$(gdb -q $1 --batch -ex 'b '$loc 2>/dev/null | grep -Po '(?<=at )0x[^:]+')
    if [ -n "$cond" ]; then
        cat <<!
$addr {
import datetime
if '$cond' in stack:
    print(datetime.datetime.now().strftime('%y-%m-%d %H:%M:%S'), '$log')
}
!
    else
        cat <<< "$addr { import datetime; print(datetime.datetime.now().strftime('%y-%m-%d %H:%M:%S'), '$log') }"
    fi
done < $2
