#!/bin/bash
for d in `ls hybrid_all_output`; do 
    echo "-----------------"
    echo $d
    brandname=${d%_*}
    index=${d##*_}
    cp ~/findtrace_output/${brandname}_result/call_checksum_$index hybrid_all_output/$d/call_checksum
done 