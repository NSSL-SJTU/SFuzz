#!/bin/bash
rootd="hybrid_all_output"
for dir in `ls $rootd`; do
    d=$rootd/$dir
    echo $d
    cp /root/uniFuzzGo/scripts/gen_poc_result_summary.py $d
    pushd $d 1>/dev/null
    python3 gen_poc_result_summary.py
    rm gen_poc_result_summary.py
    popd 1>/dev/null
    cp "$d/workdir/exec" $d/
    cp "$d/workdir/relied_functions" $d/ 2>/dev/null
    cp "$d/workdir/poc_result_summary" $d/ 2>/dev/null
    cp "$d/workdir/sink_buf" $d/ 2>/dev/null
    cp "$d/workdir/calltrace" $d/ 2>/dev/null
    cp "$d/workdir/poc_can_analyze_target_mem_size" $d/ 2>/dev/null
    rm -rf $d/afl_input $d/afl_driller $d/afl_driller_cmin $d/afl_dict $d/uf $d/all_state_summary $d/workdir $d/core
done
./add_checksum.sh
