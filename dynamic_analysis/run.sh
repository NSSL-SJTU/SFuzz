#!/bin/bash
printUsage(){
    echo "Usage: ./run.sh [OPTIONS] [GHIDRA RESULTs DIR] [TRACE IDX] [TARGET] [OPTION ARGS]"
    echo "OPTIONS:"
    echo "TRACE target input: run target with given input in debug mode, and log block and pc"
    echo "DEBUG target: run fuzzer in debug mode with gdb attach"
    echo "DRILLER target input <bitmap>: run driller with given input(and possible fuzz_bitmap)"
    echo "FUZZ target: run fuzzer"
    echo "HYBRID "
    exit -1
}

# do not add space here
OPTION=$1
export GHIDRA_DIR=$2
export TRACE_IDX=$3
export UF_TARGET=$4
APPEND_ARG=$5

initWorkdir(){
    echo "executing initWorkdir"
    mkdir -p workdir
    rm -rf workdir/*
    cp $GHIDRA_DIR/connect_$TRACE_IDX workdir/connect
    cp $GHIDRA_DIR/exec_$TRACE_IDX workdir/exec
    cp $GHIDRA_DIR/patch_$TRACE_IDX workdir/patch_
    cp $GHIDRA_DIR/stack_retaddr_$TRACE_IDX workdir/stack_retaddr
    cp $GHIDRA_DIR/cbranch_info_$TRACE_IDX workdir/cbranch_info
    cp $GHIDRA_DIR/call_checksum_$TRACE_IDX workdir/call_checksum
    cp $UF_TARGET workdir/`basename $UF_TARGET`
    python3 scripts/binary_patch.py $UF_TARGET
}

clean_workdir(){
    # delete some log file to save space for harddrive
    rm workdir/`basename $UF_TARGET`
    rm workdir/traceLog.txt
    rm workdir/pcLogger.txt
}

execCommand(){

    if [ $OPTION == "TRACE" ]; then
        make "UFDBG=-DUF_DEBUG -g"
        UF_TRACE=yes timeout 1 ./uf < $APPEND_ARG 
        retcode=$?
        echo "program exit with code $retcode"
        exit $retcode
    fi  

    if [ $OPTION == "PATCHCNTD" ]; then
        make "UFDBG=-DUF_DEBUG -g"
        UF_TRACE=yes UF_CNTPATCH=yes ./uf < $APPEND_ARG
        retcode=$?
        # echo "program exit with code $retcode"
        exit $retcode
    fi  

    if [ $OPTION == "DEBUG" ]; then
        make "UFDBG=-DUF_DEBUG -g"
        UF_TRACE=yes gdb ./uf 
    fi

    if [ $OPTION == "DRILLER" ]; then
        rm -f workdir/driller_constraints_statistic_*
        python3 scripts/driller_analysis.py $NO_OUTPUT # it will automatically parse info in afl_output/ 
        if [ $? -ne 0 ]; then
            echo -e '\033[41mDriller failed on execting '$UF_TARGET'\033[0m';
        fi
    fi

    if [ $OPTION == "FUZZ" ]; then
        rm -rf afl_input afl_dict
        mkdir afl_input
        mkdir afl_dict
        cp $GHIDRA_DIR/dict_$TRACE_IDX afl_dict/dict
        # python3 -c "print('z'*4)" > afl_input/input0
        python3 -c "print('z'*16)" > afl_input/input1
        python3 -c "print('z'*64)" > afl_input/input2
        python3 -c "print('z'*256)" > afl_input/input3
        python3 -c "print('z'*1024)" > afl_input/input4 # 1024 = 0x400
        python3 -c "print('z'*1024)" > afl_dict/dict1
        
        make 
        strip uf

        # test if current input can trigger crash, if so, directly move it to crashes input dir
        # mkdir -p afl_output/default/crashes/
        # UF_TRACE=no ./uf < afl_input/input0
        # if [[ $? > 0 ]]; then
        #     cp afl_input/input0 afl_output/default/crashes/
        #     touch "afl_output/default/fuzzer_stats"
        #     return
        # fi
        # UF_TRACE=no ./uf < afl_input/input1
        # if [[ $? > 0 ]]; then
        #     cp afl_input/input1 afl_output/default/crashes/
        #     touch "afl_output/default/fuzzer_stats"
        #     return
        # fi
        # UF_TRACE=no ./uf < afl_input/input2
        # if [[ $? > 0 ]]; then
        #     cp afl_input/input2 afl_output/default/crashes/
        #     touch "afl_output/default/fuzzer_stats"
        #     return
        # fi
        # UF_TRACE=no ./uf < afl_input/input3
        # if [[ $? > 0 ]]; then
        #     cp afl_input/input3 afl_output/default/crashes/
        #     touch "afl_output/default/fuzzer_stats"
        #     return
        # fi
        # UF_TRACE=no ./uf < afl_input/input4
        # if [[ $? > 0 ]]; then
        #     cp afl_input/input4 afl_output/default/crashes/
        #     touch "afl_output/default/fuzzer_stats"
        #     return
        # fi

        UF_TRACE=no timeout 1800 /root/AFLplusplus/afl-fuzz -U -i afl_input -o afl_output -x afl_dict ./uf & 
    fi

    if [ $OPTION == "REF" ]; then
        make 
        strip uf
        rm afl_input/* 
        cp afl_driller_cmin/* afl_input
        UF_TRACE=no timeout 1800 /root/AFLplusplus/afl-fuzz -U -i afl_input -o afl_output -x afl_dict ./uf & 
    fi

    if [ $OPTION == "SYMSOLVE" ]; then
        UF_TRACE=no python3 scripts/symbolic_solving.py $APPEND_ARG
    fi 

    if [ $OPTION == "HYBRID" ]; then

        echo -e '\033[0;42m1st phase: AFL FUZZING\033[0m'; 
        echo -e '\033[0;42mUF_PATCHJMP='$UF_PATCHJMP'\tUF_USEDRILLER='$UF_USEDRILLER'\tUF_PATCHNOP='$UF_PATCHNOP'\033[0m'; 
        OPTION="FUZZ"
        make clean
        execCommand
        sleep 10
        if [ -s "afl_output/default/fuzzer_stats" ]; then
            while true ;
            do 
                LOOP="TRUE"
                FOUND_CRASH="FALSE"
                while [[ $LOOP == "TRUE" && $FOUND_CRASH == "FALSE" ]]; do
                    last_crash=0
                    last_path=0
                    last_update=0
                    while read LINE
                    do  
                        # if [ "$LINE" == "pending_favs      : 0" ]; then
                        #     LOOP="FALSE"
                        #     break
                        # fi

                        if [[ "$LINE" =~ "last_path" ]]; then
                            last_path=`echo "$LINE" | tr -cd "[0-9]"`
                            # echo "last_path: $last_path"
                        fi
                        if [[ "$LINE" =~ "last_crash" ]]; then
                            last_crash=`echo "$LINE" | tr -cd "[0-9]"`
                            # echo "last_crash: $last_crash"
                        fi
                        if [[ "$LINE" =~ "last_update" ]]; then
                            last_update=`echo "$LINE" | tr -cd "[0-9]"`
                            # echo "last_update: $last_update"
                        fi
                        if [[ "$LINE" =~ "start_time" ]]; then
                            start_time=`echo "$LINE" | tr -cd "[0-9]"`
                            # echo "start_time: $start_time"
                        fi
                        
                        # if last_crash or last_path has not updated for over 10 minutes, end fuzzing process.
                        if [[ ($[$last_update-$last_path] -ge $[60*10]) && ($last_path -gt 0)]]; 
                        then
                            LOOP="FALSE"
                            break
                        fi
                        if [[ ($[$last_update-$last_crash] -ge $[60*10]) && ($last_crash -gt 0) ]]; 
                        then
                            LOOP="FALSE"
                            break
                        fi
                        # if last_path==0 and AFL has updated for over 10 minutes, end fuzzing process.
                        if [[ ($last_path -eq 0) && ($[$last_update-$start_time] -ge $[60*10]) ]];
                        then
                            LOOP="FALSE"
                            break
                        fi
                    done < "afl_output/default/fuzzer_stats"
                    sleep 5
                done

                pkill timeout -P $$

                cat workdir/unexpected_log 2>/dev/null | wc -l >> workdir/unexpected_count
                rm workdir/unexpected_log 2>/dev/null
                execs_done=`cat afl_output/default/fuzzer_stats | grep execs_done | awk '{print $3}'`
                echo $execs_done >> workdir/execs_done
                paths_total=`cat afl_output/default/fuzzer_stats | grep paths_total | awk '{print $3}'`
                echo $paths_total >> workdir/paths_total

                if [[ `ls afl_output/default/crashes | wc -l` > 0 ]]; then
                    FOUND_CRASH="TRUE"
                fi

                if [ $FOUND_CRASH == "TRUE" ]; then
                    echo -e "\033[0;44mSeems we have found crash input, stop HYBRID fuzzing process and call POC verifier\033[0m"
                    OPTION="DRILLER"
                    make clean
                    execCommand $NO_OUTPUT
                    echo -e "\033[0;42m4rd phase: POC Verify\033[0m"; 
                    SECONDS=0
                    ls afl_output/default/crashes | while read crash_input 
                    do
                        if [ $crash_input != "README.txt" ]; then
                            python3 scripts/symbolic_solving.py afl_output/default/crashes/$crash_input
                        fi
                    done 
                    echo $SECONDS >workdir/POC_time
                    echo -e "\033[0;42m5th phase: EXIT\033[0m"; 
                    clean_workdir
                    exit 0
                fi
                echo -e "\033[0;44mDetect AFL stuck situation, calling driller\033[0m"
                echo -e "\033[0;42m2nd phase: DRILLING\033[0m"; 
                
                if [[ $UF_USEDRILLER == 'no' || $UF_USEDRILLER == 'NO' ]]; then 
                    echo -e "\033[0;41mBypass DRILLING since UF_USEDRILLER set to $UF_USEDRILLER\033[0m"; 
                else 
                    OPTION="DRILLER"
                    make clean
                    execCommand $NO_OUTPUT
                    echo -e "\033[0;44mDriller exec success, checking whether new inputs has generated...\033[0m"
                fi


                DRILLER_GET_NEW_INPUT="FALSE"
                if [ `find afl_driller_cmin -name "driller-*" | wc -l` != "0" ]; then
                    DRILLER_GET_NEW_INPUT="TRUE"
                fi

                if [ $DRILLER_GET_NEW_INPUT  == "TRUE" ]; then
                    echo -e "\033[0;44mGet new input by drilling, refuzz\033[0m"
                    echo -e "\033[0;42m3rd phase: RE-FUZZING\033[0m"; 
                    OPTION="REF"
                    make clean
                    execCommand
                    sleep 10
                else
                    echo -e "\033[0;44mSeems we have explore everything, stop HYBRID fuzzing process\033[0m"
                    echo -e "\033[0;42m4rd phase: EXIT\033[0m"; 
                    # rkill $$
                    return 
                fi
            done
        fi 
    fi
}

if [ $OPTION == "COUNT_PATCH" ]; then
    make clean -s 2>/dev/null
    make -s
    rm `find . -name "patch_count" ` ; rm patch_count_sum
    target_dir='hybrid_all_output'
    for brand_dir in `ls $target_dir`; do
        brand_dir=`basename $brand_dir`
        echo -e "\n\033[0;42m$brand_dir ${brand_dir%_*}\033[0m"
        cp uf $target_dir/$brand_dir
        {
            pushd $target_dir/$brand_dir 
            echo "working dir: " `realpath $target_dir/$brand_dir`
            export UF_TARGET=`find ~/evaluation_set/ -name "${brand_dir%_*}"`
            for queue in `ls afl_output/default/queue`; do
                APPEND_ARG=afl_output/default/queue/$queue
                # cat workdir/exec
                # echo "queue input $APPEND_ARG"
                for i in {1..2}; do 
                    echo $i
                    UF_TRACE=no UF_CNTPATCH=yes timeout 5 ./uf < $APPEND_ARG 
                done  # 1>&2 2>/dev/null
            done
            python3 scripts/patch_count.py
            # rm workdir/patch_count
            popd
        }  &
    done 
else 
    if [ $OPTION == "COUNT_ALL" ]; then
        rm patch_count_sum
        target_dir='hybrid_all_output'
        for brand_dir in `ls $target_dir`; do
            echo -e "\n\033[0;42m$brand_dir ${brand_dir%_*}\033[0m"
            echo "----------------------------------------" >> patch_count_sum
            echo $target_dir/$brand_dir >> patch_count_sum
            echo "path count: "`cat $target_dir/$brand_dir/afl_output/default/fuzzer_stats | grep paths_total | awk '{print $3}'` >> patch_count_sum
            cat $target_dir/$brand_dir/workdir/patch_count_sum >> patch_count_sum
            echo "========================================" >> patch_count_sum
        done
    else 
        if [ $OPTION == "HYBRID_ALL" ]; then
            OPTION="HYBRID"
            NO_OUTPUT="1>/dev/null"
            echo -e "\033[42mHYBRID_ALL\033[0m"
            execCommand
            rkill $$
        else
            if [ $OPTION == "INITDIR" ]; then
                initWorkdir
            else 
                if [ $OPTION == "CLEAN" ]; then
                rm -r hybrid_all_output /tmp/pwn-asm-* /tmp/pwn-disasm-*
                else
                    execCommand
                fi
            fi
        fi
    fi
fi
