#!/bin/bash
filename=$1
cpu=$2 # should be ARM:LE:32:v7 or MIPS:LE:32:default or BE
base=$3
binary=`basename $filename`
if [ $1 == 'clean' ]; then
        rm -rf /root/ghidra_project /root/findtrace_output
        mkdir /root/ghidra_project
        exit 0
fi

mkdir -p /root/ghidra_project

rm -rf /root/ghidra_project/$binary".gpr" /root/ghidra_project/$binary".rep"


/root/deps/ghidra_9.2.3_PUBLIC/support/analyzeHeadless /root/ghidra_project `basename $filename` -import $filename -processor $cpu  -preScript /root/findtrace/setbase.py $base -postScript /root/findtrace/findtrace.py