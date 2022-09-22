#!/usr/bin/env python3
import os, sys
import re, subprocess
import time
import pprint
if len(sys.argv)>1:
    brand = sys.argv[1]
    show_crashinput_content = len(sys.argv)>2 and sys.argv[2]=="-show_crashinput_content"
else:
    print("Usage: ./count.py firmware_name [-show_crashinput_content]")
    exit(0)

dirs = next(os.walk('./hybrid_all_output/'))[1]
target = [d for d in dirs if brand in d]
resstr=[]
Ghidra_sink_results_cnt = 0
Trace_sink_results_cnt = 0
POC_Analysis_sink_results_cnt = 0
POC_Analysis_determine_sink_size_results_cnt = 0
POC_Analysis_determine_sink_size_results_tree_cnt = 0
crash_input_cnt = 0
relied_cnt = 0

poc_miss_fuzz = {}
poc_miss_tree = {}
poc_determine_fuzz_sink_size = {}

for t in target:
    execinfo = open("./hybrid_all_output/%s/exec"%t).read().strip('\n').split('\n')

    firmware = t[:t.rfind('_')]
    crashes = next(os.walk('./hybrid_all_output/%s/afl_output/default/crashes/'%t))[2]
    idx=int(t.split('_')[-1])

    beginaddr=execinfo[3]
    endaddrs_classA=execinfo[6].split(' ')
    endaddrs_classB=execinfo[8].split(' ')
    endaddrs = endaddrs_classA + endaddrs_classB

    endaddrs_convert = {}
    for i in range(len(execinfo[7].split(' '))):
        endaddrs_convert[execinfo[7].split(' ')[i]] = execinfo[6].split(' ')[i]
    for i in range(len(execinfo[9].split(' '))):
        endaddrs_convert[execinfo[9].split(' ')[i]] = execinfo[8].split(' ')[i]

    reliedinfo = '\033[0;35mPoC Result Summary:\033[0;0m\n'
    if os.access("./hybrid_all_output/%s/poc_result_summary"%t, os.F_OK):
        content = open("./hybrid_all_output/%s/poc_result_summary"%t).read()
        reliedinfo += content
        Ghidra_sink_results = Trace_sink_results = POC_Analysis_sink_results = None
        if 'Ghidra sink results ' in content:
            s=content.find('Ghidra sink results ')+len('Ghidra sink results ')
            e=content.find('\n', s)
            Ghidra_sink_results = eval(content[s:e])
            if '' in Ghidra_sink_results:
                Ghidra_sink_results.remove('')
            Ghidra_sink_results_cnt += len(Ghidra_sink_results)
        if 'Trace sink results ' in content:
            s=content.find('Trace sink results ')+len('Trace sink results ')
            e=content.find('\n', s)
            Trace_sink_results = eval(content[s:e])
            if '' in Trace_sink_results:
                Trace_sink_results.remove('')
            Trace_sink_results_cnt += len(Trace_sink_results)
        if 'POC Analysis sink ' in content:
            s=content.find('POC Analysis sink results ')+len('POC Analysis sink results ')
            e=content.find('\n', s)
            POC_Analysis_sink_results = eval(content[s:e])
            if '' in POC_Analysis_sink_results:
                POC_Analysis_sink_results.remove('')
            POC_Analysis_sink_results_cnt += len(POC_Analysis_sink_results)
        if 'POC Analysis can finally decide sink' in content:
            s=content.find('POC Analysis can finally decide sink ')+len('POC Analysis can finally decide sink ')
            e=content.find(' as sinkbuf that size can be determined', s)
            POC_Analysis_determine_sink_size_results = list(set(eval(content[s:e])))
            if '' in POC_Analysis_determine_sink_size_results:
                POC_Analysis_determine_sink_size_results.remove('')
            POC_Analysis_determine_sink_size_results_cnt += len(POC_Analysis_determine_sink_size_results)
            if len(POC_Analysis_determine_sink_size_results)>0:
                POC_Analysis_determine_sink_size_results_tree_cnt += 1

        # 统计fuzzing到但poc不到的sink地址
        if Trace_sink_results!=None and POC_Analysis_sink_results!=None and len(POC_Analysis_sink_results)<len(Trace_sink_results):
            poc_miss_fuzz[idx] = 'beginaddr %r fuzz results: %r poc results: %r'%(beginaddr, Trace_sink_results, POC_Analysis_sink_results)
        # 统计fuzzing到但poc认为这个sinkbuf大小不能确定的sink地址
        if Trace_sink_results!=None and POC_Analysis_determine_sink_size_results!=None and len(POC_Analysis_determine_sink_size_results)<len(Trace_sink_results):
            print('beginaddr %r fuzz results: %r POC_Analysis_determine_sink_size_results: %r'%(beginaddr, Trace_sink_results, POC_Analysis_determine_sink_size_results))
            poc_determine_fuzz_sink_size[idx] = 'beginaddr %r fuzz results: %r POC_Analysis_determine_sink_size_results: %r'%(beginaddr, Trace_sink_results, POC_Analysis_determine_sink_size_results)

        for execinfo in endaddrs_convert:
            reliedinfo = reliedinfo.replace(execinfo, endaddrs_convert[execinfo])
    else:
        reliedinfo += 'Not found'
        poc_miss_tree[idx] = False
    
    reliedinfo += '\n\033[0;36mRelied Functions Details:\033[0;0m\n'
    if os.access("./hybrid_all_output/%s/relied_functions"%t, os.F_OK):
        content = open("./hybrid_all_output/%s/relied_functions"%t).read()
        reliedinfo += content
        if 'Function called at ' in content:
            relied_cnt += len(set(re.findall(r'Function called at 0x[0-9a-f]{8} should return', content)))
    else:
        reliedinfo += 'Not found'
        poc_miss_tree[idx] = False

    if os.access("./hybrid_all_output/%s/call_checksum"%t, os.F_OK):
        if len(reliedinfo)>0:
            reliedinfo = reliedinfo.replace("may required:\n", "may required:\n" + open("./hybrid_all_output/%s/call_checksum"%t).read())
        else:
            reliedinfo = "all crashes may required:\n" + open("./hybrid_all_output/%s/call_checksum"%t).read()

    # process path info to full path
    input_files = re.findall('".*"', reliedinfo)
    for input_file in input_files:
        input_file_name = input_file.strip('"').split('/')[-1]
        p = subprocess.Popen("realpath `find . -name %s -print` 2>/dev/null"%input_file_name, shell=True, stdout=subprocess.PIPE)
        output = p.stdout.read().strip(b'\n')
        #print("output: %s"%output)
        if output:
            reliedinfo = reliedinfo.replace(input_file, '"'+output.decode()+'"')
    

    ress = "[\033[0;42m*\033[0m]"
    if len(crashes)>0:
        if 'README.txt' in crashes:
            crashes.remove('README.txt')
        crash_input_cnt += len(crashes)
        ress += "Firmware %s \033[0;34mfound crash\033[0m in tree %d\n" % (firmware, idx)
        ress += "Begin address %r End address %r\n" % (beginaddr, endaddrs)
        ress += "\nUnique crashes * %d:\n%r\n\n" % (len(crashes), crashes) 
        ress += "Relied functions info: \n%s\n" % reliedinfo
    else:
        ress += "Firmware %s \033[0;32mnot found crash\033[0m in tree %d\n" % (firmware, idx)
        ress += "Begin address %r End address %r" % (beginaddr, endaddrs)
        if idx in poc_miss_tree:
            poc_miss_tree.pop(idx)

    
    resstr.append((idx, ress))
resstr.sort(key=lambda v:v[0])
sys.stdout.write("\n\n".join(r[1] for r in resstr))
sys.stdout.write('\n\n%d of %d call trees found crash\n'%(len(resstr)-len([s for s in resstr if 'not found crash' in s[1]]), len(resstr)))
print('crash_input_cnt: %r'%crash_input_cnt)
print('Ghidra_sink_results_cnt: %r'%Ghidra_sink_results_cnt)
print('Trace_sink_results_cnt: %r'%Trace_sink_results_cnt)
print('POC_Analysis_sink_results_cnt: %r'%POC_Analysis_sink_results_cnt)
print('POC_Analysis_determine_sink_size_results_cnt: %r'%POC_Analysis_determine_sink_size_results_cnt)
print('POC_Analysis_determine_sink_size_results_tree_cnt: %r'%POC_Analysis_determine_sink_size_results_tree_cnt)
print('relied_cnt: %r'%relied_cnt)
pp = pprint.PrettyPrinter(indent=4)
print('poc_miss_fuzzing results: ')
pp.pprint(poc_miss_fuzz)
print('poc_miss_tree results: ')
pp.pprint(poc_miss_tree)
print('poc_determine_fuzz_sink_size: ')
pp.pprint(poc_determine_fuzz_sink_size)