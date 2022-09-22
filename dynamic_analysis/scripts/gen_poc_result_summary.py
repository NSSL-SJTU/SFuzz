#!/usr/bin/env python3
# this file is used for generate a summary for POC analysis
import os
import re
if not os.access("workdir/relied_functions", os.F_OK):
    print("No relied_functions found, poc analysis may not run")
    exit(0)
with open("workdir/exec",'r') as f:
    content = f.read().strip('\n').split('\n')
    sink_addrs = [int(i, 0) for i in content[7].split(' ')] if len(content[7])>0 else []
    sink_addrs += [int(i, 0) for i in content[9].split(' ')] if len(content[9])>0 else []
    print('sink_addrs:',sink_addrs)
    TRACE_END_ADDR = {}
    SYMSOLVE_END_ADDR = {}
    for sa in sink_addrs:
        TRACE_END_ADDR[sa] = False
        SYMSOLVE_END_ADDR[sa] = False

with open("workdir/relied_functions",'r') as f:
    content = f.read()
    # content_split = list(re.finditer('crash input.*0x[0-9a-fA-F]{8}:*\n', content))
content_split = []
idx = 0
while content.find('crash input "', idx)>=0:
    content_split.append(content[idx: content.find('crash input "', idx+11)])
    idx = content.find('crash input "', idx+11)

content_split.append(content[idx:])
for c in content_split:
    if len(c)<5:
        continue
    if 'is unable to find solvable path' not in c:
        # this sink is reachable for this crash
        sink_addr_start = c.find('reach sink addr ')+len('reach sink addr ')
        sink_addr = int(c[sink_addr_start:sink_addr_start+10], 0)
        TRACE_END_ADDR[sink_addr] = True
        if SYMSOLVE_END_ADDR[sink_addr]==False:
            SYMSOLVE_END_ADDR[sink_addr] = {}
        for detail in [i for i in c.split('\n') if 'Function called at' in i]:
            subfunc_addr = int(detail[detail.find('at ')+3:detail.find('at ')+13], 0)
            ptr_val_pos = detail.find('pointing to ')
            if ptr_val_pos>0:
                val = detail[ptr_val_pos+len('pointing to '):]
            else:
                val = int(detail[detail.find('should return: ')+len('should return: '):], 16)
            # if SYMSOLVE_END_ADDR[sink_addr]==False:
            #     SYMSOLVE_END_ADDR[sink_addr] = {subfunc_addr: val}
            if subfunc_addr not in SYMSOLVE_END_ADDR[sink_addr]:
                SYMSOLVE_END_ADDR[sink_addr][subfunc_addr]=val
            elif subfunc_addr in SYMSOLVE_END_ADDR[sink_addr] and SYMSOLVE_END_ADDR[sink_addr][subfunc_addr]!=val:
                SYMSOLVE_END_ADDR[sink_addr].pop(subfunc_addr)
            
    else:
        sink_addr_start = c.find('sink addr: ')+len('sink addr: ')
        sink_addr_end = c.find(']', sink_addr_start)+1
        sink_addr = eval(c[sink_addr_start:sink_addr_end])
        for sa in sink_addr:
            TRACE_END_ADDR[sa] = True

poc_can_analyze_target_mem_size = []
if os.access("workdir/poc_can_analyze_target_mem_size", os.F_OK):
    with open("workdir/poc_can_analyze_target_mem_size",'r') as f:
        poc_can_analyze_target_mem_size = f.read().strip('\n').split('\n')

with open("workdir/poc_result_summary",'w') as f:
    f.write("Ghidra sink results %r\n" % [hex(i) for i in sink_addrs])
    f.write("Trace sink results %r\n" % [hex(i) for i in [key for key in TRACE_END_ADDR if TRACE_END_ADDR[key]!=False]])
    f.write("POC Analysis sink results %r\n" % [hex(i) for i in [key for key in SYMSOLVE_END_ADDR if SYMSOLVE_END_ADDR[key]!=False]])
    f.write("POC Analysis can finally decide sink %r as sinkbuf that size can be determined\n" % poc_can_analyze_target_mem_size)
    f.write("For constaints analysis, refer to relied_functions")
