#!/usr/bin/env python3
# crash input的conclic testing符号执行，crash input前后过滤了多少，形成了PoC
# 即：AFL得到了多少个crash input vs. 实际确认的有漏洞的source-sink数量
import os
d = '/root/ufg-results/ufg-result-Jan2/hybrid_all_output/'
brand = '2834_AC11'

target_dir = d+brand
idx = 0

trace_sink_count = 0
poc_sink_count = 0
crashes_count = 0

while os.access("%s_%d/afl_output/default/crashes/"%(target_dir, idx), os.F_OK): 
    # print("%s_%d/afl_output/default/crashes/"%(target_dir, idx))
    _, __, crashes = next(os.walk("%s_%d/afl_output/default/crashes"%(target_dir, idx)))
    if 'README.txt' in crashes:
        crashes.remove('README.txt')
    print(crashes)
    if len(crashes)<=1:
        pass
    else:
        if not os.access("%s_%d/poc_result_summary"%(target_dir, idx), os.F_OK):
            pass
        else:
            with open("%s_%d/poc_result_summary"%(target_dir, idx)) as f:
                content = f.read()
            trace_sink_results_start = content.find('Trace sink results ') + len('Trace sink results ')
            trace_sink_results_end = content.find('\n', trace_sink_results_start)
            trace_sink_results = eval(content[trace_sink_results_start: trace_sink_results_end])

            poc_sink_results_start = content.find('POC Analysis sink results ') + len('POC Analysis sink results ')
            poc_sink_results_end = content.find('\n', poc_sink_results_start)
            poc_sink_results = eval(content[poc_sink_results_start:poc_sink_results_end])

            trace_sink_count += len(trace_sink_results)
            poc_sink_count += len(poc_sink_results)
            crashes_count += len(crashes)
    idx += 1

print("trace_sink_count:",trace_sink_count)
print("poc_sink_count:",poc_sink_count)
print("crashes_count:",crashes_count)