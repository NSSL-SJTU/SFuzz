#!/usr/bin/env python3
# 统计在目标内存大小不明确的情况下，我们统一不输出为告警，这有可能带来漏报的情况占所有sink的比例
import os
d = '/root/findtrace_output/'
brand = '2834_AC11_result'

target_dir = d+brand
idx = 0
classB_sinks_cnt = 0
all_sinks_cnt = 0

while os.access("%s/exec_%d"%(target_dir, idx), os.F_OK): 
    with open('%s/exec_%d'%(target_dir, idx), 'r') as f:
        content = f.read().strip('\n').split('\n')
    classA_sinks = content[6].split(' ')
    classB_sinks = content[8].split(' ')
    classB_sinks_cnt += len(classB_sinks)
    all_sinks_cnt += len(classA_sinks) + len(classB_sinks)
    with open('%s/sink_buf_%d'%(target_dir, idx), 'r') as f:
        content = f.read().strip('\n').split('\n')
        for c in content:
            # print(c)
            addr = c.split(' ')[0]
            dlen = c.split(' ')[2]
            if addr in classB_sinks and dlen=='-1':
                classB_sinks_cnt -= 1
    idx += 1
    
print("classB_sinks_cnt: {}".format(classB_sinks_cnt))
print("all_sinks_cnt: {}".format(all_sinks_cnt))
print("ratio: {:.2f}".format(classB_sinks_cnt/all_sinks_cnt*100))