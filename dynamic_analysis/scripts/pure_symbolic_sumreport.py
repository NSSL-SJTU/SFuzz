import os, sys, math, time
from pure_symsolve_utils import TARGET_BIN, HYBRID_ALL_OUTPUT_DIR

CVE_SINKS='''0x800cf8c8
0x800c65b4
0x800cbd8c
0x800cab2c
0x800d530c
0x800c0524
0x800bf79c
0x800c65b4
0x80070160
0x800169f4
0x800c0508
0x800cc444
0x800cc46c
0x800cab2c
0x80016454
0x800c65b4
0x404d30e4
0x4028ffd0
0xedb3c
0x80444954
0x803fcbc0
0x80090fec
0x803fe4e8
0x80096e44'''.split('\n')

_, dirs, __ = next(os.walk(HYBRID_ALL_OUTPUT_DIR))
dirs.sort(key = lambda i: int(i.split('_')[-1]))
TARGET_BIN_REPORT = {}
for tb in TARGET_BIN:
    TARGET_BIN_REPORT[tb] = ""
TARGET_BIN_PATHSUM = {}
for tb in TARGET_BIN:
    TARGET_BIN_PATHSUM[tb] = 0
TARGET_BIN_CRASHCNT = {}
for tb in TARGET_BIN:
    TARGET_BIN_CRASHCNT[tb] = 0
TARGET_BIN_FINDCRASHMINTIME = {}
for tb in TARGET_BIN:
    TARGET_BIN_FINDCRASHMINTIME[tb] = []
TARGET_BIN_STATESTAT = {}
for tb in TARGET_BIN:
    TARGET_BIN_STATESTAT[tb] = (0, 0)
TARGET_BIN_CONSTRAINTSTAT = {}
for tb in TARGET_BIN:
    TARGET_BIN_CONSTRAINTSTAT[tb] = []

def find(d):
    for tb in TARGET_BIN:
        if tb in d:
            return tb
    return None

def findl(l, l0):
    # find if any element in l0 is also in l
    for ll in l0:
        if ll in l:
            return ll
    return None

origin_workdir = os.getcwd()

for idx in range(len(dirs)):
    d = dirs[idx]
    tb = find(d)
    if tb == None:
        continue

    tmpdir = origin_workdir+'/'+HYBRID_ALL_OUTPUT_DIR+'/'+d 
    print('tmpdir: %s' % tmpdir)
    os.chdir(tmpdir)

    exec_path = tmpdir+'/workdir/exec'
    with open(exec_path, 'r') as f:
        exec_content = f.read().split('\n')
        sinks = [i for i in exec_content[7].split(' ')+exec_content[9].split(' ') if len(i)>0]
        sinks_cnt = len(sinks)


    report_path = tmpdir+'/workdir/pure_symsolve/report' 
    if os.access(report_path, os.F_OK):
        with open(report_path, 'r') as f:
            content = f.read()
            path_cnt_start = content.find('Path found:') + len('Path found: ')
            path_cnt_end = content.find('\n', path_cnt_start)
            path_cnt = eval(content[path_cnt_start:path_cnt_end])
            if path_cnt:
                TARGET_BIN_PATHSUM[tb] += path_cnt
            crash_found_start = content.find('Crash found:') + len('Crash found: ')
            crash_found_end = content.find('\n', crash_found_start)
            crash_found_cnt = eval(content[crash_found_start: crash_found_end])
            if crash_found_cnt and crash_found_cnt > sinks_cnt:
                content = content.replace('Crash found: %d' % crash_found_cnt, 'Crash found: %d' % sinks_cnt)
                TARGET_BIN_CRASHCNT[tb] += sinks_cnt
            elif crash_found_cnt:
                TARGET_BIN_CRASHCNT[tb] += crash_found_cnt
            # print(content)
            TARGET_BIN_REPORT[tb] += tmpdir + '\n' + content + '\n'
    else:
        TARGET_BIN_REPORT[tb] += tmpdir + '\nNot found\n\n'

    if os.access('workdir/pure_symsolve/symsolve_subfunc_statistic', os.F_OK):
        with open('workdir/pure_symsolve/symsolve_subfunc_statistic', 'r') as f:
            a,b=[int(i) for i in f.read().strip().split('\n')]
            TARGET_BIN_STATESTAT[tb] = (TARGET_BIN_STATESTAT[tb][0]+a, TARGET_BIN_STATESTAT[tb][1]+b)

    if os.access('workdir/pure_symsolve/symsolve_constraints_statistic', os.F_OK):
        with open('workdir/pure_symsolve/symsolve_constraints_statistic', 'r') as f:
            cont = f.read().strip('\n').split('\n')
            active_state_cnt = int(cont[0])
            constraints_sum = int(cont[1])
            crashinput_constraints_sum = int(cont[2])
            if active_state_cnt>0 or constraints_sum>0 or crashinput_constraints_sum>0:
                TARGET_BIN_CONSTRAINTSTAT[tb].append((active_state_cnt, constraints_sum, crashinput_constraints_sum))
            # print("active_state_cnt: %r"%active_state_cnt)
            # print("constraints_sum: %r"%constraints_sum)
            # print("crashinput_constraints_sum: %r"%crashinput_constraints_sum)


            

    _, __, files = next(os.walk("workdir/pure_symsolve"))
    mintime = math.inf
    for f in files:
        if 'symsolve_sink_crashinput_' in f:
            mintime = min(mintime, int(f.split('_')[-1]))
    if mintime != math.inf:
        TARGET_BIN_FINDCRASHMINTIME[tb].append(mintime)
    else:
        TARGET_BIN_FINDCRASHMINTIME[tb].append(6*60*60)

for tb in TARGET_BIN:
    print("TARGET_BIN: %s" %tb)
    print("TARGET_BIN_PATHSUM:")
    print(TARGET_BIN_PATHSUM[tb])
    print("TARGET_BIN_CRASHCNT:")
    print(TARGET_BIN_CRASHCNT[tb])
    if len(TARGET_BIN_FINDCRASHMINTIME[tb])!=0:
        while 0 in TARGET_BIN_FINDCRASHMINTIME[tb]:
            TARGET_BIN_FINDCRASHMINTIME[tb].remove(0)
        print("TARGET_BIN_FINDCRASHMINTIME:")
        print(TARGET_BIN_FINDCRASHMINTIME[tb])
        mintime = int(sum(TARGET_BIN_FINDCRASHMINTIME[tb])/len(TARGET_BIN_FINDCRASHMINTIME[tb]))
        print('%rs(%s)' % (mintime, time.strftime('%Hh%Mm%Ss', time.localtime(mintime))))
    if TARGET_BIN_STATESTAT[tb][1] != 0:
        print("TARGET_BIN_STATESTAT:")
        print(TARGET_BIN_STATESTAT[tb], '%.2f%%' % (TARGET_BIN_STATESTAT[tb][0]*100/TARGET_BIN_STATESTAT[tb][1]))
    if len(TARGET_BIN_CONSTRAINTSTAT[tb]) > 0:
        print("TARGET_BIN_CONSTRAINTSTAT:")
        print("active_state_cnt: %r" % (sum([i[0] for i in TARGET_BIN_CONSTRAINTSTAT[tb]])/len(TARGET_BIN_CONSTRAINTSTAT[tb])))
        print("constraints_sum: %r" % (sum([i[1] for i in TARGET_BIN_CONSTRAINTSTAT[tb]])/len(TARGET_BIN_CONSTRAINTSTAT[tb])))
        print("crashinput_constraints_sum: %r" % (sum([i[2] for i in TARGET_BIN_CONSTRAINTSTAT[tb]])/len(TARGET_BIN_CONSTRAINTSTAT[tb])))
        print(TARGET_BIN_CONSTRAINTSTAT[tb])

    print("")
    