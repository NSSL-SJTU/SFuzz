#!/usr/bin/env python3
import sys, signal, time, os, random,logging

def handler(signum, handler):
    exit(0)
signal.signal(signal.SIGINT, handler)

def time_calc(t):
    fl = "%.2f" % t
    mi = int(t / 60)
    st = "%dm %.2fs" % (mi, t - mi * 60)
    return "%s(%s)" % (fl, st)


def main():
    case_len = int(sys.argv[2])
    RESULT_DIR = sys.argv[3]
    PROC_SYNC_DIR = sys.argv[4]
    while True:
        case_crash_cnt = [0] * case_len 
        time_now = time.time()
        root, dirs, files = next (os.walk("%s_%s/"%(PROC_SYNC_DIR, sys.argv[1])))
        state = ['\033[36mnot started\033[0m' for i in range(case_len)]
        found = 0
        finish = 0
        task_sum_time = 0

        unexpected_ratio = []
        
        poc_times = []
        # unique_crashes = []

        unexpected_sum = 0
        exec_sum = 0

        paths_total_brand = 0
        
        for i in range(case_len):
            tf = None
            tg = None
            tmpdir = None
            execs_done = 0
            unexpected_count = 0
            paths_total = 0
            for f in files:
                if f.startswith('%d-*'%i):
                    tf = int(f.split('-')[-2],10)
                    tmpdir = f.split('-')[-1]
                elif f.startswith('%d-+'%i):
                    tg = int(f.split('-')[-2],10)
                    tmpdir = f.split('-')[-1]
            if tf and tg:
                state[i] = '\033[32;1m[FINISH]\033[0m\tdirpath:%s\ttime: %s'%(tmpdir, time_calc(tf-tg))
                finish += 1
                task_sum_time += tf-tg
            elif tg:
                state[i] = '\033[34;1;5m[ONGOING]\033[0m\tdirpath:%s\ttime: %s'%(tmpdir, time_calc(time_now-tg))
            try:
                # crash count
                if os.access("/root/uniFuzzGo/%s/%s/afl_output/default/crashes"%(RESULT_DIR, tmpdir), os.F_OK):
                    crash_cnt = len(next(os.walk("/root/uniFuzzGo/%s/%s/afl_output/default/crashes/"%(RESULT_DIR, tmpdir)))[2]) - 1 # README.md in crashes/
                    # print(crash_cnt)
                    if crash_cnt > 0:
                        case_crash_cnt[i] += crash_cnt
                        state[i] += "\t\033[31;1mFOUND CRASH * %d\033[0m" % case_crash_cnt[i]
                        found += 1
                        if os.access("/root/uniFuzzGo/%s/%s/workdir/POC_time"%(RESULT_DIR, tmpdir), os.F_OK):
                            with open("/root/uniFuzzGo/%s/%s/workdir/POC_time"%(RESULT_DIR, tmpdir), 'r') as f:
                                poctime = int(f.read())
                                state[i] += " POC time: %s"%time_calc(poctime)
                                poc_times.append(poctime)
                    else:
                        state[i] += "\tNOT FOUND CRASH"    
                else:
                    state[i] += "\tNOT FOUND CRASH"

                # unexpected crash count(if needed)
                if os.getenv("UF_LOGUNEXP_CRASH") and (os.getenv("UF_LOGUNEXP_CRASH")=="YES" or os.getenv("UF_LOGUNEXP_CRASH")=="yes") and os.access("/root/uniFuzzGo/%s/%s/workdir/execs_done"%(RESULT_DIR, tmpdir), os.F_OK):
                    with open("/root/uniFuzzGo/%s/%s/workdir/execs_done"%(RESULT_DIR, tmpdir), 'r') as f:
                        cont = f.read().strip('\n')
                        if len(cont)>0:
                            execs_done = max([int(i) for i in cont.split('\n') if len(i)>0])
                    if os.access("/root/uniFuzzGo/%s/%s/workdir/unexpected_count"%(RESULT_DIR, tmpdir), os.F_OK):
                        with open("/root/uniFuzzGo/%s/%s/workdir/unexpected_count"%(RESULT_DIR, tmpdir), 'r') as f:
                            cont = f.read().strip('\n')
                            if len(cont)>0:
                                unexpected_count = max([int(i) for i in cont.split('\n') if len(i)>0])
                        if execs_done!=0:
                            unexpected_ratio.append(unexpected_count*100.0/execs_done)
                            unexpected_sum += unexpected_count
                            exec_sum += execs_done
                    else:
                        unexpected_count = 0
                    
                    state[i] += " unexpected crash ratio: %%%.2f(%d/%d)"%(unexpected_count*100.0/execs_done, unexpected_count, execs_done)
                
                # path total count
                if os.access("/root/uniFuzzGo/%s/%s/workdir/paths_total"%(RESULT_DIR, tmpdir), os.F_OK):
                    with open("/root/uniFuzzGo/%s/%s/workdir/paths_total"%(RESULT_DIR, tmpdir), 'r') as f:
                        cont = f.read().strip('\n')
                        if len(cont)>0:
                            paths_total = max([int(i) for i in cont.split('\n') if len(i)>0])
                            paths_total_brand += paths_total
                    state[i] += " paths_total: %d"%(paths_total)
            except Exception as e:
                logging.exception("looks like afl-fuzz failed to start with %s"%str(e))
        os.system("clear")
        print("\n\nTARGET:".ljust(20,' ')+"%s(%s)\n"%(sys.argv[1], sys.argv[3]))
        for i in range(case_len):
            sys.stdout.write(("TASK %d:"%i).ljust(10,' ')+state[i].ljust(60,' ')+'\n')
        
        found_rt = found*100//case_len
        finish_rt = finish*100//case_len

        print("\n\nFOUND CRASH TREE:\t"+("*"*(found_rt)).ljust(100,'-') + "%d%%(%d/%d)"%(found_rt, found, case_len))
        print("FINISH:\t\t"+("*"*(finish_rt)).ljust(100,'-') + "%d%%(%d/%d)"%(finish_rt, finish, case_len))
        if finish!=0:
            print("Average trace fuzzing time: %s"%time_calc(task_sum_time/finish))
            print("Current model fuzzing time: %s"%time_calc(task_sum_time))
        if exec_sum != 0:
            print("unexpected crash sum count: %%%.2f(%d/%d)" % (unexpected_sum*100.0/exec_sum, unexpected_sum, exec_sum))
            print("unexpected crash ratio: %%%.2f" % (sum(unexpected_ratio)/len(unexpected_ratio)))
            print("success simlation ratio: %%%.2f" % (100-sum(unexpected_ratio)/len(unexpected_ratio)))
        if paths_total_brand != 0:
            print("paths total: %d"%paths_total_brand)
        if len(poc_times)>0:
            print("POC average time %s"%time_calc(sum(poc_times)/len(poc_times)))
        print("Find unique crash count: %d"%sum(case_crash_cnt))

        time.sleep(random.random()*10)

if __name__ == '__main__':
    main()