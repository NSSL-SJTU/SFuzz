#!/usr/bin/env python3
from multiprocessing import Pool
import subprocess as sp
import os, time, random, sys, signal, shutil
import tempfile
from tqdm import tqdm
# from pwn import context, asm, disasm
import logging
import re
if len(sys.argv)<3:
    print("Usage: ./run_hybrid_all.py [GHIDRA RESULTs DIR] [TARGET] <LINUX_ROOT>")
GHIDRA_RESULT_DIR = os.path.abspath(sys.argv[1])
TARGET = os.path.abspath(sys.argv[2])
if len(sys.argv)>3:
    LINUX_ROOT = os.path.abspath(sys.argv[3])
else:
    LINUX_ROOT = None
CDIR = os.getcwd()

# UF_PATCHJMP=no UF_USEDRILLER=no UF_PATCHNOP=no
RESULT_DIR = "hybrid_all_output"
PROGRESS_BAR_DIR = '/tmp/progress_bar'
if os.getenv("UF_PATCHJMP") == "no" or os.getenv("UF_PATCHJMP") == "NO":
    RESULT_DIR += "_NOJMP"
    PROGRESS_BAR_DIR += "_NOJMP"
if os.getenv("UF_PATCHNOP") == "no" or os.getenv("UF_PATCHNOP") == "NO":
    RESULT_DIR += "_NONOP"
    PROGRESS_BAR_DIR += "_NONOP"
if os.getenv("UF_USEDRILLER") == "no" or os.getenv("UF_USEDRILLER") == "NO":
    RESULT_DIR += "_NODRILLER"
    PROGRESS_BAR_DIR += "_NODRILLER"

if not os.access(RESULT_DIR, os.F_OK):
    os.mkdir(RESULT_DIR)




def time_calc(t):
    fl = "%f" % t
    mi = int(t / 60)
    st = "%dm %fs" % (mi, t - mi * 60)
    return "%s(%s)" % (fl, st)

class cbranch_analysis():
    def __init__(self):
        self.cbranch_blockinfos = []
        self.movn_like_cbranch_infos = []
        self.parse_cbranch_blockinfos()
        self.state_str = 'initial state:\n'
        self.state_id = -1
        if os.access("all_state_summary",os.F_OK):
            shutil.rmtree("all_state_summary")
        os.mkdir("all_state_summary")
    def parse_cbranch_blockinfos(self):
        with open("workdir/cbranch_info",'r') as f:
            # this info should contains 4 parts each line: cbranch instr addr, cbranch block start addr, branch 1 block start addr, branch 2 block start addr
            cont = f.read().strip('\n').split('\n')
            for cb_info in cont:
                if len(cb_info)<=0:
                    continue
                if len(cb_info.split(' '))<=3:
                    cbranch_instr_addr, cbranch_block_addr, branch_addr = [int(_, 16) for _ in cb_info.split(' ') if len(_)>0]    
                    self.movn_like_cbranch_infos.append((cbranch_instr_addr, cbranch_instr_addr-4))
                    continue
                cbranch_instr_addr, cbranch_block_addr, branch1_addr, branch2_addr = [int(_, 16) for _ in cb_info.split(' ') if len(_)>0]
                if branch1_addr == cbranch_instr_addr or branch2_addr == cbranch_instr_addr:
                    if branch1_addr != cbranch_instr_addr:
                        self.movn_like_cbranch_infos.append((cbranch_instr_addr, branch1_addr))
                        continue
                    elif branch2_addr != cbranch_instr_addr:
                        self.movn_like_cbranch_infos.append((cbranch_instr_addr, branch2_addr))
                        continue
                prev_loc = cbranch_block_addr
                prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
                prev_loc &= 0xffff
                prev_loc = prev_loc >> 1
                cur_loc1 = branch1_addr
                cur_loc1 = (cur_loc1 >> 4) ^ (cur_loc1 << 8)
                cur_loc1 &= 0xffff
                cur_loc2 = branch2_addr
                cur_loc2 = (cur_loc2 >> 4) ^ (cur_loc2 << 8)
                cur_loc2 &= 0xffff

                AFL_branch1_loc = prev_loc ^ cur_loc1
                AFL_branch2_loc = prev_loc ^ cur_loc2
                self.cbranch_blockinfos.append((cbranch_instr_addr, AFL_branch1_loc, AFL_branch2_loc, branch1_addr, branch2_addr))
        # print("self.movn_like_cbranch_infos: %r"%self.movn_like_cbranch_infos)
        self.movn_like_iter_max = 2**len(self.movn_like_cbranch_infos)
        self.movn_like_iter_cnt = 0
        with open('workdir/cbranch_info_norm','w') as f:
            for cb_info in self.cbranch_blockinfos:
                f.write('0x%08x 0x%08x 0x%08x\n'%(cb_info[0], cb_info[3], cb_info[4]))
        with open('workdir/cbranch_info_movn','w') as f:
            for cb_info in self.movn_like_cbranch_infos:
                f.write('0x%08x 0x%08x\n'%(cb_info[0], cb_info[1]))
        

    def alter_patch_file(self, cb_instr_addr, target_br_addr, is_movn_like_instr, change_str = True):
        if change_str:
            self.state_str+=' 0x%08x' % cb_instr_addr
        sys.stdout.write("\033[44mtrying to change patch with addr 0x%08x jmp to 0x%08x, is_movn_like_instr %r\033[0m\n"%(cb_instr_addr, target_br_addr, is_movn_like_instr))
        with open('workdir/patch_','r') as f:
            cont = f.read().strip('\n').split('\n')
        cont_out = []
        for c in cont:
            # print("c: %r"%c)
            if len(c)<3:
                continue
            if '0x%08x'%cb_instr_addr not in c or 'nop' in c:
                cont_out.append(c)
            else:
                assert '0x0' in c or is_movn_like_instr, "any jmp cbranch patch not found in %s"%c
                addrs = re.findall("0x[0-9a-f]{8}",c)
                if len(addrs)>1 and int(addrs[1],0)==target_br_addr:
                    print('detect avoid address equals to target_br_addr, not alter')
                    cont_out.append(c)
                elif target_br_addr != 0:
                    cont_out.append(c.replace('0x0','0x%08x'%target_br_addr))
                else:
                    print("c: %r"%c)
                    cont_out.append(c.replace(addrs[1],'0x0'))
        with open('workdir/patch__','w') as f:
            f.write('\n'.join(cont_out))
            f.write('\n')
        # sys.stdout.write("\033[42malter_patch_file finished! diffing...\033[0m\n")
        p = sp.Popen("""
            diff workdir/patch_ workdir/patch__
            mv workdir/patch__ workdir/patch_
        """,shell=True)
        p.wait()

    def apply_patch_file(self, i):
        p = sp.Popen(""" 
            # diff workdir/patch_ workdir/patch__
            # mv workdir/patch__ workdir/patch_
            cp {TARGET} workdir/`basename {TARGET}` 
            export GHIDRA_DIR={GHIDRA_RESULT_DIR} 
            export TRACE_IDX={i} 
            export UF_TARGET=workdir/`basename {TARGET}`
            python3 scripts/binary_patch.py {TARGET}
        """.format(TARGET=TARGET, GHIDRA_RESULT_DIR=GHIDRA_RESULT_DIR, i=i), shell=True)
        p.wait()
    
    def do_cbranch_analysis(self, i):
        try:
            sys.stdout.write("\033[42mHybrid fuzzing finished.\033[0m\n")
            print("collecting hybrid fuzzing crash inputs...")
            r_dir, s_dir, crash_input_files = next(os.walk('afl_output/default/crashes'))
            if len(crash_input_files)>0:
                if 'README.txt' in crash_input_files:
                    crash_input_files.remove("README.txt")
                # if we have found at least one crash input, save current image state
                self.state_id += 1
                with open("all_state_summary/crash_summary",'a') as f:
                    f.write(str(self.state_id)+': '+self.state_str+'\n'+', '.join(crash_input_files)+'\n')
                os.mkdir("all_state_summary/%d"%self.state_id)
                for crash_input_file in crash_input_files:
                    shutil.copy(r_dir+'/'+crash_input_file, "all_state_summary/%d"%self.state_id)

            self.state_str='changing'
            print("detecting whether there are any cbranch that has no judge variation in fragment execution")
            with open("afl_output/default/fuzz_bitmap",'rb') as f:
                bitmap = f.read()
            assert len(bitmap)==0x10000, "AFL bitmap length not equals to 0x10000?"
            not_changed = True

            # try to alter movn and movz instructions to move and nop
            # FIXME: since we cannot determine whether the reg value suffice the condition, we will iterate through each possible branch direction state here, this could bring great efficiency loss
            # print("self.movn_like_cbranch_infos %r self.movn_like_iter_cnt %r self.movn_like_iter_max %r" % (self.movn_like_cbranch_infos,self.movn_like_iter_cnt,self.movn_like_iter_max))
            # FIXME: here we only consider 2 states: all patch to move or all patch to nop
            print("self.movn_like_iter_cnt 0x%x, self.movn_like_iter_max 0x%x self.movn_like_cbranch_infos %r"%(self.movn_like_iter_cnt, self.movn_like_iter_max, self.movn_like_cbranch_infos))
            if len(self.movn_like_cbranch_infos)>0 and self.movn_like_iter_cnt<self.movn_like_iter_max:
                not_changed = False
                for i,cb_info in enumerate(self.movn_like_cbranch_infos):
                    cbranch_instr_addr, branch_addr = cb_info
                    if self.movn_like_iter_cnt & (2**i) != 0:
                        self.alter_patch_file(cbranch_instr_addr, cbranch_instr_addr, is_movn_like_instr = True)
                    else:
                        self.alter_patch_file(cbranch_instr_addr, branch_addr, is_movn_like_instr = True)
                    if self.movn_like_iter_cnt == 0:
                        self.movn_like_iter_cnt = self.movn_like_iter_max-2
                    self.movn_like_iter_cnt += 1
            else:
                self.movn_like_iter_cnt = 0
                for cb_info in self.movn_like_cbranch_infos:
                    cbranch_instr_addr, branch_addr = cb_info
                    self.alter_patch_file(cbranch_instr_addr, 0, is_movn_like_instr = True, change_str = False)
                # print("self.cbranch_blockinfos %r" % self.cbranch_blockinfos)
                cb_blockinfo_remove = []
                for cb_info in self.cbranch_blockinfos:
                    # print("cb_info: ", cb_info)
                    cbranch_instr_addr, AFL_branch1_loc, AFL_branch2_loc, branch1_addr, branch2_addr = cb_info
                    # print("bitmap[AFL_branch1_loc] %r bitmap[AFL_branch2_loc] %r")
                    if bitmap[AFL_branch1_loc] == 255 and bitmap[AFL_branch2_loc] == 255:
                        print("cbranch @ 0x%08x has not executed yet, continue" % cbranch_instr_addr)
                        continue
                    elif bitmap[cb_info[1]] == 255:
                        # branch 1 has not executed yet
                        print("cbranch @ 0x%08x has not executed 0x%08x branch yet, change it to direct branch"%(cbranch_instr_addr, branch1_addr))
                        not_changed = False
                        cb_blockinfo_remove.append(cb_info)
                        self.alter_patch_file(cbranch_instr_addr, branch1_addr, is_movn_like_instr = False)
                    elif bitmap[cb_info[2]] == 255:
                        # branch 2 has not executed yet
                        print("cbranch @ 0x%08x has not executed 0x%08x branch yet, change it to direct branch"%(cbranch_instr_addr, branch2_addr))
                        not_changed = False
                        cb_blockinfo_remove.append(cb_info)
                        self.alter_patch_file(cbranch_instr_addr, branch2_addr, is_movn_like_instr = False)
                    else:
                        print("cbranch @ 0x%08x can run both branch in fuzzing, continue"%cbranch_instr_addr)
                self.cbranch_blockinfos = [i for i in self.cbranch_blockinfos if i not in cb_blockinfo_remove]
                if not not_changed:
                    self.apply_patch_file(i)
                if len(crash_input_files)>0:
                    os.rename("afl_output","afl_output_%d"%self.state_id)
                else:
                    shutil.rmtree("afl_output")
            return not_changed
        except Exception as e:
            sys.stdout.write("\033[41mdo_cbranch_analysis failed with %s\033[0m\n"%str(e))
            logging.exception("do_cbranch_analysis failed with %s"%str(e))
            return True
    
def worker(i,tmpdir,not_log_process=False):
    try:
        sys.stdout.write("\033[0;44msubprocess %i working on %s\033[0m\n"%(i,tmpdir))
        if not not_log_process:
            with open("%s_%s/%d-+-%d-%s"%(PROGRESS_BAR_DIR, os.path.basename(GHIDRA_RESULT_DIR), i, time.time(), os.path.basename(tmpdir)), 'w') as f:
                f.write('')
        os.chdir(CDIR)
        # STDERR = STDOUT = sp.DEVNULL
        # STDERR = STDOUT = sp.STDOUT
        
        p1 = sp.Popen("""
            make
            cp {cdir}/uf {tdir}/uf
            ln -s {cdir}/scripts {tdir}/scripts
            ln -s {cdir}/run.sh {tdir}/run.sh
        """.format(cdir=CDIR, tdir=tmpdir), shell=True)
        p1.wait()

        os.chdir(tmpdir) 
        
        appendcmd = ''
        if LINUX_ROOT!=None:
            appendcmd = """
                cp {cdir}/demo-libcpreload.so {tdir}/demo-libcpreload.so
            """.format(cdir=CDIR, tdir=tmpdir, linuxroot=LINUX_ROOT)
            os.environ['UF_PRELOAD']="{tdir}/demo-libcpreload.so".format(tdir=tmpdir)
            os.environ['UF_LIBPATH']="{linuxroot}/lib:{linuxroot}/usr/lib".format(linuxroot=LINUX_ROOT)
        p2 = sp.Popen(""" 
            rm -rf workdir; mkdir workdir
            cp {TARGET} {tdir}/workdir/`basename {TARGET}`
            cp {GHIDRA_RESULT_DIR}/connect_{i} {tdir}/workdir/connect 
            cp {GHIDRA_RESULT_DIR}/exec_{i} {tdir}/workdir/exec 
            cp {GHIDRA_RESULT_DIR}/patch_{i} {tdir}/workdir/patch_
            cp {GHIDRA_RESULT_DIR}/cbranch_info_{i} {tdir}/workdir/cbranch_info
            cp {GHIDRA_RESULT_DIR}/stack_retaddr_{i} {tdir}/workdir/stack_retaddr 
            cp {GHIDRA_RESULT_DIR}/call_checksum_{i} {tdir}/workdir/call_checksum
            cp {GHIDRA_RESULT_DIR}/calltrace_{i} {tdir}/workdir/calltrace
            cp {GHIDRA_RESULT_DIR}/dict_{i} {tdir}/workdir/dict
            cp {GHIDRA_RESULT_DIR}/sink_buf_{i} {tdir}/workdir/sink_buf
            cp {GHIDRA_RESULT_DIR}/xalloc_{i} {tdir}/workdir/xalloc
            export GHIDRA_DIR={GHIDRA_RESULT_DIR} 
            export TRACE_IDX={i} 
            export UF_TARGET={tdir}/workdir/`basename {TARGET}`
            {appendcmd}
            python3 scripts/binary_patch.py {TARGET}
        """.format(GHIDRA_RESULT_DIR=GHIDRA_RESULT_DIR, tdir=tmpdir, TARGET=TARGET, i=i, appendcmd=appendcmd), shell=True)
        p2.wait()

        cb_analysis = cbranch_analysis()

        start_time = time.time()
        while True:
            p3 = sp.Popen("timeout 86400 ./run.sh HYBRID_ALL {GHIDRA_RESULT_DIR} {i} {TARGET}".format(GHIDRA_RESULT_DIR=GHIDRA_RESULT_DIR, TARGET=TARGET, i=i), shell=True)#, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
            p3.wait()
            break
            # if cb_analysis.do_cbranch_analysis(i):
            #     break
        
        end_time = time.time()

        p4 = sp.Popen("echo \"%s\" > time_summary"%"time used: %s"%time_calc(end_time - start_time), shell=True)
        p4.wait()

        # 跑一下POC Analysis的汇总分析脚本
        p5 = sp.Popen("python3 scripts/gen_poc_result_summary.py", shell=True)
        p5.wait()
        
        print("%d finished"%i)
        if not not_log_process:
            with open("%s_%s/%d-*-%d-%s"%(PROGRESS_BAR_DIR, os.path.basename(GHIDRA_RESULT_DIR), i, time.time(), os.path.basename(tmpdir)), 'w') as f:
                f.write('')
        
        sys.stdout.write("\033[0;42msubprocess %i work done %s\033[0m\n"%(i,tmpdir))
        # p5 = sp.Popen("rkill %d ; rkill %d ; rkill %d ; rkill %d ; rkill %d"%(os.getpid(), p1.pid, p2.pid, p3.pid, p4.pid), shell=True)
        # p5.wait()
        # exit(0)
    except Exception as e:
        logging.exception("subprocess worker failed with %s"%str(e))



pool = Pool(8)

def sigint_handler(signalnum, handler):
    print("RECV SIGINT or SIGTERM or SIGKILL signal, stop all subprocesses")
    pool.terminate()
    exit(0)

def main():
    signal.signal(signal.SIGINT, sigint_handler)
    not_log_process = True if os.getenv('HYBRID_LOG') else False

    p0 = sp.Popen("rm -r /tmp/pwn-asm-* ; rm -r /tmp/pwn-disasm-*",shell=True)
    p0.wait()
    if os.access('/tmp/lock_pwntools.lock',os.F_OK):
        os.remove('/tmp/lock_pwntools.lock')
    if not os.access(os.getcwd()+'/%s'%RESULT_DIR,os.F_OK):
        os.mkdir(os.getcwd()+'/%s'%RESULT_DIR)

    if not not_log_process and os.access('%s_%s' % (PROGRESS_BAR_DIR, os.path.basename(GHIDRA_RESULT_DIR)), os.F_OK):
        shutil.rmtree('%s_%s' % (PROGRESS_BAR_DIR, os.path.basename(GHIDRA_RESULT_DIR)), ignore_errors=True)
    if not not_log_process:
        os.mkdir('%s_%s' % (PROGRESS_BAR_DIR, os.path.basename(GHIDRA_RESULT_DIR)))

    trace_cnt=0
    while os.access("%s/exec_%d"%(GHIDRA_RESULT_DIR, trace_cnt),os.F_OK):
        trace_cnt+=1
    if not not_log_process:
        for i in range(trace_cnt):
            with open("%s_%s/%d--"%(PROGRESS_BAR_DIR, os.path.basename(GHIDRA_RESULT_DIR), i), 'w') as f:
                f.write('')

    if not not_log_process:
        if os.getenv("UF_LOGUNEXP_CRASH"):
            os.system("tmux split -h \"UF_LOGUNEXP_CRASH=%s python3 progress_bar.py %s %d %s %s; sleep 5\""%(os.getenv("UF_LOGUNEXP_CRASH"), os.path.basename(GHIDRA_RESULT_DIR), trace_cnt, RESULT_DIR, PROGRESS_BAR_DIR))
        else:
            os.system("tmux split -h \"python3 progress_bar.py %s %d %s %s; sleep 5\""%(os.path.basename(GHIDRA_RESULT_DIR), trace_cnt, RESULT_DIR, PROGRESS_BAR_DIR))

    subprocess_dirs = []
    sys.stdout.write("\033[0;42m----start----\033[0m\n")

    
    for i in range(trace_cnt):
    # for i in [41]:
        tmpdir = os.getcwd()+'/%s/'%RESULT_DIR+os.path.basename(TARGET)+"_%d"%i
        if os.access(tmpdir, os.F_OK):
            shutil.rmtree(tmpdir)
        os.mkdir(tmpdir)
        subprocess_dirs.append(tmpdir)
        pool.apply_async(worker,args=(i,tmpdir,not_log_process))
        
    pool.close()  # 关闭进程池，关闭后po不再接收新的请求
    pool.join()  # 等待po中所有子进程执行完成，再执行下面的代码,可以设置超时时间join(timeout=)

    sys.stdout.write("\033[0;42m-----hybrid done------\033[0m\n")
    sys.stdout.write("\033[0;42m-----summary-----\033[0m\n")
    for i in range(len(subprocess_dirs)):
        print("id: %d, subprocess workdir %s"%(i, subprocess_dirs[i]))
        if os.access("%s/all_state_summary/crash_summary"%subprocess_dirs[i], os.F_OK): 
            print("Found crash input, see %s for more info"%("%s/all_state_summary/crash_summary"%subprocess_dirs[i]))
        else:
            print("Not found any crash input")
        os.system("cat %s/time_summary"%subprocess_dirs[i])

if __name__=='__main__':
    main()
