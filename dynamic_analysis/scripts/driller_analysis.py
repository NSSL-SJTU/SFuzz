import driller_core
import random, string, subprocess
from utils import conv_regs, UF_Logging, Patch, Free_Memory_Manager
import time
import sys, os
import pwn
from threading import Timer
# driller.l.setLevel(1)

start_time = time.time()
one_time = None
end_time = None

log = UF_Logging(__name__)

ARCH = None
ENDIAN = None
TARGET = os.environ['UF_TARGET']
BASE_ADDR = None
START_ADDR = None
TARGET_END_ADDR = None
INJECT_ADDR = None
INJECT_IDX = None
OS = None
EXEC_END_ADDR = None
LIBPATH = None
# FUZZ_INPUT = sys.argv[1]
# FUZZ_BITMAP = open(sys.argv[2],'rb').read() if len(sys.argv)>2 else None

def quit_drilling():
    log.info("quit drilling because of time out")
    exit(0)

class Driller_analysis(object):
    # def __init__(self, binary, start_addr, end_addr, args, input_idx, libpath, inputfile, fuzz_bitmap, arch, libdirs):
    def __init__(self, binary, start_addr, inject_addr, end_addr, inject_idx, os, exec_end_addr, arch, endian, fuzz_input, fuzz_bitmap, **kargs):
        '''
        Initially we define input as following form:
        vuln(arg0, arg1, arg2, ...) which we mutate and fuzz only one of them, start addr is start of vuln() and end addr is the return address of vuln(instead of the ret instr of vuln()!)
        the args is a list here
        '''
        self.binary = binary
        self.start_addr = start_addr
        self.inject_addr = inject_addr
        self.end_addr = end_addr
        self.inject_idx = inject_idx
        self.os = os
        self.fuzz_input = fuzz_input
        self.fuzz_bitmap = fuzz_bitmap
        self.exec_end_addr = exec_end_addr

        if arch=='mips' and endian=='little':
            self.angr_arch = 'mipsel'
        elif arch=='mips':
            self.angr_arch = 'mipseb'
        elif arch=='arm' and endian=='little':
            self.angr_arch = 'armel'
        elif arch=='mips':
            self.angr_arch = 'armeb'

        pwn.context.arch=arch
        pwn.context.endian=endian
        NOP = pwn.asm("NOP")

        if os == 'linux':
            self.libdirs = kargs["libdirs"]
            # need re-implemented
            # self.d = driller_core.Driller(binary, start_addr, end_addr, args, input_idx, libpath, inputfile, fuzz_bitmap)
        elif os == 'rtos':
            self.base_addr = kargs["base_addr"]
            self.d = driller_core.Driller(binary, start_addr, inject_addr, end_addr, inject_idx, os, exec_end_addr, arch, self.angr_arch, fuzz_input, fuzz_bitmap, NOP, base_addr = self.base_addr)
        
        self.timer = Timer(10*60, quit_drilling)

    def drill(self):
        '''
        Driller main logic goes here
        '''
        self.drill_result = self.d.drill()
        self.clean_input = set(i[1] for i in self.drill_result)
        return self.drill_result
        
    def apply_new_input(self):
        '''
        Write new corpus to input seeds
        ''' 
        for afl_input in self.clean_input:
            input_file_name="".join(random.choice(string.ascii_letters+string.digits) for i in range(8))    
            with open('./afl_driller/driller-%s'%input_file_name,'wb') as f:
                f.write(afl_input)


def parse_exec_info():
    global ARCH, ENDIAN, BASE_ADDR, START_ADDR, TARGET_END_ADDR, INJECT_ADDR, INJECT_IDX, OS, EXEC_END_ADDR, LIBPATH
    try:
        with open("workdir/exec",'r') as f:
            exec_info = f.read().strip('\n').split('\n')
        BASE_ADDR = int(exec_info[0], 0)
        ARCH = 'arm' if 'arm' in exec_info[1] else 'mips'
        ENDIAN = 'little' if 'el' in exec_info[1] or 'le' in exec_info[1] else 'big'
        START_ADDR = int(exec_info[2], 0)
        INJECT_ADDR = int(exec_info[3], 0)
        INJECT_IDX = int(exec_info[4], 0)
        TARGET_END_ADDR = [int(i, 0) for i in exec_info[6].split(' ')] if len(exec_info[6])>0 else []
        FUZZ_END_ADDR = [int(i, 0) for i in exec_info[7].split(' ')] if len(exec_info[7])>0 else []
        TARGET_END_ADDR += [int(i, 0) for i in exec_info[8].split(' ')] if len(exec_info[8])>0 else []
        FUZZ_END_ADDR += [int(i, 0) for i in exec_info[9].split(' ')] if len(exec_info[9])>0 else []
        OS = exec_info[10]
        if len(exec_info)>11:
            EXEC_END_ADDR = [int(i, 0) for i in exec_info[11].split(',')] if len(exec_info[11])>0 else []
        else:
            EXEC_END_ADDR = []
        
    except Exception as e:
        log.error("Parse exec info errored with %s"%str(e))

def clean_driller_output(apply_afl_tmin=False, apply_afl_cmin=False):
    if apply_afl_cmin:
        os.system("cp afl_output/default/queue/* afl_driller/")
        os.system("UF_TARGET=%s UF_TRACE=no afl-cmin -U -i afl_driller -o afl_driller_cmin ./uf" % TARGET)
    else:
        os.system("cp afl_output/default/queue/* afl_driller/")
        os.system("mkdir afl_driller_cmin/")
        os.system("cp afl_driller/* afl_driller_cmin/")

    if apply_afl_tmin:
        for file in next(os.walk("afl_driller_cmin"))[2]:
            os.system("UF_TARGET=%s UF_TRACE=no afl-tmin -U -i afl_driller_cmin/%s -o afl_driller_cmin/%s ./uf" % (TARGET, file, file))

driller = None

def main():
    global driller
    
    log.info("driller_analysis begin")

    parse_exec_info()

    if os.access("afl_output/default/fuzz_bitmap", os.F_OK):
        FUZZ_BITMAP = open("afl_output/default/fuzz_bitmap",'rb').read()
    else:
        FUZZ_BITMAP = None

    os.system("rm -rf afl_driller afl_driller_cmin; mkdir afl_driller ;")

    if OS == 'rtos':
        for queue_input in next(os.walk('afl_output/default/queue'))[2]:
            FUZZ_INPUT = 'afl_output/default/queue/'+queue_input
            driller = Driller_analysis(TARGET, START_ADDR, INJECT_ADDR, TARGET_END_ADDR, INJECT_IDX, OS, EXEC_END_ADDR, ARCH, ENDIAN, FUZZ_INPUT, FUZZ_BITMAP, base_addr = BASE_ADDR)
            driller.drill()
            driller.apply_new_input()
            # break
    elif OS == 'linux':
        for queue_input in next(os.walk('afl_output/default/queue'))[2]:
            FUZZ_INPUT = 'afl_output/default/queue/'+queue_input
            driller = Driller_analysis(TARGET, START_ADDR, INJECT_ADDR, TARGET_END_ADDR, INJECT_IDX, OS, EXEC_END_ADDR, ARCH, ENDIAN, FUZZ_INPUT, FUZZ_BITMAP, libpath = LIBPATH)
            driller.drill()
            driller.apply_new_input()
            # break

    # cmin: input directory
    # tmin: one input
    clean_driller_output(apply_afl_tmin=False, apply_afl_cmin=False)
    
def shutdown():
    global driller
    log.info("Time limit reached, we have some findings, stop symbolic solving")
    try:
        log.info("try to dump new input")
        driller.apply_new_input()
    except:
        log.info("failed to dump new input")
    os._exit(0)

if __name__ == '__main__':
    timer = Timer(20*60, shutdown, args=())
    timer.start()
    try:
        main()
    except Exception as e:
        raise e
    timer.cancel()