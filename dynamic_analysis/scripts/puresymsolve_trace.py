import subprocess as sp
import os, time
from pure_symsolve_utils import TARGET_BIN, HYBRID_ALL_OUTPUT_DIR
_, dirs, __ = next(os.walk(HYBRID_ALL_OUTPUT_DIR))
cwd = os.getcwd()
TIMEOUT = 10
def find(d):
    for tb in TARGET_BIN:
        if tb in d:
            return tb
    return None

TARGET_BIN_VULNCNT = {}
for tb in TARGET_BIN:
    TARGET_BIN_VULNCNT[tb] = 0
TARGET_BIN_VULNDETAIL = {}
for tb in TARGET_BIN:
    TARGET_BIN_VULNDETAIL[tb] = ''

for idx in range(len(dirs)):
    d = dirs[idx]
    tb = find(d)
    if tb == None:
        continue
    binpath = sp.Popen('find /root/evaluation_set -name "%s"'%tb, shell=True, stdout=sp.PIPE).stdout.read().decode().strip()
    tmpdir = cwd+'/'+HYBRID_ALL_OUTPUT_DIR+'/'+d 
    print('tmpdir: %s' % tmpdir)
    os.chdir(tmpdir)
    with open('workdir/exec', 'r') as f:
        exec_content = f.read().split('\n')
        source = exec_content[3]
        sinks = exec_content[7].split(' ') + exec_content[9].split(' ')
        sinks = [i for i in sinks if len(i)>0]
    if len(sinks)<=0:
        continue
    sinks_hit = {}
    for s in sinks:
        sinks_hit[s] = False
    if not os.access('workdir/pure_symsolve/crash_output', os.F_OK):
        continue
    _, __, syminputs = next(os.walk('workdir/pure_symsolve/crash_output'))
    for syminput in syminputs:
        print(syminputs)
        find_crash = False
        for i in range(32):
            p_start_time = time.time()
            p = sp.Popen('UF_TARGET="%s" ./uf < workdir/pure_symsolve/crash_output/%s' % (binpath, syminput), shell=True, stdout=sp.DEVNULL, stderr=sp.PIPE)
            output = b''
            while p.poll() is None:
                output += p.stderr.read()
                time.sleep(0.1)
                if time.time() - p_start_time > TIMEOUT:
                    print("Failed to execute subprocess in given time")
                    p.terminate()
                    os.system("kill -9 %d"%p.pid)
                    continue
            if p.poll()==0:
                continue
            find_crash = True
            if b'overflow at' in output:
                crash_addr_start = output.find(b'overflow at') + len(b'overflow at ')
                crash_addr_end = output.find(b'\n', crash_addr_start)
                crash_addr = output[crash_addr_start: crash_addr_end].decode()
                # assert crash_addr in sinks_hit
                if crash_addr in sinks_hit and sinks_hit[crash_addr] == False:
                    sinks_hit[crash_addr] = True
                    TARGET_BIN_VULNDETAIL[tb] += """source addr: %s -> sink addr: %s with input %s\n"""%(source, crash_addr, syminput)
                    break
        if not find_crash:
            print("Failed to trigger crash with given syminput")
    print('sinks_hit:',sinks_hit)
    TARGET_BIN_VULNCNT[tb] += len([addr for addr in sinks_hit if sinks_hit[addr]==True])

os.chdir(cwd)

for tb in TARGET_BIN:
    print("TARGET_BIN:")
    print(tb)
    print("TARGET_BIN_VULNCNT:")
    print(TARGET_BIN_VULNCNT[tb])
    print("TARGET_BIN_VULNDETAIL:")
    print(TARGET_BIN_VULNDETAIL[tb])

with open('symsolve_traceresult.txt','w') as f:
    for tb in TARGET_BIN:
        f.write("TARGET_BIN:\n")
        f.write(str(tb)+'\n')
        f.write("TARGET_BIN_VULNCNT:\n")
        f.write(str(TARGET_BIN_VULNCNT[tb])+'\n')
        f.write("TARGET_BIN_VULNDETAIL:\n")
        f.write(str(TARGET_BIN_VULNDETAIL[tb])+'\n')