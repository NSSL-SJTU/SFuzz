import time,random
import os, re, sys

wait_time = 0
while True:
    try:
        os.open('/tmp/lock_pwntools.lock',os.O_CREAT|os.O_RDWR|os.O_EXCL)
        from pwn import context, asm, p16, disasm, u16, p32, u32
        os.remove('/tmp/lock_pwntools.lock')
        break
    except:
        print("another process is initializing pwntools, waiting...")
        time.sleep(random.random()*20+3)
        wait_time += 1
        if wait_time > 10:
            try:
                os.remove('/tmp/lock_pwntools.lock')
            except:
                pass
import binascii

# if not os.access(sys.argv[1], os.F_OK):
#     print("Unable to read image %r" % os.environ['UF_TARGET'])
with open(sys.argv[1], 'rb') as f:
    orin_binary = f.read()

with open("workdir/exec", 'r') as f:
    exec_info=f.read().strip('\n').split('\n')
ARCH=exec_info[1][:-2]
ENDIAN='little' if 'le' in exec_info[1][-2:] or 'el' in exec_info[1][-2:] else 'big'
# TARGET=os.environ['UF_TARGET']
LOAD_BASE=int(exec_info[0], 0)
context.arch=ARCH
context.endian=ENDIAN
NOP=asm("nop")
# if ARCH == 'mips':
#     NOP = b'\0\0\0\0'
# elif ARCH == 'arm':
#     if ENDIAN == 'little':
#         NOP = b'\x00\xf0 \xe3'
#     elif ENDIAN == 'big':
#         NOP = b'\xe3 \xf0\x00'

'''
the patch_ file shoule follow the rules:
for nop:
    <addr> nop <poc follow> <arg count>
        addr: nop address
        nop: patch type
        poc follow: get in subfunc in poc analysis(0 for not follow while 1 for follow)
        arg count: args passing to this subfunc
    example:
        0x800d88bc nop 1 2

for jmp:
    <addr> jmp <target branch> <avoid branch>
        addr: jmp address
        jmp: patch type
        target branch: branch set jump to this branch, if it set to 0, it means a random jump
        avoid branch: branch that shoule avoid(since it cannot get to sink address)
    example:
        0x800c8470 jmp 0x0: branch at 0x800c8470 should set to random jump
        0x800c897c jmp 0x0 0x800c89a4: branch at 0x800c897c should set to random jump, and 0x800c89a4 should avoid
        0x800d89cc jmp 0x800d89d4 0x800d8a88: branch at 0x800c897c should set to jumping towards 0x800d89d4, and 0x800d8a88 should avoid
'''

with open("workdir/patch_","r") as f:
    patches = [patch.split(' ') for patch in set(f.read().strip('\n').split('\n')) if len(patch)>3]

class_nop_info = []
class_jmp_info = []

for patch in patches:
    try:
        if patch[1] == 'nop':
            if int(patch[0], 0) not in [cni[0] for cni in class_nop_info]:
                if len(patch)==3:
                    class_nop_info.append((int(patch[0], 0), int(patch[2], 0),             None ))
                elif len(patch)==4:
                    class_nop_info.append((int(patch[0], 0), int(patch[2], 0), int(patch[3], 0) ))
        elif patch[1] == 'jmp':
            if int(patch[0], 0) not in [cji[0] for cji in class_jmp_info]:
                target_branch = int(patch[2],0)
                # info = (instr_addr, target_branch_addr - instr_addr, avoid_addr)
                if target_branch == 0:
                    # condition jump is input-data-related
                    if len(patch)>3 and len(patch[3])>2:
                        # if has avoid addr
                        info = (int(patch[0], 0), None, int(patch[3], 0))
                        class_jmp_info.append(info)
                    else:
                        info = (int(patch[0], 0), None, None)
                        class_jmp_info.append(info)
                else:
                    # condition jump is not input-data-related
                    if len(patch)>3 and len(patch[3])>2:
                        # if has avoid addr
                        info = (int(patch[0], 0), int(patch[2], 0) - int(patch[0],0), int(patch[3], 0))
                        class_jmp_info.append(info)
                    else:
                        info = (int(patch[0], 0), int(patch[2], 0) - int(patch[0],0), None)
                        class_jmp_info.append(info)
    except Exception as e:
        print("Parsing %s error with %s"%(patch, str(e)))

# Each element in class_jmp_info follow following def:
# (patch addr, direct jmp offset if not None, avoid addr if not None)

# print("class_nop_info: %r"%class_nop_info)
# print("class_jmp_info: %r"%class_jmp_info)
# print("%r"%([i for i in class_jmp_info if i[0]==0x800d8940]))
# print("class_jmp_info with avoid addr: %r"%[i for i in class_jmp_info if i[2]!=None])
# print("avoid addr set: %r"%set([hex(j[2]) for j in [i for i in class_jmp_info if i[2]!=None]]))

with open("workdir/patch",'wb') as f:
    if os.getenv('UF_PATCHNOP') and (os.getenv('UF_PATCHNOP')=='no' or os.getenv('UF_PATCHNOP')=='NO'):
        print("Pass nop patch due to UF_PATCHNOP set to %s"%os.getenv('UF_PATCHNOP'))
    else:
        # follow the (addr, should follow flag) format
        # print("class_nop_info",class_nop_info)
        for info in class_nop_info:
            f.write(b"%s %d "%(hex(info[0]).encode('utf8'), len(NOP))+binascii.hexlify(NOP))
            f.write(b' ' + str(info[1]).encode('utf8'))
            if info[2]:
                f.write(b' ' + str(info[2]).encode('utf8'))
            f.write(b'\n')
    
    if os.getenv('UF_PATCHJMP') and (os.getenv('UF_PATCHJMP')=='no' or os.getenv('UF_PATCHJMP')=='NO'):
        print("Pass jmp patch due to UF_PATCHJMP set to %s"%os.getenv('UF_PATCHJMP')) 
    else:
        # follow the (addr, target branch offset, avoid excution/exit emulation addr) format
        # print("class_jmp_info:",class_jmp_info)
        for info in class_jmp_info:
            # print("jmp info: {} {} {}".format(hex(info[0]) if info[0] else None, hex(info[1]) if info[1] else None, hex(info[2]) if info[2] else None))
            # if info[1] == None:
            #     # no need to patch
            #     continue
            if ARCH=='mips':
                orig_bytes = orin_binary[info[0]-LOAD_BASE:info[0]+4-LOAD_BASE]
                orig_instr = disasm(orig_bytes)
                # print("orig_instr @ 0x%08x: %s"%(info[0], orig_instr))
                orig_instr = (orig_instr.split(' '*8)[1]).split(' ')
                # deal with movn and movz
                if 'movn' in orig_instr[0] or 'movz' in orig_instr[0]: 
                    # for instructions like movn, if targetaddr equals itself, change it to move, or just nop it
                    print("info for movn/movz: ",info)
                    if info[1]==0:
                        bnum = u32(orig_bytes)
                        code = p32((bnum & (2**32-1 ^ 0b111111) | 0b100001) & (2**32-1 ^ 0x3e0000 ) )
                    elif info[1]!=None:
                        code = NOP
                    else:
                        code = b''
                else:
                    # use b instead of j to indirect jump with pc
                    if info[1]==None:
                        code=b''
                    elif info[1]>=4:
                        code=p16((info[1]-4)//4)+b'\x00\x10'
                    elif info[1]<0:
                        code=p16(2**16-1+(info[1])//4)+b'\x00\x10'
                    else: # info[1]>=0 and info[1]<4, same address
                        code=b''
                    if ENDIAN == 'big':
                        code=code[::-1]
                    if re.match("^b[a-z].+l",orig_instr[0]) and ((info[1]!=int(orig_instr[-1],0) and info[1]!=0) or info[1]==8) and info[1]:
                        # if target branch not equal to instr target branch, delay slot will not get executed
                        print("Found branch-likely instr")
                        code += NOP
                avoid = info[2]
            elif ARCH=='arm': 
                if info[1]==None:
                    code=b''
                elif info[1]>=8:
                    code = p32((info[1]-8)//4)[:-1]+b'\xEA'
                elif info[1]<0 or info[1]>=4:
                    code = p32(2**32+(info[1]-8)//4)[:-1]+b'\xEA'
                elif info[1]<4:
                    code = b''
                if ENDIAN == 'big':
                    code = code[::-1]
                avoid = info[2]
            # elif ARCH=='i386':
            #     code=asm("jmp $+"%info[1])

            avoid = 0 if avoid==None else avoid
            f.write(b"%s %d "%(hex(info[0]).encode('utf8'), len(code)) + binascii.hexlify(code) + b' ' + hex(avoid).encode() + b'\n')

