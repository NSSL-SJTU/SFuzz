import sys, time, binascii, claripy, os, angr
import logging
l=logging.getLogger(__name__)
l.setLevel(logging.INFO)


reg_mips = {'pc':'pc','sp':'sp','lr':'ra','a0':'a0','a1':'a1','a2':'a2','a3':'a3','rv':'v0','syscall':'v0','bp':'fp'}
reg_arm = {'pc':'pc','sp':'sp','lr':'lr','a0':'r0','a1':'r1','a2':'r2','a3':'r3','rv':'r0','syscall':'r7','bp':'r11'}
reg_x86 = {'pc':'eip','sp':'esp','lr':0,'a0':'ebx','a1':'ecx','a2':'edx','a3':'esi','rv':'eax','syscall':'eax','bp':'ebp'}
conv_regs = {'mips':reg_mips, 'arm':reg_arm, "x86":reg_x86}
global_symbol_idx = 0
all_added_retval_sim = {}
specific_sim = None
class UF_Logging():
    def __init__(self, name):
        self.loglevel=0
        self.DEBUG=0
        self.INFO=1
        self.CRITICAL=2

        self.name = name
        self.info_color = '\033[0;32m%s\033[0m' #1
        self.debug_color = '\033[0;34m%s\033[0m' #0
        self.error_color = '\033[0;34m%s\033[0m' #2
        self.success_color = '\033[0;42m%s\033[0m' #2
    def info(self, content):
        if self.loglevel <= self.INFO:
            sys.stderr.write(self.info_color % "INFO")
            sys.stderr.write(' | '+time.ctime()+' | '+self.name+' | ')
            sys.stderr.write(self.info_color % str(content))
            sys.stderr.write('\n')
    def debug(self, content):
        if self.loglevel <= self.DEBUG:
            sys.stderr.write(self.debug_color % "DEBUG")
            sys.stderr.write(' | '+time.ctime()+' | '+self.name+' | ')
            sys.stderr.write(self.debug_color % str(content))
            sys.stderr.write('\n')
    def error(self, content):
        if self.loglevel <= self.CRITICAL:
            sys.stderr.write(self.error_color % "ERROR")
            sys.stderr.write(' | '+time.ctime()+' | '+self.name+' | ')
            sys.stderr.write(self.error_color % str(content))
            sys.stderr.write('\n')
            os._exit(-1)
    def success(self, content):
        if self.loglevel <= self.CRITICAL:
            sys.stderr.write(self.success_color % "SUCCESS")
            sys.stderr.write(' | '+time.ctime()+' | '+self.name+' | ')
            sys.stderr.write(self.success_color % str(content))
            sys.stderr.write('\n')
    def setlevel(self, level):
        if level<=self.CRITICAL:
            self.loglevel = level

patch_all = set()


class Patch():
    def get_bbl_addr(self, addr, angr_project):
        # Since we have problem in angr CFG analysis, we use following basic ways to find block address
        # Remember in 32bit MIPS and ARM arch instrs are mostly 4 bytes long

        # FIXME: this could bring problem, like:
        # ROM:800C83C8 158                 addiu   $t8, $s3, (a73420+8 - 0x802E0000)  # "0"
        # ROM:800C83CC 158                 bnez    $v0, loc_800C83E0  # Branch on Not Zero
        # ROM:800C83D0 158                 sw      $t8, 0x130+var_10($sp)  # Store Word
        # ROM:800C83D4 158                 la      $t8, aActualLengthSi+0x28  # "1"
        # ROM:800C83DC 158                 sw      $t8, 0x130+var_10($sp)  # Store Word
        # ROM:800C83E0
        # ROM:800C83E0     loc_800C83E0:                            # CODE XREF: sub_800C82F8+D4↑j
        # ROM:800C83E0 158                 lui     $s5, 0x802C      # Load Upper Immediate
        # ROM:800C83E4 158                 lui     $a2, 0x802E      # Load Upper Immed  iate
        # ROM:800C83E8 158                 addiu   $a3, $s5, (aD02fs+0xC - 0x802C0000)  # ""
        # if we give addr = 0x800C83E8 it will return 0x800C83D0 instead of 0x800C83E0 since it can't find the split of block because of the condition jump without CFG analysis

        block = angr_project.factory.block(addr)
        block_end_addr = block.addr + block.size
        try_idx = 1
        while try_idx<2000: # find at most 2000 instrs upwards
            block = angr_project.factory.block(addr - try_idx*4)
            if block_end_addr != block.addr + block_size:
                return block.addr + 4
            try_idx += 1
        print("get_bbl_addr: Unable to find block addr, instr addr: 0x%08x", addr)
        return -1

    

    def add_subfunc_call_hook(self, angr_project):
        # Remember in 32bit MIPS and ARM arch instrs are mostly 4 bytes long
        def subfunc_call(state):
            main_obj = angr_project.loader.all_objects[0]
            angr_project.factory.cc().get_args(state, is_fp=self.argcount)
            l.debug('add_subfunc_call_hook: state %r recent_actions: %s'%(state, str(state.history.recent_actions)))
            for ra in state.history.recent_actions:
                if type(ra) == angr.state_plugins.sim_action.SimActionData and ra.action == 'read' and 'pc' not in str(ra) and 'reg' in str(ra):
                    if ra.data.args[1] == None:
                        continue
                    if type(ra.data.args[0]) != int:
                        cond = (ra.data.args[0] < main_obj.min_addr).is_true() or (ra.data.args[0] > main_obj.max_addr).is_true()
                        if (not (ra.data.args[0] < main_obj.min_addr).is_true()) and (not (ra.data.args[0] > main_obj.max_addr).is_false()):
                            # if the symbolic expression can't be judged
                            cond = True
                    else:
                        cond = ra.data.args[0] < main_obj.min_addr or ra.data.args[0] > main_obj.max_addr
                    if cond and 'crash_input' not in str(ra.data) and 'crash_input' not in str(state.memory.load(ra.data,4)):
                        if type(ra.data.args[1]) != int:
                            try:
                                prepared_sym = claripy.BVS('subfunc_mem_sim_0x%08x'%state.addr, ra.data.args[1])
                                state.memory.store(ra.data.args[0], prepared_sym, ra.data.args[1]/8)
                            except:
                                prepared_sym = claripy.BVS('subfunc_mem_sim_0x%08x'%state.addr, 32)
                                state.memory.store(ra.data.args[0], prepared_sym, 4)
                        else:
                            prepared_sym = claripy.BVS('subfunc_mem_sim_0x%08x'%state.addr, ra.data.args[1])
                            state.memory.store(ra.data.args[0], prepared_sym, ra.data.args[1]//8)
                    else:
                        pass
                        # prepared_sym = claripy.BVS('mem', 32)
                        # state.memory.store(ra.data.args[0], prepared_sym, 4)
            
            # reaching our subfuntion call that intending to pass, add a symbolic return value and record it in current state
            # since our self-defined properties of state cannot perserve
            global global_symbol_idx
            if self.arch == 'mips':
                l.debug("add symbolized return value at 0x%08x"%(state.addr-4))
                subfunc_retval_sim = claripy.BVS("subfunc_retval_sim_0x%08x_%d"%(state.addr-4, global_symbol_idx), 32)
                all_added_retval_sim["subfunc_retval_sim_0x%08x_%d"%(state.addr-4, global_symbol_idx)] = subfunc_retval_sim
            else:
                l.debug("add symbolized return value at 0x%08x"%(state.addr-4))
                subfunc_retval_sim = claripy.BVS("subfunc_retval_sim_0x%08x_%d"%(state.addr-4, global_symbol_idx), 32)
                all_added_retval_sim["subfunc_retval_sim_0x%08x_%d"%(state.addr, global_symbol_idx)] = subfunc_retval_sim
            global_symbol_idx += 1
            setattr(state.regs, conv_regs[self.arch]['rv'], subfunc_retval_sim)
            # print("cpeggggg000 %r"%state, state.memory.load(subfunc_retval_sim, 4))

        def undrop(state):
            l.debug("state %r reach undrop"%state)
            state.globals['undrop']=True
            state.globals['undrop_setaddr'] = state.addr
        # IMPORTANT: 如果仅需要统计依赖于哪些函数，这里选择if True即可，进行可选择性patch可以对一些函数返回值被子函数调用的情况进行符号进一步求解
        if self.bypass_in_poc == 0: # whether get into some subfunc call?
        # if True:
            if self.arch=='mips':
                print("Adding hook at 0x%08x, arch: %s" % (self.addr, self.arch))
                delay_slot_instr = angr_project.loader.memory.load(self.addr+4, 4)
                angr_project.loader.memory.store(self.addr, delay_slot_instr)
                angr_project.hook(addr=self.addr+4, hook=subfunc_call, length=4, replace=True) # hook call instr and jump pass it
            else:
                print("Adding hook at 0x%08x, arch: %s" % (self.addr, self.arch))
                angr_project.hook(addr=self.addr, hook=subfunc_call, length=4, replace=True) # hook call instr and jump pass it
        elif self.bypass_in_poc == 1:
            print("Adding undrop hook at 0x%08x, arch: %s" % (self.addr, self.arch))
            angr_project.hook(addr=self.addr, hook=undrop, length=0, replace=True) # hook call instr and jump pass it

    def add_subfunc_call_hook_in_reexec(self, angr_project, constrain):
        global specific_sim
        for constrain_name in all_added_retval_sim:
            if constrain_name in str(constrain):
                specific_sim = all_added_retval_sim[constrain_name]
                break
        def subfunc_call_reexec(state):
            global specific_sim
            main_obj = angr_project.loader.all_objects[0]
            angr_project.factory.cc().get_args(state, is_fp=self.argcount)
            l.debug('subfunc_call_reexec: state %r recent_actions: %s'%(state, str(state.history.recent_actions)))
            for ra in state.history.recent_actions:
                if type(ra) == angr.state_plugins.sim_action.SimActionData and ra.action == 'read' and 'pc' not in str(ra) and 'reg' in str(ra):
                    if ra.data.args[1] == None:
                        continue
                    if type(ra.data.args[0]) != int:
                        cond = (ra.data.args[0] < main_obj.min_addr).is_true() or (ra.data.args[0] > main_obj.max_addr).is_true()
                        if (not (ra.data.args[0] < main_obj.min_addr).is_true()) and (not (ra.data.args[0] > main_obj.max_addr).is_false()):
                            # if the symbolic expression can't be judged
                            cond = True
                    else:
                        cond = ra.data.args[0] < main_obj.min_addr or ra.data.args[0] > main_obj.max_addr
                    if cond and 'crash_input' not in str(ra.data) and 'crash_input' not in str(state.memory.load(ra.data,4)):
                        if type(ra.data.args[1]) != int:
                            try:
                                prepared_sym = claripy.BVS('subfunc_mem_sim_0x%08x'%state.addr, ra.data.args[1])
                                state.memory.store(ra.data.args[0], prepared_sym, ra.data.args[1]/8)
                            except:
                                prepared_sym = claripy.BVS('subfunc_mem_sim_0x%08x'%state.addr, 32)
                                state.memory.store(ra.data.args[0], prepared_sym, 4)
                        else:
                            prepared_sym = claripy.BVS('subfunc_mem_sim_0x%08x'%state.addr, ra.data.args[1])
                            state.memory.store(ra.data.args[0], prepared_sym, ra.data.args[1]//8)
                    else:
                        pass
                        # prepared_sym = claripy.BVS('mem', 32)
                        # state.memory.store(ra.data.args[0], prepared_sym, 4)
            
            if self.arch == 'mips':
                l.debug("add symbolized reexec return value at 0x%08x"%(state.addr-4))
            else:
                l.debug("add symbolized reexec return value at 0x%08x"%(state.addr-4))
            subfunc_retval_sim = specific_sim
            setattr(state.regs, conv_regs[self.arch]['rv'], subfunc_retval_sim)

        if self.arch=='mips':
            print("Adding reexec hook at 0x%08x, arch: %s" % (self.addr, self.arch))
            angr_project.hook(addr=self.addr+4, hook=subfunc_call_reexec, length=4, replace=True) # hook call instr and jump pass it
        else:
            print("Adding reexec hook at 0x%08x, arch: %s" % (self.addr, self.arch))
            angr_project.hook(addr=self.addr, hook=subfunc_call_reexec, length=4, replace=True) # hook call instr and jump pass it

    def __init__(self, addr, leng, content, append_info1, append_info2, angr_project, NOP):
        global patch_all
        self.addr = addr
        self.len = leng
        self.content = binascii.unhexlify(content)
        self.TYPE_CALL = 0
        self.TYPE_JMP = 1
        self.append_info1 = append_info1
        self.append_info2 = append_info2
        if "MIPS" not in angr_project.arch.name and "ARM" not in angr_project.arch.name:
            print("Not supported arch %s" % angr_project.arch.name)
        self.arch = "mips" if "MIPS" in angr_project.arch.name else "arm"
        if content == binascii.hexlify(NOP).decode('utf8'): 
            # if it is a nop instr(jump the subfunction call)
            self.type = self.TYPE_CALL
            self.bypass_in_poc = self.append_info1
            if self.append_info2==-1 or self.append_info2==None:
                self.argcount = 4
            else:
                self.argcount = self.append_info2
        else:
            self.type = self.TYPE_JMP
            self.avoid_addr = self.append_info1 

        # currently abandon this property, use bbl_end_addr
        # self.bbl_addr = self.get_bbl_addr(addr, angr_project) 
        block = angr_project.factory.block(addr)
        self.bbl_end_addr = block.addr + block.size

        self.patch_all = patch_all
        patch_all.add(self)

class Free_Memory_Manager():
    # TODO: we give a constant address here,,, its better to give a address like mmap with addr==NULL
    def __init__(self, base=None, max_size=None):
        PROGRAM_FREE_ADDR = 0x12340000 # asserting this area will not get touched by program itself
        PROGRAM_FREE_MAX = 0x10000 # maximum size of this area
        # self.write_offset = 0
        self.base = base if base else PROGRAM_FREE_ADDR
        self.max_size = max_size if max_size else PROGRAM_FREE_MAX
    def write_data(self, angr_state, content, size=None):
        if not size:
            size = len(content)
        # assert self.write_offset + size < self.max_size, "ERROR: no free memory remaining, current max free space size: 0x%08x" % self.max_size
        # l.debug("Inject 0x%x of '\\0' to 0x%x"%(self.max_size, self.base))
        # angr_state.memory.store(self.base, b'\0'*self.max_size)
        l.debug("Inject 0x%x of data %r to 0x%x"%(size, content[:size], self.base))
        angr_state.memory.store(self.base, content[:size])
        # self.write_offset += size
        # return self.write_offset - size + self.base