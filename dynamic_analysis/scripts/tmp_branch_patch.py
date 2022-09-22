class cbranch_analysis():
    def __init__(self):
        self.cbranch_blockinfos = []
        self.movn_like_cbranch_infos = []
        self.parse_cbranch_blockinfos()
        self.state_str = 'initial state:\n'
        self.state_id = -1
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

# print("tmp_branch_patch.py get executed")
cb_analysis = cbranch_analysis()