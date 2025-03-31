# This script is used to analyze the dest of sink point using rd analysis

import angr 
import sys
import archinfo
import os
from pathlib import Path
from networkx.drawing.nx_agraph import write_dot
import json
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from archinfo import Arch, RegisterOffset
from angr.engines.light import SpOffset, RegisterOffset
from angr.knowledge_plugins.key_definitions.atoms import Register, SpOffset, MemoryLocation
from angr.knowledge_plugins.key_definitions.undefined import Undefined
from angr.knowledge_plugins.key_definitions.definition import Tag
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag
from angr.knowledge_plugins.key_definitions.tag import ParameterTag
from angr import Project
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE,OP_AFTER
import re
import glob
from collections import deque

def extract_points(trace):
    points = re.findall(r'[\w_]+', trace)
    return points

def magic_graph_print(filename, dependency_graph):
    path_and_filename = os.path.join('./', filename)
    write_dot(dependency_graph, "%s.dot" % path_and_filename)
    os.system("dot -Tsvg -o %s.svg %s.dot" % (path_and_filename, path_and_filename))

class FunctionMap:
    def __init__(self):
        self.name_to_offset = {}
        self.offset_to_name = {}

    def add_function(self, func_name, offset):
        self.name_to_offset[func_name] = offset
        self.offset_to_name[offset] = func_name

    def get_offset(self, func_name):
        return self.name_to_offset.get(func_name)

    def get_name(self, offset):
        return self.offset_to_name.get(offset)

    def remove_function_by_name(self, func_name):
        offset = self.name_to_offset.pop(func_name, None)
        if offset is not None:
            self.offset_to_name.pop(offset, None)

    def remove_function_by_offset(self, offset):
        func_name = self.offset_to_name.pop(offset, None)
        if func_name is not None:
            self.name_to_offset.pop(func_name, None)

func_map = FunctionMap()

def parse_funcs(project,simresult_filepath):
    try:
        f=open(simresult_filepath, 'r')
    except:
        print("Failed to open file:", simresult_filepath)
        return
    simresults=json.load(f)
    if simresults:
        for simresult in simresults:
            offset = int(simresult['offset'], 16)
            funcName = simresult['funcName']
            func_map.add_function(funcName,offset)
   
def parse_traces(result_filepath):
    traces=[]
    file_pattern = os.path.join(result_filepath, "calltrace_*")
    calltrace_files = glob.glob(file_pattern)
    for file_path in calltrace_files:
        f=open(file_path)
        while(1):
            one_trace=f.readline()
            trace=[]
            if one_trace:
                points = extract_points(one_trace)[1:]
                for each in points:
                    if func_map.get_offset(each):
                        trace.append(func_map.get_offset(each))
                    elif each.startswith("FUN_"):
                        # print("0x"+(each[4:]))
                        trace.append(int("0x"+each[4:],16))
                    elif each.startswith("thunk_FUN_"):
                        # print("0x"+(each[4:]))
                        trace.append(int("0x"+each[10:],16))
                    else:
                        print("Error: unknown function",each)
                        return
                # print(points)
                traces.append(trace)
            else:
                break
    return traces

def find_call_site(arch, func, next_func_addr):
    """
    find call site in a function to the next func in the trace
    Args:
        func (Function): Function object analyzed currently
        next_func_addr (int): called func addr
    Returns:
        _type_: addr
    """
    # print(func)
    res=[]
    # print("Try to find call site of %s from %s"%(hex(next_func_addr),func))
    if "ARM" in arch.name:
        for block in func.blocks:
            # print("one block ",hex(block.addr))
            for insn in block.capstone.insns:
                if "bl" in insn.mnemonic:
                    print(hex(insn.address),hex(insn.operands[0].imm),hex(next_func_addr))
                    if hex(insn.operands[0].imm) == hex(next_func_addr):
                        res.append(insn.address)
    elif "MIPS" in arch.name:
        for block in func.blocks:
            # print("one block ",hex(block.addr))
            for insn in block.capstone.insns:
                if "jal" in insn.mnemonic:
                    # print(hex(insn.address),insn.operands[0].imm)
                    if hex(insn.operands[0].imm) == hex(next_func_addr):
                        res.append(insn.address)
    else:
        print("Unknown arch")
        return None
    return res
      
def RDanalyze_trace(project,trace):
    res=[]
    for i in range(len(trace)-1):
        # loop all func in this trace
        print(hex(trace[i]),trace[i] in project.kb.functions.function_addrs_set)
        current_func=project.kb.functions.function(addr=trace[i])
        if(current_func is None):
            continue
        print("Analyzing function at: ",hex(trace[i]))
        call_stack=trace[:i]
 
        # find call point
        call_site = find_call_site(project.arch,current_func,trace[i+1])
        if call_site==[]:
            continue
        print("Call site:",end=" ")
        for each in call_site:
            print(hex(each))
        observation_points=[]
        for each in call_site:
            observation_points.append(('insn', each, OP_BEFORE))
        # RDA
        function_rda = project.analyses.ReachingDefinitions(
            subject=current_func,
            track_calls=True,
            # track_consts=True,
            # track_tmps=True,
            # observe_all=True,
            observation_points=observation_points,
            dep_graph=DepGraph(),
            call_stack=call_stack
        )
        # store res to final_res
        res.append(function_rda)
    return res
 
analyzed_cfg_func=[]       
def RDA_analyze(project,traces):   
    print(traces)
    rda_res=[]  
    i=0
    for each in traces:
        print("Analyzing trace: ", " ".join(hex(a) for a in each))
        # if(len(each)>4):
        #     print("This trace is too long,we only focus on the last 4 func")
        #     each=each[-4:]
        print("Analyzing CFG (it's better to run cfgfast for whole bin, here we just analyze the region near target function for current trace)")
        # func_addr=0x40207890
        funcs_need_cfganalyze=[a for a in each if a not in analyzed_cfg_func]
        
        # for func in each:
        #     if(func not in project.kb.functions.function_addrs_set):
        #         new_function = angr.knowledge_plugins.functions.Function(project.kb.functions,addr=func)
        #         print(func in project.kb.functions.function_addrs_set)
        #         print("add new func at %s"%(hex(func)))
        #         project.kb.functions[func] = new_function
        #         project.kb.functions.rebuild_callgraph()
        #         print(func in project.kb.functions.function_addrs_set)
        
        project.entry = each[0]  
        if(len(funcs_need_cfganalyze)!=0):
            cfg = project.analyses.CFGFast(
                # normalize=True,
                # force_complete_scan=False,  
                resolve_indirect_jumps=False,
                cross_references=False,  
                show_progressbar=True,
                exclude_sparse_regions=False,
                regions=[(a-0x10000, a+ 0x10000) for a in each if a not in analyzed_cfg_func]
                # start=func_addr-0x100000, 
                # end=func_addr+ 0x100000,
            )
            analyzed_cfg_func.append(a for a in funcs_need_cfganalyze)
         
        for func in each:
            if func in project.kb.functions.function_addrs_set:
                print(f"Function {hex(func)} is still in the knowledge base.")
            else:
                print(f"Function {hex(func)} is missing from the knowledge base.")
           
        # print(project.kb.functions.function_addrs_set)
        trace_rda=RDanalyze_trace(project,each)
        if trace_rda==[]:
            i=i+1
            continue
        rda_res.append(trace_rda)
        # print(len(trace_rda))
    return  rda_res 
         
def main():
    # Path of the blob.
    blob_path = sys.argv[1]
    base_addr = int(sys.argv[2],16)
    findtrace_output = sys.argv[3]
    arch = sys.argv[4].lower()

    if 'mips' in arch:
        if 'le' in arch:
            angr_arch = 'mipsel'
        else:
            angr_arch = 'mipseb'
    elif 'arm' in arch:
        if 'le' in arch:
            angr_arch = 'armel'
        else:
            angr_arch = 'armeb'
    else:
        print("Not supprt arch!")
        return
    
    print("Creating angr Project")
    project = angr.Project(blob_path, main_opts={'backend': 'blob', 'arch': angr_arch, 'base_addr': base_addr})
    
    # Load func info
    parse_funcs(project,blob_path+".simresult")    
    # parse findtrace result:
    traces=parse_traces(findtrace_output)
    
    rda_res=RDA_analyze(project,traces)

    for each in rda_res:
        for func in reversed(each):
            for a in func._observation_points:
                state_before_call = func.observed_results[a]
                if "ARM"  in project.arch.name:
                    r0_offset = project.arch.registers['r0'][0]
                    r1_offset = project.arch.registers['r1'][0]
                    r2_offset = project.arch.registers['r2'][0]
                elif "MIPS" in project.arch.name:
                    r0_offset = project.arch.registers['a0'][0]
                    r1_offset = project.arch.registers['a1'][0]
                    r2_offset = project.arch.registers['a2'][0]
                r0_definition = list(state_before_call.get_register_definitions(r0_offset,4))
                r1_definition = list(state_before_call.get_register_definitions(r1_offset,4))
                r2_definition = list(state_before_call.get_register_definitions(r2_offset,4))
                
                if(len(r0_definition)==0): 
                    r0_dependencies=None
                else:
                    r0_dependencies = func.dep_graph.transitive_closure(r0_definition[0])
                    
                if(len(r1_definition)==0): 
                    r1_dependencies=None
                else:
                    r1_dependencies = func.dep_graph.transitive_closure(r1_definition[0])
                    
                if(len(r2_definition)==0): 
                # When analyze single func, if len==0,the reg have not been define in the func.Maybe same as called in parent
                    r2_dependencies=None
                else:   
                    r2_dependencies = func.dep_graph.transitive_closure(r2_definition[0]) # nxgraph   
                # print(r0_dependencies.nodes)         
                outfile = open(os.path.join(findtrace_output,hex(a[1])+"_paramsource"),"w")
                    
                for target in [[r0_definition,r0_dependencies],[r1_definition,r1_dependencies],[r2_definition,r2_dependencies]]:
                    if(len(target[0])==0): 
                        continue
                    tasks = deque()
                    analyzed_task=[]
                    tasks.append([target[0][0]])
                    dependencies=target[1]
                    print(f"Analyzing reg {project.arch.translate_register_name(target[0][0].atom.reg_offset, target[0][0].atom.size)} at {hex(a[1])}:\n")
                    outfile.write(f"Analyzing reg {project.arch.translate_register_name(target[0][0].atom.reg_offset, target[0][0].atom.size)} at {hex(a[1])}:\n")
                    
                    while(tasks):
                        level=tasks.pop()
                        for each in level:
                            analyzed_task.append(each)
                            # print("\ncurrent level:",each)
                            try:
                                predecessors = list(dependencies.predecessors(each))
                                # print(predecessors)
                                if(len(predecessors)==0):
                                    if("ReturnValueTag " in str(each)):
                                        print(f"    - Reg {project.arch.translate_register_name(each.atom.reg_offset, each.atom.size)} comes from func return_val of function {hex(list(each.tags)[0].function)} at {hex(each.codeloc.ins_addr)} \n")
                                        outfile.write(f"    - Reg {project.arch.translate_register_name(each.atom.reg_offset, each.atom.size)} comes from func return_val of function {hex(list(each.tags)[0].function)} at {hex(each.codeloc.ins_addr)} \n")
                                    else:
                                        block = project.factory.block(each.codeloc.ins_addr)
                                        for insn in block.capstone.insns:
                                            if insn.address == each.codeloc.ins_addr:
                                                match = re.search(r'#(0x[\da-fA-F]+|\d+)', insn.op_str)
                                                if match:
                                                    number = int(match.group(1),16)
                                                    print(f"    - Reg {project.arch.translate_register_name(each.atom.reg_offset, each.atom.size)} is set as Const {number} at {hex(each.codeloc.ins_addr)}")
                                                    outfile.write(f"    - Reg {project.arch.translate_register_name(each.atom.reg_offset, each.atom.size)} is set as Const {number} at {hex(each.codeloc.ins_addr)} \n")
                                                break
                                else:
                                    if(isinstance(each.atom,MemoryLocation)):
                                        print(f"    Predecessors of memory {each.atom} at {hex(each.codeloc.ins_addr)}:\n",len(predecessors), predecessors)
                                        outfile.write(f"    Predecessors of memory {each.atom} at {hex(each.codeloc.ins_addr)}:\n",len(predecessors), predecessors)
                                        
                                    else:
                                        print(f"    Predecessors of reg {project.arch.translate_register_name(each.atom.reg_offset, each.atom.size)} at {hex(each.codeloc.ins_addr)}:\n",len(predecessors), predecessors)
                                        outfile.write(f"    Predecessors of reg {project.arch.translate_register_name(each.atom.reg_offset, each.atom.size)} at {hex(each.codeloc.ins_addr)}:\n {len(predecessors)} {predecessors}\n")
                                        
                                    predecessors=[task for task in predecessors if task not in analyzed_task]
                                    # print(f"\nadd target : {predecessors}\n")
                                    tasks.append(predecessors)
                            except Exception as e:
                                print(f"    Exception: {e} happen! the reg may come from external. ")
                                if(isinstance(each.atom,MemoryLocation)):
                                    # LDR addr from region after function
                                    print(f"    - Memory {each.atom}  comes from Func_arg/InitialValue(sp...) of function {each.codeloc}\n")
                                    outfile.write(f"    - Memory {each.atom}  comes from Func_arg/InitialValue(sp...) of function {each.codeloc}\n")
                                else:
                                    print(f"    - Reg {project.arch.translate_register_name(each.atom.reg_offset, each.atom.size)} comes from Func_arg/InitialValue(sp...) of function {each.codeloc}\n")
                                    outfile.write(f"    - Reg {project.arch.translate_register_name(each.atom.reg_offset, each.atom.size)} comes from Func_arg/InitialValue(sp...) of function {each.codeloc}\n")
                                continue
                    print()
                    outfile.write("\n")

if __name__ == "__main__":
    main()
