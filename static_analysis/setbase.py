# coding:utf-8
import os, json, sys
sys.stdout.write("\033[0;42msetbase begin %r\033[0m\n"%currentProgram)
try:
    # For https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    from ghidra.ghidra_builtins import *
except:
    pass

# Parameters passed in during headless mode
args = getScriptArgs()
# Here parameter 1 is the specified base address, 0x0000
firt_arg = int(args[0],16)
base_addr = toAddr(firt_arg)
print("Setting ImageBase to 0x%08x"%firt_arg)
currentProgram.setImageBase(base_addr,True)


# if os.access(currentProgram.getExecutablePath()+'.simresult', os.F_OK):
#     print("Reading simresult from %s"%(currentProgram.getExecutablePath()+'.simresult'))
#     with open(currentProgram.getExecutablePath()+'.simresult', 'r') as f:
#         simresults = json.load(f)
#     for simresult in simresults:
#         offset = int(simresult['offset'], 16)
#         funcName = simresult['funcName']
#         if not createFunction(toAddr(offset), funcName):
#             print("Failed to create function %s @ 0x%08x"%(funcName, offset))

sys.stdout.write("\033[0;44msetbase end %r\033[0m\n"%currentProgram)
