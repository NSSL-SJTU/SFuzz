import os, json
maybe_critical_funcs = {
    'memcpy':[3],
    'memncpy':[3],
    'memmove':[3],
    'snprintf':[2, 3],
    'vsnprintf':[2, 3],
    'sprintf':[2, 3, 4, 5, 6, 7, 8],
    'vsprintf':[2, 3, 4, 5, 6, 7, 8],
    'sscanf':[1, 2],
    'strcat':[2],
    'strcpy':[2],
    'strncat':[3],
    'strncpy':[3],
    'spliter':[1,2],
    'bcopy':[3],
    'strscat':[1,2],

    'getenv':[0],
    'setenv':[2],
    'nvram_set':[2],
    'nvram_get':[0],

    'Packt_WebGetsVar':[0],
    'jsonObjectGetString':[0],
    'jsonGetObjectString':[0],
    'json_object_get_decode':[0],
    'recv_http_response':[2],
    'os_file_get':[1],
    'os_get_file':[1],
    'recvfrom':[2, 0], 
    'recv':[2, 0],
}
def get_named_func():
    named_funcs = []
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True) # True means 'forward'
    for func in funcs: 
        name = func.getName()
        ea = func.getEntryPoint().getOffset()
        if not name.startswith('FUN_') and not name.startswith('thunk_FUN_'):
            criticalIndex = [-1]
            for maybe_critical_func in maybe_critical_funcs:
                if maybe_critical_func in name:
                    criticalIndex = maybe_critical_funcs[maybe_critical_func]
            named_funcs.append({"funcName":name, "offset":hex(ea).strip('L'), "criticalIndex":str(criticalIndex)})
    return named_funcs

os.system('mkdir -p extrace_result')
with open("%s/extrace_result/%s.simresult"%(os.getcwd(), currentProgram.getExecutablePath().split('/')[-1]), 'w') as f:
    # print(get_named_func())
    json.dump(get_named_func(), f,indent=2)
    print("IDA extraction result has been saved in %s/extrace_result/%s.simresult"%((os.getcwd(), currentProgram.getExecutablePath().split('/')[-1])))
