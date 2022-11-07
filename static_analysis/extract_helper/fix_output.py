import json
import sys
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
funcSigns = {
    'memcpy': 'void* memcpy(void* dest, void* src, unsigned int n)',
    'memncpy': 'void* memncpy(void* dest, void* src, unsigned int n)',
    'memmove': 'void* memmove(void* dest, void* src, unsigned int n)',
    'snprintf': 'int snprintf(char* str, unsigned int size, char* format, ...)',
    'sprintf': 'int sprintf(char* str, char* format, ...)',
    'sscanf': 'int sscanf(char* str, char* format, ...)',
    'strcat': 'char* strcat(char* dest, char* src)',
    'strcpy': 'char* strcpy(char* dest, char* src)',
    'strncat': 'char* strncat(char* dest, char* src, unsigned int n)',
    'strncpy': 'char* strncpy(char* dest, char* src, unsigned int n)',
    'setenv': 'int setenv(char* name, char* value)',
    'nvram_set': 'int nvram_set(char* name, char* value)',
    'spliter': 'int spliter(char* src, char* term, char* dst)',
    'bcopy': 'int bcopy(char* src, char* dst, unsigned int n)',
    'vsnprintf': 'int vsnprintf(char* str, unsigned int size, char* format, ...)',
    'vsprintf': 'int vsprintf(char* str, char* format, ...)',
    'strscat': 'char* strscat(char* src1, char* src2, char* dst)',

}
def fix_output(simresultfile):
    with open(simresultfile,'r') as f:
        cont = json.load(f)

    converted_func = {}
    address_funcName_map = {}
    error = False
    for item in cont:
        if item['funcName'] not in converted_func:
            if 'criticalIndex' in item:
                converted_func.update({item['funcName']:(item['offset'], item['criticalIndex'])})
            else:
                converted_func.update({item['funcName']:(item['offset'], '[]')})
        elif item['offset']!=converted_func[item['funcName']][0]:
            # if one funcName have 2 different address
            found = False
            for maybe_critical_func in maybe_critical_funcs:
                if maybe_critical_func in item['funcName']:
                    found = True
                    break
            if not found:
                error = True
                print("%r not correspond to %r"%(item, converted_func[item['funcName']]))
        
        if item['offset'] not in address_funcName_map:
            address_funcName_map.update({item['offset']:item['funcName']})
        elif address_funcName_map[item['offset']]!=item['funcName']:
            error = True
            print("%r not correspond to %r"%(item, address_funcName_map[item['offset']]))
        if 'funcSign' in item and item['funcName'] not in item['funcSign']:
            error = True
            print("%r has non-corresponding funcName %r and funcSign %r"%(item, item['funcName'], item['funcSign']))
    if not error:
        convert = []
        for item in cont:
            info = None
            for maybe_critical_func in maybe_critical_funcs:
                if maybe_critical_func in item['funcName']:
                    #print("fixing funcName %s critIdx %r to %r"%(item['funcName'], item['criticalIndex'], str(maybe_critical_funcs[maybe_critical_func])))
                    if maybe_critical_func in funcSigns:
                        info = {'offset':item['offset'], 'funcName':item['funcName'], 'criticalIndex':item['criticalIndex'], 'criticalIndex':str(maybe_critical_funcs[maybe_critical_func]), 'funcSign':funcSigns[maybe_critical_func].replace(maybe_critical_func, item['funcName'])}

                    else:
                        info = {'offset':item['offset'], 'funcName':item['funcName'], 'criticalIndex':item['criticalIndex'], 'criticalIndex':str(maybe_critical_funcs[maybe_critical_func])}
                    break
            if not info:
                info = item
                if 'funcSign' in info:
                    info.pop('funcSign')
            if item['funcName'] not in [i['funcName'] for i in convert]:
                convert.append(info)
        assert set([i['funcName'] for i in convert]) == set([i['funcName'] for i in convert])
        with open(simresultfile.replace('_all',''),'w') as f:
            print("%s dump %d results"%(simresultfile,len(convert)))
            json.dump(convert, f, indent=2)
        return 0
    return -1
if __name__=='__main__':
    exit(fix_output(sys.argv[1]))
