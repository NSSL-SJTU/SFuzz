#include <unicorn/unicorn.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>

#include "elfLoader.h"
#include "utils.h"
#include "common.h"

#define INPUT_MAX_SIZE 0x2000

extern int uniFuzzerInit(uc_engine *uc, enum uf_arch arch, uint64_t start_addr, char* os, uint64_t inject_addr, uint64_t input_idx, uint64_t input_max_len, uint32_t imagebase, uint32_t imagesize);
extern int uniFuzzerBeforeExec(uc_engine *uc, const uint8_t *data, size_t len, const char* os);
extern int uniFuzzerAfterExec(uc_engine *uc, const char* os);
extern int execOneStep(uc_engine* uc);
extern int startEmulation(uc_engine* uc, unsigned char* data, uint32_t size);
extern void raiseCrashSignal(uc_engine* uc, uc_err err);
extern char* PERROR_INFO(char* str);
extern void flushlogger();
extern int deploy_code_patch(uc_engine* uc);

uc_engine *uc;
extern enum uf_arch arch;
static unsigned char data[INPUT_MAX_SIZE];
extern uint64_t inject_len;

int loadFuzzingData(char* argv[], uint64_t input_max_len){    
    input_max_len = (!input_max_len)?INPUT_MAX_SIZE:(input_max_len<INPUT_MAX_SIZE)?input_max_len:INPUT_MAX_SIZE;
#ifdef UF_USE_FOPEN
    FILE* input = fopen(argv[1], "rb");
    if (!input) {
        perror("fopen"); 
        exit(0);
    }
    fseek(input, 0, SEEK_END);
    unsigned int input_len = ftell(input);
    fseek(input, 0, SEEK_SET);
    if (input_len > input_max_len) exit(0);
    int size=fread(data, 1, input_len, input);
    uf_debug("Data prepared %s(len:%d)\n", data, size);
    fclose(input);
    return size;
#endif
#ifdef UF_USE_MMAP
    // todo
#endif
#ifdef UF_USE_STDIN
    int size=read(fileno(stdin), data, input_max_len);
    uf_debug("Data prepared %s(len:%d)\n", data, size);
    return size;
#endif
}


// log lib base addr to libLog.txt for lib base specification when angr project initialing
extern FILE* libLogger;

// add block hook to log trace info to traceLog.txt for driller analysis
int logIndex=0;
int passLog=1;
extern FILE* patch_count;
extern FILE* unexpected_log;
extern FILE* traceLogger;
extern FILE* pcLogger;
extern uint32_t* pc_log_buffer;
extern uint32_t pc_log_index;

void dumphex(uint8_t* buf, uint32_t size){
    fprintf(stderr, "%s\n", buf);
    for (uint32_t i=0;i<size;i++){
        fprintf(stderr, "0x%02X ", buf[i]);
    }
    fprintf(stderr, "\n");
    for (uint32_t i=0;i<size/4;i++){
        fprintf(stderr, "0x%08X ", *(uint32_t*)&buf[i*4]);
    }
    fprintf(stderr, "\n");
}

void logInstAddr(uc_engine* uc){
    uint32_t pc;
    if (passLog) {
        // if we have meet unexpected crash, we will jump the instruction. However, this may bring unexpected block logging behaviour, so we will jump it.
        uf_debug("passLog: %d\n",passLog);
        passLog--;
        return;
    }
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
#ifdef UF_DEBUG
    fprintf(stderr, "Trace[%d] 0x%08x\n", logIndex++, pc);
#endif

    fprintf(traceLogger, "0x%08x\n", pc);
}

static uint8_t start_follow = 0;

extern uint32_t pc_before;
extern uc_context *context;

void checkeachpc(uc_engine *uc){
    uint32_t pc,lr ;
    uint8_t ss[0x800];
    uint32_t reg;
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
    if (pcLogger)
        fprintf(pcLogger, "0x%08x\n", pc);
    uf_debug("PC: 0x%08x\n", pc);
    pc_before = pc;
    // if(uc_context_save(uc, context) != UC_ERR_OK) {
    //     fprintf(stderr, "uc_context_save failed\n");
    //     _exit(0);
    // }
    // pc_log_buffer[pc_log_index++] = pc;
    // raiseCrashSignal(uc, UC_ERR_OK);
    // if (pc == 0x8022CB88){
    //     puts("0x8022CB88::::::::::::::::");
    //     raiseCrashSignal(uc, UC_ERR_OK);

    //     uc_reg_read(uc, UC_MIPS_REG_A0, &reg);
    //     fprintf(stderr, "T8: 0x%08x\n", reg);
    //     memset(ss,0,0x400); uc_mem_read(uc, reg, ss, 0x400);
    //     dumphex(ss,0x10);
    //     puts("");

    //     uc_reg_read(uc, UC_MIPS_REG_A1, &reg);
    //     fprintf(stderr, "T8: 0x%08x\n", reg);
    //     memset(ss,0,0x400); uc_mem_read(uc, reg, ss, 0x400);
    //     dumphex(ss,0x10);
    //     puts("");

    //     uc_reg_read(uc, UC_MIPS_REG_A2, &reg);
    //     fprintf(stderr, "T8: 0x%08x\n", reg);
    //     memset(ss,0,0x400); uc_mem_read(uc, reg, ss, 0x400);
    //     dumphex(ss,0x10);
    //     puts("");
    //     // sleep(1);
    //     // start_follow=1;
    //     exit(0);
    // }
}

uint32_t end_addrs[100] = {0};
uint32_t end_count = 0; 
uint32_t end_addrs_classB[100] = {0};
uint32_t end_count_classB = 0; 
uint32_t start_detect_crash_addrs[100] = {0};
uint32_t exec_end_addr[100] = {0};
uint32_t exec_end_count = 0;
uint32_t stack_call_trace[100][10]={0};
uint32_t stack_call_trace_cnt = 0;


int read_from_exec_info(char**preload, char** libPath, char** archstr, uint64_t* start_addr, uint64_t* base_addr, uint64_t* inject_addr, char** os, uint64_t* input_idx, uint64_t* input_max_len){
    int exec_fd = open("workdir/exec",O_RDONLY);
    if (exec_fd<0){
        fprintf(stderr, "exec information file not found, pass.\n");
        return -1;
    }
    struct stat st;
    stat("workdir/exec", &st);
    char* exec_info = (char*)malloc(st.st_size);
    read(exec_fd, exec_info, st.st_size);
    
    char * line = exec_info;
    char * info = exec_info;
    uint32_t offset;

    // 1st line: program load base
    line = strchr(line, '\n');
    if (!line) {fprintf(stderr, "exec information file syntax wrong(load base), check your file content\n");return -1;}
    *line = '\0';
    line += sizeof(char);
    *base_addr = strtoul(info, NULL, 16);
    info = line;

    // 2nd line: program arch
    line = strchr(line, '\n');
    if (!line) {fprintf(stderr, "exec information file syntax wrong(arch), check your file content\n");return -1;}
    *line = '\0';
    line += sizeof(char);
    *archstr = strdup(info);
    info = line;

    // 3rd line: simulation start address(fuzzer and angr, should be the block address of input)
    line = strchr(line, '\n');
    if (!line) {fprintf(stderr, "exec information file syntax wrong(start addr), check your file content\n");return -1;}
    *line = '\0';
    line += sizeof(char);
    *start_addr = strtoul(info, NULL, 16);
    info = line;

    // 4th line: address that we nop and hook to inject our input data(shoule be a call instr)
    line = strchr(line, '\n');
    if (!line) {fprintf(stderr, "exec information file syntax wrong(inject addr), check your file content\n");return -1;}
    *line = '\0';
    line += sizeof(char);
    *inject_addr = strtoul(info, NULL, 16);
    info = line;

    // 5th line: the args index that we should inject our fuzzing data(should be a int >=0 and <=6)
    line = strchr(line, '\n');
    if (!line) {fprintf(stderr, "exec information file syntax wrong(inject reg idx), check your file content\n");return -1;}
    *line = '\0';
    line += sizeof(char);
    *input_idx = atol(info);
    info = line;

    // 6th line: the longest data input length(-1 means apply our default maxlength)
    line = strchr(line, '\n');
    if (!line) {fprintf(stderr, "exec information file syntax wrong(inject max len), check your file content\n");return -1;}
    *line = '\0';
    line += sizeof(char);
    *input_max_len = atol(info);
    info = line;

    // 7th line: address to stop our symbolic soving(should be the block address of vuln call, here we simply apply the call instr addr)
    line = strchr(line, '\n');
    if (!line) {fprintf(stderr, "exec information file syntax wrong(sym solve stop addr), check your file content\n");return -1;}
    *line = '\0';
    line += sizeof(char);
    end_count = 0;
    do{
        start_detect_crash_addrs[end_count++] = strtoul(info, NULL, 16);
        info+=sizeof(char);
    }while ((info = strchr(info, ' '))!=NULL);
    info = line;

    // 8th line: address to stop our fuzzer(should be the one last instr after vuln call)
    line = strchr(line, '\n');
    if (!line) {fprintf(stderr, "exec information file syntax wrong(fuzz stop addr), check your file content\n");return -1;}
    *line = '\0';
    line += sizeof(char);
    uint64_t tmp_end_count = 0;
    do{
        end_addrs[tmp_end_count++] = strtoul(info, NULL, 16);
        info+=sizeof(char);
    }
    while ((info = strchr(info, ' '))!=NULL);
    if (tmp_end_count != end_count){fprintf(stderr, "end_addrs and start_detect_crash_addrs length not match, abort\n");return -1;}
    info = line;

    // 9th line: address to stop our symbolic soving(should be the block address of vuln call, here we simply apply the call instr addr)
    line = strchr(line, '\n');
    if (!line) {fprintf(stderr, "exec information file syntax wrong(sym solve stop addr), check your file content\n");return -1;}
    *line = '\0';
    line += sizeof(char);
    do{
        start_detect_crash_addrs[end_count++] = strtoul(info, NULL, 16);
        info+=sizeof(char);
    }while ((info = strchr(info, ' '))!=NULL);
    info = line;

    // 10th line: address to stop our fuzzer(should be the one last instr after vuln call)
    line = strchr(line, '\n');
    if (!line) {fprintf(stderr, "exec information file syntax wrong(fuzz stop addr), check your file content\n");return -1;}
    *line = '\0';
    line += sizeof(char);
    end_count_classB = 0;
    do{
        end_addrs[tmp_end_count++] = strtoul(info, NULL, 16);
        end_addrs_classB[end_count_classB++] = strtoul(info, NULL, 16);
        info+=sizeof(char);
    }
    while ((info = strchr(info, ' '))!=NULL);
    if (tmp_end_count != end_count){fprintf(stderr, "end_addrs and start_detect_crash_addrs length not match, abort\n");return -1;}
    info = line;

    // 11th line: Linux or RTOS?
    line = strchr(line, '\n');
    if (!line) {fprintf(stderr, "exec information file syntax wrong(os), check your file content\n");return -1;}
    *line = '\0';
    line += sizeof(char);
    *os = strdup(info);
    info = line;

    // 12th line: address to stop our emulation(should be the one last block in source func caller)
    line = strchr(line, '\n');
    // if (!line) {fprintf(stderr, "exec information file syntax wrong(emu stop addr), check your file content\n");return -1;}
    if (line){
        *line = '\0';
        line += sizeof(char);
        do{
            exec_end_addr[exec_end_count++] = strtoul(info, NULL, 16);
            info+=sizeof(char);
        }
        while ((info = strchr(info, ','))!=NULL);
        info = line;
    }

    uf_debug("base_addr: 0x%08lx, archstr: %s start_addr: 0x%08lx, inject_addr: 0x%08lx, os: %s, input_idx: %ld, input_max_len: 0x%lx\n", *base_addr, *archstr, *start_addr, *inject_addr, *os, *input_idx, *input_max_len);
    free(exec_info);
    return 0;
}

void alarm_handler(){
    uf_debug("Failed to finish emulation in 200ms, exit\n");
    flushlogger();
    _exit(0);
}

void settimer(){
    // set timer so that it will not execute over 200ms
    signal(SIGALRM, alarm_handler);
    
    struct itimerval new_value;
    new_value.it_value.tv_sec = 0;
    new_value.it_value.tv_usec = 200000;
    // new_value.it_value.tv_usec = 10000;
    new_value.it_interval.tv_sec = 0;
    new_value.it_interval.tv_usec = 0;
    
    if (setitimer(ITIMER_REAL, &new_value, NULL)){
        perror("setitimer");
        flushlogger();
        exit(-1);
    }
}

int main(int argc, char* argv[]){
#ifdef UF_USE_FOPEN
    if (argc<2) {exit(-1);}
#endif

    char *target = getenv("UF_TARGET")?getenv("UF_TARGET"):"";
    char *preload = getenv("UF_PRELOAD")?getenv("UF_PRELOAD"):"";
    char *libPath = getenv("UF_LIBPATH")?getenv("UF_LIBPATH"):"";
    char *archstr = getenv("UF_ARCH")?getenv("UF_ARCH"):"";
    char *trace = getenv("UF_TRACE")?getenv("UF_TRACE"):"";
    uint64_t start_addr = getenv("UF_STARTADDR")?atol(getenv("UF_STARTADDR")):0;
    char *count_patch = getenv("UF_CNTPATCH")?getenv("UF_CNTPATCH"):"";
    /*  
        we interpret end_addr as the target function(such as strcpy, sprintf, etc.) call finished addr
        example:
        MIPS arch:                                              ARM arch:                                               X86 arch:
            addiu $a0, $sp, 0x130 ;                                 mov r1, ... ;                                           push xxx ;
            jal strcpy ;                                            mov r0, ... ;                                           push xxx ; 
            move $a1, $v0 ;                                         bl strcpy ;                                             call strcpy ;
            nop ; <--- This should be the end_addr                  nop ; <----- This should be the end_addr                nop ; <-----This should be the end_addr
            Due to the MIPS Branch Delay Slot(延迟槽) design, the following instr after b/j instr should also be considered
    */

    uint64_t base_addr = getenv("UF_BASEADDR")?atol(getenv("UF_BASEADDR")):0;
    uint64_t inject_addr = getenv("UF_INJECTADDR")?atol(getenv("UF_INJECTADDR")):0;
    uint64_t input_idx = getenv("UF_INPUTIDX")?atol(getenv("UF_INPUTIDX")):0;
    uint64_t input_max_len = getenv("UF_INPUTMAXLEN")?atol(getenv("UF_INPUTMAXLEN")):0;
    uint32_t image_base;
    uint32_t image_size;
    uint64_t exec_end_addr = getenv("UF_INPUTMAXLEN")?atol(getenv("UF_INPUTMAXLEN")):0;

    char *os = getenv("UF_OS");

    if (!start_addr || !base_addr || !exec_end_addr){
        if (read_from_exec_info(&preload, &libPath, &archstr, &start_addr, &base_addr, &inject_addr, &os, &input_idx, &input_max_len)){
            fprintf(stderr, "Failed to load basic execution info, abort.\n");
            exit(-1);
        }
    }
    
    if (strstr(archstr,"arm")){
        uf_debug("Target ARCH: arm\n");
        arch = UF_ARCH_ARM;
    } else if (strstr(archstr, "mips")){
        uf_debug("Target ARCH: MIPS\n");
        arch = UF_ARCH_MIPS;
    } else if (strstr(archstr, "i386")){
        uf_debug("Target ARCH: i386\n");
        arch = UF_ARCH_X86;
    } else {
        fprintf(stderr, "Unsupported arch %s\n", archstr);
        exit(-1);
    }

    if (strstr(archstr,"le") || strstr(archstr,"el")){
        endian = UF_ENDIAN_LITTLE;
    } else if (strstr(archstr,"be") || strstr(archstr,"eb")){
        endian = UF_ENDIAN_BIG;
    } else {
        fprintf(stderr, "Unsupported arch %s\n", archstr);
        exit(-1);
    }

    if (!strcmp(os,"linux")){
        if (!strcmp(trace,"yes") || !strcmp(trace,"YES")){
            // if UF_TRACE set to yes, we log every lib base addr when UF loading
            libLogger = fopen("workdir/libLog.txt","wb");
            if (!libLogger){
                fprintf(stderr, "Failed to open and write lib log\n");
                exit(-1);
            }
        }
        uc = loadELF(target, preload, libPath, arch);
    }
    else{
        // For RTOS system, no dynamic library
        uc = loadRTOS(target, arch, archstr, base_addr, &image_base, &image_size);
    }

    if(uc == NULL || uniFuzzerInit(uc, arch, start_addr, os, inject_addr, input_idx, input_max_len, image_base, image_size)) {
        fprintf(stderr, "init failed for %s\n",target);
        fprintf(stderr, "Usage: UF_TARGET=<target> [UF_PRELOAD=<preload>] UF_LIBPATH=<libPath> ./uf\n");
        exit(1);
    }

    // Deploy the code patch here
    // NOTICE: Since we mmap the ROM with MAP_PRIVATE, the change happen to this memory area will not affect the fireware file itself
    if (deploy_code_patch(uc)){
        fprintf(stderr, "deploy_code_patch failed, check your patch file format.\n");
        exit(1);
    }
    
    if (count_patch && (!strcmp(count_patch, "yes") || !strcmp(count_patch, "YES"))){
        patch_count = fopen("workdir/patch_count", "a");
        if (!patch_count){
            fprintf(stderr, "Failed to open and write patch count log\n");
            exit(-1);
        }
    }

    // IMPORTANT: exec one step so that fuzzer will write data to input file, or the following fopen will fail
    if (execOneStep(uc)){
        exit(1);
    }

    // add alarm after AFL get in
    settimer();

    uc_err err;
    uc_hook hh;
    if (!strcmp(trace,"yes") || !strcmp(trace,"YES")){
        // if UF_TRACE set to yes, we log every block addr with given input

        err = uc_hook_add(uc, &hh,  UC_HOOK_BLOCK, logInstAddr, NULL, 1, 0);
        if (err!=UC_ERR_OK){
            fprintf(stderr, "Hook block failed\n");
            exit(-1);
        }

        pcLogger = fopen("workdir/pcLogger.txt","w");

        traceLogger = fopen("workdir/traceLog.txt","wb");

        if (!traceLogger || !pcLogger){
            fprintf(stderr, "Failed to open and write trace log\n");
            exit(-1);
        }
    }

    // for UC_ERR_EXCEPTION, log the instruction successfully executed
    err = uc_hook_add(uc, &hh,  UC_HOOK_CODE, checkeachpc, NULL, 1, 0);
    if (err!=UC_ERR_OK){
        fprintf(stderr, "Hook block failed\n");
        exit(-1);
    }

    int size=loadFuzzingData(argv, input_max_len);
    
    if(uniFuzzerBeforeExec(uc, data, size, os)) {
        exit(1);
    }
    if(startEmulation(uc, data, sizeof(data))) {
        exit(1);
    }
    if(uniFuzzerAfterExec(uc, os)) {
        exit(1);
    }
#ifdef UF_DEBUG
    uint32_t pc;
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
    uf_debug("End emulation at %p\n",(void*)pc);
#endif
    return 0;
}
