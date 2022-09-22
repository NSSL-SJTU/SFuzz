#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unicorn/unicorn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/random.h>
#include <assert.h>
#include "common.h"

uc_context *context;

// CHANGE ME!
// start addr of the emulation (entry point of function vuln)
// #define START 0x105fc
// end addr of the emulation (return addr in main)
// #define END 0x1077C
// return addr of the target function
// #define RA 0x1077C

// CHANGE ME!
// name of the preload library
#define PRELOAD_LIB "demo-libcpreload.so"

// CHANGE ME!
// readelf -sW demo-libcpreload.so | grep heap_boundary
#define HEAP_BOUNDARY_GOT_OFFSET 0x10380

#define HEAP_SIZE 1024*1024*32
#define STACK_SIZE 1024*1024*8
#define DATA_SIZE 0x2000
#define END_ADDR 0xdeadbee0

static char *heapBase;
static char *stackTop;
static char *dataAddr;

uint32_t inject_idx=0xffffffff;
uint32_t inject_len;

extern enum uf_arch arch;
extern void dumphex(uint8_t* buf, uint32_t size);
extern char* PERROR_INFO(char* str);
extern int passLog;

// heap_boundary@got for the simplified malloc() in demo-preload
static uint32_t *heapBoundaryGOT;
#define HEAP_CANARY 0xdeadbeef 

extern FILE* libLogger;
extern FILE* pcLogger;
extern FILE* traceLogger;
extern FILE* unexpected_log;

// callback: invoked when ELFs(target binary and dependent libs) are loaded 
void onLibLoad(const char *libName, void *baseAddr, void *ucBaseAddr) {
    fprintf(stderr, "loading %s at %p, uc addr: %p\n", libName, baseAddr, ucBaseAddr);
    if (libLogger) fprintf(libLogger, "%s %p\n", libName, ucBaseAddr);
    if(strlen(libName)+1 >= sizeof(PRELOAD_LIB)) {
        // libname ends with "demo-libcpreload.so"
        if(strcmp(libName+strlen(libName)-sizeof(PRELOAD_LIB)+1, PRELOAD_LIB) == 0) {
            heapBoundaryGOT = (uint32_t*)((char *)baseAddr + HEAP_BOUNDARY_GOT_OFFSET);
            fprintf(stderr, PRELOAD_LIB" is at %p, heap_boundary@got is at %p\n", baseAddr, heapBoundaryGOT);
        }
    }
}

extern uint32_t end_addrs[100];
extern uint32_t end_count; 
extern uint32_t end_addrs_classB[100];
extern uint32_t end_count_classB; 
extern uint32_t exec_end_addr[100];
extern uint32_t exec_end_count; 
// extern uint64_t start_detect_crash_addrs[100] = {0};
extern uint32_t stack_call_trace[100][10];
extern uint32_t stack_call_trace_cnt;

unsigned int start_detect = 0;
uint32_t has_injected = 0;
uint32_t unexpected_crash_cnt = 0;
uint32_t err_exception_cnt = 0;
uint32_t start_addr_global = 0;
uint32_t image_size_global = 0;
uint32_t pc_before = 0;
#define MAX_UNEXPECTED_CRASH 20
#define MAX_ERR_EXCEPTION_CNT 20
// #define MAX_UNEXPECTED_CRASH 0
#define UNEXPECTED_CRASH_IGNORE 0
// int random_fd;

void flushlogger(){
    if (libLogger) {uf_debug("flushing libLogger\n");fflush(libLogger);};
    if (traceLogger) {uf_debug("flushing traceLogger\n");fflush(traceLogger);};
    if (pcLogger) {uf_debug("flushing pcLogger\n");fflush(pcLogger);};
}

void raiseCrashSignal(uc_engine* uc, uc_err err){
    uc_err sigsegv_errs[] = {UC_ERR_READ_UNMAPPED, UC_ERR_READ_PROT, UC_ERR_READ_UNALIGNED, \
                                         UC_ERR_WRITE_UNMAPPED, UC_ERR_WRITE_PROT, UC_ERR_WRITE_UNALIGNED, \
                                         UC_ERR_FETCH_UNMAPPED, UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNALIGNED};
    uint32_t reg1,reg2;

    // ignore some exception
    if (err == UC_ERR_EXCEPTION){
        uf_debug("unicorn meet UC_ERR_EXCEPTION error, pc_before: 0x%08x\n", pc_before);
        if (err_exception_cnt++ > MAX_ERR_EXCEPTION_CNT){
            fprintf(stderr, "unicorn meet multiple unexpected UC_ERR_EXCEPTION error, exit emulation.\n");
            flushlogger();
            _exit(0);
        }
        // uc_context_restore(uc, context);
        if (arch == UF_ARCH_MIPS)
            pc_before += 8;
        else if (arch == UF_ARCH_ARM)
            pc_before += 4;
        uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &pc_before);
        
        return ;
    }
    // if (err == UC_ERR_READ_UNALIGNED || err == UC_ERR_WRITE_UNALIGNED){
    //     uint32_t pc;
    //     uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
    //     uf_debug("%s triggered at 0x%08x, passing\n", uc_strerror(err), pc);
    //     pc += 4;
    //     uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
    //     return ;
    // }
    // if (err == UC_ERR_FETCH_UNALIGNED){
    //     uint32_t pc, lr;
    //     uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
    //     uf_debug("%s triggered at 0x%08x, passing\n", uc_strerror(err), pc);
    //     uc_reg_read(uc, uf_conv_regs[arch][UF_REG_LR], &lr);
    //     uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &lr);
    //     return ;
    // }

    if (!start_detect && (unexpected_crash_cnt < MAX_UNEXPECTED_CRASH || UNEXPECTED_CRASH_IGNORE) && err!=UC_ERR_OK){
        unexpected_crash_cnt+=1;
        uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &reg1);
        if (reg1 && reg1 != END_ADDR){
            if (getenv("UF_LOGUNEXP_CRASH") && (!strcmp(getenv("UF_LOGUNEXP_CRASH"), "yes") || !strcmp(getenv("UF_LOGUNEXP_CRASH"), "YES"))){
                uf_debug("UF_LOGUNEXP_CRASH set to %s\n", getenv("UF_LOGUNEXP_CRASH"));
                unexpected_log = fopen("workdir/unexpected_log","a");
                if (unexpected_log){
                    fprintf(stderr, "unexpected_log init @ %p\n", unexpected_log);
                    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &reg1);
                    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_LR], &reg2);
                    fprintf(unexpected_log, "PC 0x%08x LR 0x%08x: %s\n", reg1, reg2, uc_strerror(err));
                    uf_debug("PC 0x%08x LR 0x%08x: %s\n", reg1, reg2, uc_strerror(err));
                    fclose(unexpected_log);
                }
            }
            uf_debug("unexpected crash happened @ 0x%08x because of %s, but under bare threshold, pass this instrution\n", reg1, uc_strerror(err));
            reg1+=4;
            passLog = 2;
            uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &reg1);
            return ;
        }
    }
    
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &reg1);
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_LR], &reg2);
    if (reg1 == END_ADDR || (reg1 <= 0x1000 && reg2 == END_ADDR)){
        uf_debug("seems program execution reach the end of caller function, pc=0x%08x, lr=0x%08x, exit\n", reg1, reg2);
        flushlogger();
        _exit(0);
    }
#ifdef UF_DEBUG
    fprintf(stderr,"UC raise: %s\n",uc_strerror(err));
    uint32_t pc, sp, a0, a1, a2, a3, lr, rv, bp;
    uint8_t code[0x20]={0};
    uint8_t stack[0x20]={0};
    uc_err read_err;
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_SP], &sp);
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_A0], &a0);
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_A1], &a1);
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_A2], &a2);
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_A3], &a3);
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_LR], &lr);
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_RV], &rv);
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_BP], &bp);
    fprintf(stderr, "CRASH PC: 0x%08x SP: 0x%08x A0: 0x%08x A1: 0x%08x A2: 0x%08x A3: 0x%08x LR: 0x%08x RV: 0x%08x BP: 0x%08x\n", pc, sp, a0, a1, a2, a3, lr, rv, bp);
    if (arch==0) fprintf(stderr," ARCH: ARM\n");
    else if (arch==1) fprintf(stderr," ARCH: MIPS\n");
    else if (arch==2) fprintf(stderr," ARCH: X86\n");
    if((read_err=uc_mem_read(uc, pc, code, 0x20))!=UC_ERR_OK){
        fprintf(stderr, "uc_mem_read: %s\n", uc_strerror(read_err));
    }
    fprintf(stderr, "CODE: ");
    for (int i=0;i<0x20;i++){
        fprintf(stderr, "%02X", code[i]);
    }
    fprintf(stderr,"\n");
    if((read_err=uc_mem_read(uc, sp, stack, 0x20))!=UC_ERR_OK){
        fprintf(stderr, "uc_mem_read: %s\n", uc_strerror(read_err));
    }
    fprintf(stderr, "STACK: ");
    for (int i=0;i<0x20;i++){
        fprintf(stderr, "%02X", stack[i]);
    }
    fprintf(stderr,"\n");
#endif
    flushlogger();
    if (!start_detect && err != UC_ERR_OK){
        fprintf(stderr, "unexpected crash detected, exit.\n");
        if (getenv("UF_LOGUNEXP_CRASH") && (!strcmp(getenv("UF_LOGUNEXP_CRASH"), "yes") || !strcmp(getenv("UF_LOGUNEXP_CRASH"), "YES"))){
            uf_debug("UF_LOGUNEXP_CRASH set to %s\n", getenv("UF_LOGUNEXP_CRASH"));
            unexpected_log = fopen("workdir/unexpected_log","a");
            if (unexpected_log){
                fprintf(stderr, "unexpected_log init @ %p\n", unexpected_log);
                uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &reg1);
                uc_reg_read(uc, uf_conv_regs[arch][UF_REG_LR], &reg2);
                fprintf(unexpected_log, "PC 0x%08x LR 0x%08x: %s\n", reg1, reg2, uc_strerror(err));
                uf_debug("PC 0x%08x LR 0x%08x: %s\n", reg1, reg2, uc_strerror(err));
                fclose(unexpected_log);
            }
        }
        _exit(0);
    }
    for (int i=0;i<sizeof(sigsegv_errs)/sizeof(uc_err);i++){
        if (err==sigsegv_errs[i]){
            fprintf(stderr,"raise SIGSEGV signal\n");
            raise(SIGSEGV);
            _exit(-1);
        }
    }
    if(err == UC_ERR_INSN_INVALID){
        fprintf(stderr,"raise SIGILL signal\n");
        raise(SIGILL);
        _exit(-1);
    }
    if(err != UC_ERR_OK){
        fprintf(stderr,"raise SIGABRT signal\n");
        raise(SIGABRT);
        _exit(-1);
    }
}

int execOneStep(uc_engine* uc){
    uint32_t pc;
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
    uf_debug("Exec one instr at %p before officially write fuzz data\n",(void*)pc);
    uc_err err=UC_ERR_OK;
    startemu1:
    err = uc_emu_start(uc, pc, -1, 0, 1);
    // exit(0);
#ifdef UF_DEBUG
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
    uf_debug("pc after exec 1 instr: %p\n",(void*)pc);
    // __asm__("int $0x3;");
#endif
    if (err!=UC_ERR_OK){
        uf_debug("err with %s\n", uc_strerror(err));
        if (!has_injected) {
            passLog = 2;
            uint32_t reg;
            uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &reg);
            reg+=4;
            uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &reg);
            uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
            goto startemu1;
        }
        uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
        // printf("CRASH happened at %p\n",(void*)pc);
        raiseCrashSignal(uc, err); 
        goto startemu1;
    }
    return 0;
}

int startEmulation(uc_engine* uc, unsigned char* data, uint32_t size){
    uint32_t pc, old_pc=0;
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
    // Start emulation
    uf_debug( "Start emulation at %p\n", (void*)pc);
    
    // sometimes the first instruction will change the sp value, we don't want it, check it here
    uint32_t sp;
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_SP], &sp);
    if (sp!=(unsigned int)(stackTop+STACK_SIZE - 0x8000)){
        sp =(unsigned int)(stackTop+STACK_SIZE - 0x8000);
        uc_reg_write(uc, uf_conv_regs[arch][UF_REG_SP], &sp);
    }

    uc_err err;
    startemu2:
    err = uc_emu_start(uc, pc, 0, 1000*1000*5, 100000);  // run maximum 1000*1000*5 us and 100000 instructions
    if (err != UC_ERR_OK){
        if (!has_injected) {
            passLog = 2;
            uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
            pc+=4;
            uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
            uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
            goto startemu2;
            // return 0;
        }
        uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
        raiseCrashSignal(uc, err);
        uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
        goto startemu2;
    }
    return 0;
}

// syscall hook: currently only support at most FOUR args
void hook_syscall(uc_engine* uc, uint32_t intno, void* user_data) {
    // Interrupt may include syscall, so we need to filter it out and execute them with native syscall
    // MIPS interrupt reference: https://blog.csdn.net/myxmu/article/details/10502681
    // 
    if (((arch == UF_ARCH_MIPS) && (intno == 8)) || ((arch == UF_ARCH_ARM) && (intno == 0)) || ((arch == UF_ARCH_X86) && (intno == 0x80))){
        int syscall_abi[5] = {uf_conv_regs[arch][UF_REG_SYSCALL], uf_conv_regs[arch][UF_REG_A0], uf_conv_regs[arch][UF_REG_A1], uf_conv_regs[arch][UF_REG_A2], uf_conv_regs[arch][UF_REG_A3]};
        uint32_t regval[5], pc;
        uc_err err;
        void* regptr[5] = {&regval[0], &regval[1], &regval[2], &regval[3], &regval[4]};
        if ((err = uc_reg_read_batch(uc,syscall_abi,regptr,5))!=UC_ERR_OK){
            fprintf(stderr, "uc_reg_read_batch error with %s", uc_strerror(err));
            flushlogger();
            _exit(-1);
        }
        if ((err = uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc))!=UC_ERR_OK){
            fprintf(stderr, "uc_reg_read error with %s", uc_strerror(err));
            flushlogger();
            _exit(-1);
        };
        uf_debug("syscall get called at 0x%08x, syscall# before converted: %u\n",pc, regval[0]);
        if (arch==UF_ARCH_MIPS) { regval[0] = regval[0] - 4000; }
        if (regval[0]>433){fprintf(stderr,"Uncaught syscall\n");raiseCrashSignal(uc, UC_ERR_EXCEPTION);}
        regval[0]=uf_syscall[arch][regval[0]];
        uf_debug("hook_syscall get called syscall number %d, args: %d %d %d %d\n",regval[0],regval[1],regval[2],regval[3],regval[4]);
        
        // FIXME: What if the ptr doest not match the memory?
        // NOTICE: clang cannot make pie executable here so 0x400000-0x408000, 0x607000-0x608000 and such address in 32-bit memspace may cause incorrespondency between unicorn memory and fuzzer memory
        uint32_t retval=syscall(regval[0],regval[1],regval[2],regval[3],regval[4]);
        #ifdef UF_DEBUG
            if (retval<0){
                uf_debug("syscall exec failed.\n");
            }
        #endif 
        uc_reg_write(uc,uf_conv_regs[arch][UF_REG_RV],&retval);
    }
    else{
        uint32_t pc;
        uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
        uf_debug("Simulation encounter interrupt %u at 0x%08x\n", intno, pc);
        raiseCrashSignal(uc, UC_ERR_HANDLE);
    }

    
}
void hook_invalidInstr(uc_engine* uc, void* user_data){
#ifdef UF_DEBUG
    uint64_t pc;
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC],&pc);
    fprintf(stderr, "Meet invalid instr at %p",(void*)pc);
#endif
    raiseCrashSignal(uc, UC_ERR_INSN_INVALID);
}

void exitemulation(uc_engine *uc, uint64_t addr){
    uf_debug("exit emulation at @ 0x%08lx\n", addr);
    flushlogger();
    _exit(0);
}


// #define MAP_CONTENT "1111111"
#define MAP_MINSIZE 0x1000
#define MAP_MIPS_CODE_CONTENT "\x08\x00\xe0\x03"
#define MAP_ARM_CODE_CONTENT "\x0e\xf0\xa0\xe1"
#define MAP_OTHER_CONTENT "dddd"
#define MAP_MIPS_CODEBE_CONTENT "\x03\xe0\x00\x08"
#define MAP_ARM_CODEBE_CONTENT "\xe1\xa0\xf0\x0e"



int hook_unmappedmem(uc_engine* uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void* user_data){
    /*
        addr: address that trigger unmap error
        size: read/write/fetch data size
        value: read/write/fetch data content
    */
    uint64_t addrrangeL = addr & (~(MAP_MINSIZE-1));
    uint64_t addrrangeH = ((addr+size) & (~(MAP_MINSIZE-1)));
    if (((addr+size) & (MAP_MINSIZE-1))!=0){
        addrrangeH += MAP_MINSIZE;
    }
    uint64_t map_size = addrrangeH-addrrangeL;

    uf_debug("hook_unmappedmem intercept a UNMAP event, addr 0x%08lx, size 0x%08x, value 0x%08lx, addrrangeL 0x%08lx, addrrangeH 0x%08lx, map_size 0x%08lx, arch %s\n", addr, size, value, addrrangeL, addrrangeH, map_size, (char*)user_data);
    if (addrrangeL <= 0x10000){// || addrrangeL >= 0xffff0000){
        uf_debug("hook_unmappedmem warning: addrrangeL is too small or big\n");
    }
    uc_err err;
    err = uc_mem_map(uc, addrrangeL, map_size, UC_PROT_READ|UC_PROT_WRITE|UC_PROT_EXEC);
    if (err != UC_ERR_OK){
        raiseCrashSignal(uc, err);
    }
    if (type == UC_MEM_WRITE_UNMAPPED){
        err = uc_mem_write(uc, addr, &value, size);
        // fprintf(stderr, "test1\n");
        if (err != UC_ERR_OK){
            raiseCrashSignal(uc, err);
        }
    }
    else{
        if (type == UC_MEM_FETCH_UNMAPPED){
            if (!strcmp(user_data, "mips")){
                // fprintf(stderr, "MIPS-----------\n");
                if (addr & 2){
                    uint64_t lr;
                    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_LR], &lr);
                    uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &lr);
                    // err = uc_mem_write(uc, addr, "\0\0" MAP_MIPS_CODE_CONTENT, 6);
                    // if (err != UC_ERR_OK){
                    //     raiseCrashSignal(uc, err);
                    // }
                } else {
                    if (endian == UF_ENDIAN_BIG) {
                        err = uc_mem_write(uc, addr, MAP_MIPS_CODEBE_CONTENT, 4);
                        if (err != UC_ERR_OK){
                            raiseCrashSignal(uc, err);
                        }
                    }else{
                        err = uc_mem_write(uc, addr, MAP_MIPS_CODE_CONTENT, 4);
                        if (err != UC_ERR_OK){
                            raiseCrashSignal(uc, err);
                        }
                    }
                }
            }
            else if (!strcmp(user_data, "arm")){
                // fprintf(stderr, "ARM-----------\n");
                if (addr & 2){
                    uint64_t lr;
                    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_LR], &lr);
                    uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &lr);
                } else {
                    if (endian == UF_ENDIAN_BIG){
                        err = uc_mem_write(uc, addr, MAP_ARM_CODEBE_CONTENT, 4);
                        if (err != UC_ERR_OK){
                            raiseCrashSignal(uc, err);
                        }
                    } else {
                        err = uc_mem_write(uc, addr, MAP_ARM_CODE_CONTENT, 4);
                        if (err != UC_ERR_OK){
                            raiseCrashSignal(uc, err);
                        }
                    }
                }
            }
        } else if (addr>=0x100000000-4){
            err = uc_mem_write(uc, addr, MAP_OTHER_CONTENT, 0x100000000-addr);
            if (err != UC_ERR_OK){
                raiseCrashSignal(uc, err);
            }
        }
        else{
            err = uc_mem_write(uc, addr, MAP_OTHER_CONTENT, 4);
            if (err != UC_ERR_OK){
                raiseCrashSignal(uc, err);
            }
        }
    }
    return 1;
}



uint32_t setaddr[0x40],getaddr[0x40],setargidx[0x40],getargidx[0x40];
uint32_t connect_cnt=0;
uint32_t connect_reg=0;
void connect_get_hook(uc_engine* uc){
    uc_reg_write(uc, uf_conv_regs[arch][UF_REG_RV], &connect_reg);
}
void connect(uc_engine* uc){
    uint32_t pc, i;
    uint32_t get_addrs[0x40] = {0};
    uint32_t get_addrs_cnt = 0;
    uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
    uf_debug("connect called at 0x%08x\n", pc);
    uf_debug("Let's decide whether way to go~!\n");
    for (i=0; i<connect_cnt; i++){
        if (setaddr[i] == pc){
            get_addrs[get_addrs_cnt++] = i;
        }
    }
    int choice = random()%(get_addrs_cnt+1);
    uf_debug("choice: %d with mod %d\n", choice, get_addrs_cnt + 1);
    if (choice == 0){
        //just nop the function call
        // TODO: randomlly switch to different get func sharing same key
        uf_debug("nop set func\n");
        pc += 4;
        uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
        return ;
    } else {
        i = get_addrs[choice-1];
        uf_debug("jump to get func 0x%08x\n", getaddr[i]);
        // getaddr[i]+=4;
        pc = getaddr[i];
        pc += 4;
        if (arch==UF_ARCH_MIPS){
            pc += 4;
            uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
        }
        else
            uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
        uint32_t setargval;
        switch (setargidx[i])
        {
            case 1:
                uc_reg_read(uc, uf_conv_regs[arch][UF_REG_A0], &setargval);
                break;
            case 2:
                uc_reg_read(uc, uf_conv_regs[arch][UF_REG_A1], &setargval);
                break;
            case 3:
                uc_reg_read(uc, uf_conv_regs[arch][UF_REG_A2], &setargval);
                break;
            case 4:
                uc_reg_read(uc, uf_conv_regs[arch][UF_REG_A3], &setargval);
                break;
            default:
                fprintf(stderr, "set arg index out of range: %d", setargidx[i]);
                raiseCrashSignal(uc,UC_ERR_ARG);
        }
        connect_reg = setargval;
        switch (getargidx[i])
        {
            case 0:
                uc_reg_write(uc, uf_conv_regs[arch][UF_REG_RV], &setargval);
                break;
            case 1:
                uc_reg_write(uc, uf_conv_regs[arch][UF_REG_A0], &setargval);
                break;
            case 2:
                uc_reg_write(uc, uf_conv_regs[arch][UF_REG_A1], &setargval);
                break;
            case 3:
                uc_reg_write(uc, uf_conv_regs[arch][UF_REG_A2], &setargval);
                break;
            case 4:
                uc_reg_write(uc, uf_conv_regs[arch][UF_REG_A3], &setargval);
                break;
            default:
                fprintf(stderr, "get arg index out of range: %d", getargidx[i]);
                raiseCrashSignal(uc,UC_ERR_ARG);
        }
        uf_debug("connect from 0x%08x(arg:%d) to 0x%08x(arg:%d) success, argval: %08x\n", setaddr[i], setargidx[i], getaddr[i], getargidx[i], setargval);
    }
}

void cbranch_norm_hook_mips_1(uc_engine* uc){
    // condition not suffice
    uint32_t pc;
    if (arch != UF_ARCH_MIPS){
        fprintf(stderr, "not supported arch\n");
        raiseCrashSignal(uc, UC_ERR_ARCH);
    }
    uc_reg_read(uc, UC_MIPS_REG_PC, &pc);
    pc = pc+4;
    uf_debug("MIPS at 0x%08x branch 1 new_pc = pc+8 = 0x%08x\n", pc-8, pc);
    uc_reg_write(uc, UC_MIPS_REG_PC, &pc);
}
void cbranch_norm_hook_mips_2(uc_engine* uc){
    uint32_t new_pc=0, pc;
    if (arch != UF_ARCH_MIPS){
        fprintf(stderr, "not supported arch\n");
        raiseCrashSignal(uc, UC_ERR_ARCH);
    }
    uc_reg_read(uc, UC_MIPS_REG_PC, &pc);
    if (endian == UF_ENDIAN_LITTLE){
        uc_mem_read(uc, pc, &new_pc, 2);
    }
    if (endian == UF_ENDIAN_BIG){
        fprintf(stderr, "Untest cbranch_norm_hook_mips_2!\n");
        uc_mem_read(uc, pc+2, &new_pc, 2);
        new_pc = ((new_pc & 0xff)<<8) || ((new_pc & 0xff00)>>8);
    }
    new_pc *= 4;
    if (new_pc & 0x8000){
        new_pc |= 0xffff0000;
    }
    new_pc = pc + new_pc + 4;
    new_pc -= 4;  // since we hook at real branch instr + 4
    new_pc = (new_pc & 0xffff) | (pc & 0xffff0000);
    uf_debug( "MIPS at 0x%08x branch 2 new_pc = 0x%x\n", pc-4, new_pc);
    uc_reg_write(uc, UC_MIPS_REG_PC, &new_pc);
}
void cbranch_norm_hook_arm(uc_engine* uc){
    uint32_t jmp_dir = random();
#ifdef UF_DEBUG
    uint32_t pc;
    uc_err err;
    if ((err = uc_reg_read(uc, UC_ARM_REG_PC, &pc))!=UC_ERR_OK){
        raiseCrashSignal(uc, err);
    }
    uf_debug("arm cbranch pc 0x%08x jmp_dir %d\n", pc, jmp_dir);
#endif
    if (arch != UF_ARCH_ARM){
        fprintf(stderr, "not supported arch\n");
        raiseCrashSignal(uc, UC_ERR_ARCH);
    }
    if (jmp_dir & 1){
        uint32_t cpsr;
        uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);
        cpsr &= 0x0fffffff;
        uc_reg_write(uc, UC_ARM_REG_CPSR, &cpsr);
    } else {
        uint32_t cpsr;
        uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);
        cpsr |= 0xf0000000;
        uc_reg_write(uc, UC_ARM_REG_CPSR, &cpsr);
    }
}

void cbranch_movn_handle(uc_engine* uc, uint64_t pc){
    uc_err err;
    uint32_t jmp_dir = random();
    uint32_t code = 0;
    if ((err = uc_mem_read(uc, pc, &code, 4))!=UC_ERR_OK){
        raiseCrashSignal(uc, err);
    }
    uf_debug("movn patch @ 0x%08lx, code 0x%08x to ", pc, code);
    // change "movn reg1, reg2, reg3" to "movn reg1, reg2, zero" or "movz reg1, reg2, zero"
    if (jmp_dir & 1){
        if (endian == UF_ENDIAN_LITTLE){
            code = ((code & 0b11111111111111111111111100000000) | 0b00001011) & 0xffe0ffff;
        }   
        else{
            fprintf(stderr, "Untest cbranch_movn_handle1!\n");
            code = ((code & 0b00000000111111111111111111111111) | 0b00001011111111111111111111111111) & 0xffffe0ff;
        }
    } else {
        if (endian == UF_ENDIAN_LITTLE){
            code = ((code & 0b11111111111111111111111100000000) | 0b00001010) & 0xffe0ffff;
        }   
        else{
            fprintf(stderr, "Untest cbranch_movn_handle2!\n");
            code = ((code & 0b00000000111111111111111111111111) | 0b00001010111111111111111111111111) & 0xffffe0ff;
        }
    }
    uf_debug("code 0x%08x\n",code);
    if ((err = uc_mem_write(uc, pc, &code, 4))!=UC_ERR_OK){
        raiseCrashSignal(uc, err);
    }

}
#define CBRANCH_FILE_MAXSIZE 0x2000
char cbranch_norm_file[CBRANCH_FILE_MAXSIZE];
char cbranch_movn_file[CBRANCH_FILE_MAXSIZE];
int init_cbranch_randomization(uc_engine *uc){
    // this function is executed before fork()
        
    if (getenv("UF_PATCHJMP")){
        if (!strcmp(getenv("UF_PATCHJMP"), "no")){
            uf_debug("init_cbranch_randomization: return due to environment UF_PATCHJMP set to %s\n",getenv("UF_PATCHJMP"));
            return 0;
        }
        if (!strcmp(getenv("UF_PATCHJMP"), "NO")){
            uf_debug("init_cbranch_randomization: return due to environment UF_PATCHJMP set to %s\n",getenv("UF_PATCHJMP"));
            return 0;
        }
    }

    int cbranch_norm_fd = open("workdir/cbranch_info_norm", O_RDONLY);
    if (cbranch_norm_fd<0) {
        uf_debug("init_cbranch_randomization: cbranch_info_norm file not found\n");
        return 0;
    }
    struct stat st;
    stat("workdir/cbranch_info_norm", &st);
    if (st.st_size > CBRANCH_FILE_MAXSIZE){
        fprintf(stderr, "init_cbranch_randomization: cbranch_info_norm file size(0x%lx) exceed, > max size 0x%x", st.st_size, CBRANCH_FILE_MAXSIZE);
        return -1;
    }
    if (st.st_size && (read(cbranch_norm_fd, cbranch_norm_file, st.st_size)!=st.st_size)){
        perror("read");
        return -1;
    }
    close(cbranch_norm_fd);

    if (arch == UF_ARCH_MIPS){
        int cbranch_movn_fd = open("workdir/cbranch_info_movn", O_RDONLY);
        if (cbranch_movn_fd<0) {
            uf_debug("init_cbranch_randomization: cbranch_info_movn file not found\n");
            return 0;
        }
        stat("workdir/cbranch_info_movn", &st);
        if (st.st_size > CBRANCH_FILE_MAXSIZE){
            fprintf(stderr, "init_cbranch_randomization: cbranch_info_norm file size(0x%lx) exceed, > max size 0x%x", st.st_size, CBRANCH_FILE_MAXSIZE);
            return -1;
        }
        if (st.st_size && (read(cbranch_movn_fd, cbranch_movn_file, st.st_size)!=st.st_size)){
            perror("read");
            return -1;
        }
        close(cbranch_movn_fd);
    }
    return 0;
}
int judge_branch_likely(uint8_t* code){
    uint8_t byt1, byt2;
    if (endian == UF_ENDIAN_LITTLE){
        byt1 = code[3];
        byt2 = code[2];
    }
    else{
        fprintf(stderr, "Untest judge_branch_likely!\n");
        byt1 = code[0];
        byt2 = code[1];
    }
    byt1 &= 0b11111100;
    if (byt1 == 0x50 || byt1 == 0x5c || byt1 == 0x54 || byt1 == 0x58){ // BEQL, BGTZL, BNEL, BLEZL
        return 1;
    }
    byt2 &= 0b00011111;
    if (byt1 == 0b00000100 && ((byt2 == 0b10000) || (byt2 == 0b10001))){ // BLTZAL, BGEZAL, BGEZAL
        return 1;
    }
    return 0;
}
int deploy_cbranch_randomization(uc_engine* uc){
    // this function is executed after fork()
        
    if (getenv("UF_PATCHJMP")){
        if (!strcmp(getenv("UF_PATCHJMP"), "no")){
            uf_debug("deploy_cbranch_randomization: return due to environment UF_PATCHJMP set to %s\n",getenv("UF_PATCHJMP"));
            return 0;
        }
        if (!strcmp(getenv("UF_PATCHJMP"), "NO")){
            uf_debug("deploy_cbranch_randomization: return due to environment UF_PATCHJMP set to %s\n",getenv("UF_PATCHJMP"));
            return 0;
        }
    }

    char * line = cbranch_norm_file;
    char * info = cbranch_norm_file;
    
    uint32_t cbranch_norm_addr;
    uc_err err;
    uc_hook hh;
    uint8_t codes[8]={0};
    
    if (!cbranch_norm_file[0]) {
        uf_debug("cbranch_norm_file not found\n");
    }
    else {
        while ((line = strchr(line, '\n'))){
            line += sizeof(uint8_t);
            cbranch_norm_addr = strtoul(info, NULL, 16);
            if (arch == UF_ARCH_MIPS){
                if (random() & 1){
                    // NOP the b instr
                    if ((err = uc_mem_read(uc, cbranch_norm_addr, codes, 8))!= UC_ERR_OK){
                        raiseCrashSignal(uc, err);
                    }
                    uf_debug("judege_branch_likely: pc 0x%08x return %d\n", cbranch_norm_addr, judge_branch_likely(codes));
                    if (judge_branch_likely(codes)){
                        uc_mem_write(uc, cbranch_norm_addr, "\0\0\0\0", 4);
                        uc_hook_add(uc, &hh, UC_HOOK_CODE, cbranch_norm_hook_mips_1, NULL, cbranch_norm_addr + 4, cbranch_norm_addr + 4);
                    }
                    else{
                        uc_mem_write(uc, cbranch_norm_addr, &codes[4], 4);
                        uc_hook_add(uc, &hh, UC_HOOK_CODE, cbranch_norm_hook_mips_1, NULL, cbranch_norm_addr + 4, cbranch_norm_addr + 4);
                    }                
                }
                else{
                    if ((err = uc_mem_read(uc, cbranch_norm_addr, codes, 8))!= UC_ERR_OK){
                        raiseCrashSignal(uc, err);
                    }
                    uc_mem_write(uc, cbranch_norm_addr, &codes[4], 4);
                    uc_mem_write(uc, cbranch_norm_addr+4, codes, 4);
                    uc_hook_add(uc, &hh, UC_HOOK_CODE, cbranch_norm_hook_mips_2, NULL, cbranch_norm_addr + 4, cbranch_norm_addr + 4);

                }
            } else if (arch == UF_ARCH_ARM){
                uf_debug("deploying randomization @ 0x%08x\n", cbranch_norm_addr);
                if ((err = uc_hook_add(uc, &hh, UC_HOOK_CODE, cbranch_norm_hook_arm, NULL, cbranch_norm_addr, cbranch_norm_addr))!=UC_ERR_OK){
                    raiseCrashSignal(uc, err);
                }
            }
            info = line;
        }
    }

    if (!cbranch_movn_file[0]){
        if (arch == UF_ARCH_MIPS){
            uf_debug("cbranch_movn_file not found\n");
        }
    }
    else {
        line = info = cbranch_movn_file;
        uint32_t cbranch_movn_addr;
        while ((line = strchr(line,'\n'))){
            line += sizeof(uint8_t);
            cbranch_movn_addr = strtoul(info, NULL, 16);
            uf_debug("cbranch_movn_addr 0x%08x\n",cbranch_movn_addr);
            cbranch_movn_handle(uc, cbranch_movn_addr);
            info = line;
        }
    }
    return 0;

}

int deploy_set_get_connect(uc_engine* uc){
    int connect_fd = open("workdir/connect", O_RDONLY);
    if (connect_fd<0) {uf_debug("deploy_set_get_connect: connect file not found\n");return 0;}
    struct stat st;
    stat("workdir/connect", &st);
    char * connect_file = (char*)mmap(NULL, st.st_size, PROT_READ|PROT_WRITE , MAP_PRIVATE, connect_fd, 0);
    if (connect_file==MAP_FAILED){
        perror("mmap");
        return -1;
    }
    char * line = connect_file;
    char * info = connect_file;
    uint32_t last_setaddr;
    uc_err err;
    uc_hook hh;
    connect_cnt = 0;
    last_setaddr = 0;
    while ((line = strchr(line, '\n'))){
        // each line will follow format like: setaddr getaddr setargidx getargidx
        *line = '\0';
        line += sizeof(uint8_t);

        setaddr[connect_cnt] = strtoul(info,NULL,16);
        info = strchr(info, ' ');
        if (!info) return -1;
        getaddr[connect_cnt] = strtoul(++info,NULL,16);
        info = strchr(info, ' ');
        if (!info) return -1;
        setargidx[connect_cnt] = atoi(++info);
        info = strchr(info, ' ');
        if (!info) return -1;
        getargidx[connect_cnt] = atoi(++info);
        if (arch==UF_ARCH_MIPS){
            char codes[8]={0};
            if ((err = uc_mem_read(uc, setaddr[connect_cnt]+4, codes, 4))!=UC_ERR_OK){
                raiseCrashSignal(uc, err);
            }
            if ((err = uc_mem_write(uc, setaddr[connect_cnt], codes, 4))!=UC_ERR_OK){
                raiseCrashSignal(uc, err);
            }
            setaddr[connect_cnt] += 4;
            if (setaddr[connect_cnt] == last_setaddr){
                uf_debug("detect multiple connect hook at 0x%08x\n", setaddr[connect_cnt]);    
            } else {
                last_setaddr = setaddr[connect_cnt];
                uf_debug("add connect hook at 0x%08x\n", setaddr[connect_cnt]);
                if ((err = uc_hook_add(uc, &hh, UC_HOOK_CODE, connect, NULL, setaddr[connect_cnt], setaddr[connect_cnt]))!=UC_ERR_OK){
                    raiseCrashSignal(uc, err);
                }
            }
            uc_mem_write(uc, getaddr[connect_cnt], "\0\0\0\0\0\0\0\0", 8);
            if ((err = uc_hook_add(uc, &hh, UC_HOOK_CODE, connect_get_hook, NULL, getaddr[connect_cnt], getaddr[connect_cnt]))!=UC_ERR_OK){
                raiseCrashSignal(uc, err);
            }
        }
        else{
            if (setaddr[connect_cnt] == last_setaddr){
                uf_debug("detect multiple connect hook at 0x%08x\n", setaddr[connect_cnt]);    
            } else {
                last_setaddr = setaddr[connect_cnt];
                uf_debug("add connect hook at 0x%08x\n", setaddr[connect_cnt]);
                if ((err = uc_hook_add(uc, &hh, UC_HOOK_CODE, connect, NULL, setaddr[connect_cnt], setaddr[connect_cnt]))!=UC_ERR_OK){
                    raiseCrashSignal(uc, err);
                }
            }
            if (endian == UF_ENDIAN_LITTLE)
                uc_mem_write(uc, getaddr[connect_cnt], "\x00\xf0 \xe3", 4);
            else
                uc_mem_write(uc, getaddr[connect_cnt], "\xe3 \xf0\x00", 4);
            if ((err = uc_hook_add(uc, &hh, UC_HOOK_CODE, connect_get_hook, NULL, setaddr[connect_cnt], setaddr[connect_cnt]))!=UC_ERR_OK){
                raiseCrashSignal(uc, err);
            }

        }

        connect_cnt += 1;
        info = line;
    }
    if (munmap(connect_file, st.st_size)){
        perror("munmap");
        return -1;
    }
    close(connect_fd);
    return 0;

}

int deploy_stack_retaddr(uint32_t sp, uc_engine* uc){
    int stack_retfile = open("workdir/stack_retaddr", O_RDONLY);
    if (stack_retfile<0){
        fprintf(stderr, "stack retaddr file not found, pass.\n");
        return 0;
    }
    struct stat st;
    stat("workdir/stack_retaddr", &st);
    char * stack_file = (char*)mmap(NULL, st.st_size, PROT_READ|PROT_WRITE , MAP_PRIVATE, stack_retfile, 0);
    if (stack_file==MAP_FAILED){
        perror("mmap");
        return -1;
    }
    char * line = stack_file;
    char * info = stack_file;
    uint32_t offset;
    uint32_t count;
    uint32_t i=0;
    while ((line = strchr(line, '\n'))){
        // each line will follow format like: offset
        *line = '\0';
        line += sizeof(uint8_t);
        count = 0;
        do{
            offset = atoi(info);    
            stack_call_trace[i][++count]=offset;
            info+=sizeof(char);
        }while ((info = strchr(info,' '))!=NULL);
        stack_call_trace[i][0] = count;
        info = line;
        i+=1;
    }
    stack_call_trace_cnt = i;
#ifdef UF_DEBUG
    fprintf(stderr, "stack offset file loaded: [\n");
    for (uint32_t j=0;j<stack_call_trace_cnt;j++){
        fprintf(stderr, "\t[");
        for (uint32_t i=0;i<stack_call_trace[j][0]-1;i++){
            fprintf(stderr, "0x%x, ", stack_call_trace[j][i+1]);
        }
        fprintf(stderr, "0x%x]\n",stack_call_trace[j][stack_call_trace[j][0]]);
    }
    fprintf(stderr, "]\n");
#endif    
    uint32_t reg, end_addr = END_ADDR;
    for (i=0;i<stack_call_trace_cnt; i++){
        reg = sp;
        if (stack_call_trace[i][0]>1){
            reg += stack_call_trace[i][stack_call_trace[i][0]]-stack_call_trace[i][stack_call_trace[i][0]-1];
            if (arch == UF_ARCH_ARM){
                reg -= 8;
            }
            if (arch == UF_ARCH_MIPS){
                reg -= 4;
            }
            uf_debug("Deploying init ret addr @ sp+0x%x(0x%08x)\n", stack_call_trace[i][stack_call_trace[i][0]]-stack_call_trace[i][stack_call_trace[i][0]-1], reg);
        }
        else{
            reg+=stack_call_trace[i][stack_call_trace[i][0]];
            uf_debug("Deploying init ret addr @ sp+0x%x(0x%08x)\n", stack_call_trace[i][stack_call_trace[i][0]], reg);
        }
        if (endian == UF_ENDIAN_BIG){
            end_addr = ((end_addr & 0xff000000)>>24) | ((end_addr & 0xff0000)>>8) | ((end_addr & 0xff00)<<8) | ((end_addr & 0xff)<<24);
        }
        uc_mem_write(uc, reg, &end_addr, 4);
    }

    if (munmap(stack_file, st.st_size)){
        perror("munmap");
        return -1;
    }
    close(stack_retfile);
    return 0;
}

#define SIMPLECHECK 0

void checkStackRet(uc_engine *uc){
    uint32_t pc=-1;
    uint32_t sp, log_pc;
    uf_debug("checkStackRet get called with strategy %d(SIMPLECHECK %s)\n", SIMPLECHECK, (SIMPLECHECK)?"enable":"disable");
    if (SIMPLECHECK){
        // Jan2 update: Directly raisecrashsignal
        start_detect = 1;
simplecheck:
        if (random()%2==0 && inject_len>=0x40){
            // raise crash
            uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc);
            fprintf(stderr, "detect buffer overflow at 0x%08x\n", pc);
            raiseCrashSignal(uc, UC_ERR_FETCH_UNMAPPED);
        }
            
        start_detect = 0;
    } else {
        uc_err err;
        start_detect = 1;
        if ((err = uc_reg_read(uc, uf_conv_regs[arch][UF_REG_PC], &pc)) != UC_ERR_OK){
            fprintf(stderr, "FATAL: Unable to read pc in checkStackRet.\n");
        }
        uf_debug("Program reach checkpoint @ 0x%08x\n", pc);
        uint32_t end_addr_idx; 
        for (end_addr_idx=0; end_addr_idx<end_count_classB; end_addr_idx++){
            if (end_addrs_classB[end_addr_idx]==pc){
                uf_debug("found end_address classB[%d]\n", end_addr_idx);
                goto simplecheck;
            }
        }
        for (end_addr_idx=0; end_addr_idx<end_count; end_addr_idx++){
            if (end_addrs[end_addr_idx]==pc){
                uf_debug("found end_address[%d]\n", end_addr_idx);
                break;
            }
        }
        
        log_pc = pc;
        if ((err = uc_reg_read(uc, uf_conv_regs[arch][UF_REG_SP], &sp)) != UC_ERR_OK){
            fprintf(stderr, "FATAL: Unable to read sp in checkStackRet.\n");
            raiseCrashSignal(uc, err);
        }
        for (int i=0;i<stack_call_trace[end_addr_idx][0]; i++){
            if ((err = uc_mem_read(uc, sp+stack_call_trace[end_addr_idx][i+1], &pc, 4)) != UC_ERR_OK){
                fprintf(stderr, "unable to read stack in checkStackRet.\n");
                raiseCrashSignal(uc, err);
            }
            if (endian == UF_ENDIAN_BIG){
                pc = ((pc & 0xff000000)>>24) | ((pc & 0xff0000)>>8) | ((pc & 0xff00)<<8) | ((pc & 0xff)<<24);
            }
            uf_debug("checking [%d(sp+0x%04x, 0x%08x)]: 0x%08x stored on stack...\n", i, stack_call_trace[end_addr_idx][i+1], sp+stack_call_trace[end_addr_idx][i+1], pc);
            uf_debug("image range: 0x%08x-0x%08x, initial sp 0x%08x, current sp 0x%08x\n",start_addr_global, start_addr_global+image_size_global, (uint32_t)(stackTop+STACK_SIZE - 0x8000), sp);
            // we only check the ret addr is readable (since stack overflow will mostly cause this addr become unreadable)
            if (pc != END_ADDR && pc != 0){
                if (pc<start_addr_global || pc>start_addr_global+image_size_global){
                    // raise crash
                    fprintf(stderr, "unable to exec from ret addr 0x%08x on stack at 0x%08x\n", pc, log_pc);
                    raiseCrashSignal(uc, UC_ERR_FETCH_UNMAPPED);
                }
            }
        }
        uf_debug("All stack ret value check pass!\n");
        start_detect = 0;
    }
}

void findRegsAndChangeValue(uc_engine*uc, uint32_t regval){
    // arm: R4-R11
    // mips: S0-S7,FP
    uf_debug("findRegsAndChangeValue begins\n");
    uint32_t reg;
    if (arch == UF_ARCH_ARM){
        uc_reg_read(uc, UC_ARM_REG_R4, &reg);
        if (reg == regval){
            uf_debug("changing arm reg r4\n");
            uc_reg_write(uc, UC_ARM_REG_R4, &dataAddr);
        }
        uc_reg_read(uc, UC_ARM_REG_R5, &reg);
        if (reg == regval){
            uf_debug("changing arm reg r5\n");
            uc_reg_write(uc, UC_ARM_REG_R5, &dataAddr);
        }
        uc_reg_read(uc, UC_ARM_REG_R6, &reg);
        if (reg == regval){
            uf_debug("changing arm reg r6\n");
            uc_reg_write(uc, UC_ARM_REG_R6, &dataAddr);
        }
        uc_reg_read(uc, UC_ARM_REG_R7, &reg);
        if (reg == regval){
            uf_debug("changing arm reg r7\n");
            uc_reg_write(uc, UC_ARM_REG_R7, &dataAddr);
        }
        uc_reg_read(uc, UC_ARM_REG_R8, &reg);
        if (reg == regval){
            uf_debug("changing arm reg r8\n");
            uc_reg_write(uc, UC_ARM_REG_R8, &dataAddr);
        }
        uc_reg_read(uc, UC_ARM_REG_R9, &reg);
        if (reg == regval){
            uf_debug("changing arm reg r9\n");
            uc_reg_write(uc, UC_ARM_REG_R9, &dataAddr);
        }
        uc_reg_read(uc, UC_ARM_REG_R10, &reg);
        if (reg == regval){
            uf_debug("changing arm reg r10\n");
            uc_reg_write(uc, UC_ARM_REG_R10, &dataAddr);
        }
        uc_reg_read(uc, UC_ARM_REG_R11, &reg);
        uf_debug("R11: 0x%08x\n", reg);
        if (reg == regval){
            uf_debug("changing arm reg r11\n");
            uc_reg_write(uc, UC_ARM_REG_R11, &dataAddr);
        }
    }
    else if (arch == UF_ARCH_MIPS){
        uc_reg_read(uc, UC_MIPS_REG_S0, &reg);
        if (reg == regval){
            uf_debug("changing mips reg s0\n");
            uc_reg_write(uc, UC_MIPS_REG_S0, &dataAddr);
        }
        uc_reg_read(uc, UC_MIPS_REG_S1, &reg);
        if (reg == regval){
            uf_debug("changing mips reg s1\n");
            uc_reg_write(uc, UC_MIPS_REG_S1, &dataAddr);
        }
        uc_reg_read(uc, UC_MIPS_REG_S2, &reg);
        if (reg == regval){
            uf_debug("changing mips reg s2\n");
            uc_reg_write(uc, UC_MIPS_REG_S2, &dataAddr);
        }
        uc_reg_read(uc, UC_MIPS_REG_S3, &reg);
        if (reg == regval){
            uf_debug("changing mips reg s3\n");
            uc_reg_write(uc, UC_MIPS_REG_S3, &dataAddr);
        }
        uc_reg_read(uc, UC_MIPS_REG_S4, &reg);
        if (reg == regval){
            uf_debug("changing mips reg s4\n");
            uc_reg_write(uc, UC_MIPS_REG_S4, &dataAddr);
        }
        uc_reg_read(uc, UC_MIPS_REG_S5, &reg);
        if (reg == regval){
            uf_debug("changing mips reg s5\n");
            uc_reg_write(uc, UC_MIPS_REG_S5, &dataAddr);
        }
        uc_reg_read(uc, UC_MIPS_REG_S6, &reg);
        if (reg == regval){
            uf_debug("changing mips reg s6\n");
            uc_reg_write(uc, UC_MIPS_REG_S6, &dataAddr);
        }
        uc_reg_read(uc, UC_MIPS_REG_S7, &reg);
        if (reg == regval){
            uf_debug("changing mips reg s7\n");
            uc_reg_write(uc, UC_MIPS_REG_S7, &dataAddr);
        }
        uc_reg_read(uc, UC_MIPS_REG_FP, &reg);
        if (reg == regval){
            uf_debug("changing mips reg fp\n");
            uc_reg_write(uc, UC_MIPS_REG_FP, &dataAddr);
        }
    }

}

void inject_data(uc_engine *uc, uint32_t addr){
    uf_debug("inject_data get called!\n");
    has_injected = 1;
    
    // some case need to be specially treated
    // if (strstr(getenv("UF_TARGET"), "20030_SP221")){
    //     uint32_t sp;
    //     uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    //     uc_mem_write(uc, sp, &dataAddr, 4);
    //     uf_debug("20030_SP221 special injection\n");
    //     return ;
    // }

    uint32_t pc;
    uc_err err;
    if (arch == UF_ARCH_MIPS){
        pc = addr+8;
        if ((err=uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &pc))!=UC_ERR_OK){
            fprintf(stderr, "Failed to write new pc data\n");
            raiseCrashSignal(uc, err);
        }
    }
    else if (arch == UF_ARCH_ARM){
        pc = addr+4;
        if ((err=uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &pc))!=UC_ERR_OK){
            fprintf(stderr, "Failed to write new pc data\n");
            raiseCrashSignal(uc, err);
        }
    }
    if (inject_idx == 0xffffffff){
        fprintf(stderr, "Inject info not initialized. Abort.\n");
        flushlogger();
        exit(-1);
    }

    // a fix for following driller tracer analysis: since driller will hook address here and this may bring desync situation, so we manually add trace log here
    if (traceLogger) {fprintf(traceLogger, "0x%08x\n", pc-4);}

    uint32_t regval=0;
    uf_debug("inject_idx: %d, instruction address 0x%08x\n", inject_idx, addr);
    switch (inject_idx){
        case 0: 
            uf_debug("Writing to return value register\n");
            if ((err=uc_reg_write(uc, uf_conv_regs[arch][UF_REG_RV], &dataAddr))!=UC_ERR_OK){
                fprintf(stderr, "Failed to write fuzzing data to target register\n");
                raiseCrashSignal(uc, err);
            }
            return;
        case 1:
            if ((err=uc_reg_read(uc, uf_conv_regs[arch][UF_REG_A0], &regval))!=UC_ERR_OK){
                fprintf(stderr, "Failed to read reg value.\n");
                raiseCrashSignal(uc, err);
            }
            break;
        case 2:
            if ((err=uc_reg_read(uc, uf_conv_regs[arch][UF_REG_A1], &regval))!=UC_ERR_OK){
                fprintf(stderr, "Failed to read reg value.\n");
                raiseCrashSignal(uc, err);
            }
            break;
        case 3:
            if ((err=uc_reg_read(uc, uf_conv_regs[arch][UF_REG_A2], &regval))!=UC_ERR_OK){
                fprintf(stderr, "Failed to read reg value.\n");
                raiseCrashSignal(uc, err);
            }
            break;
        case 4:
            if ((err=uc_reg_read(uc, uf_conv_regs[arch][UF_REG_A3], &regval))!=UC_ERR_OK){
                fprintf(stderr, "Failed to read reg value.\n");
                raiseCrashSignal(uc, err);
            }
            break;
        default: 
            fprintf(stderr, "Inject info is insane. Abort.\n"); 
            return;
    }
    // if (regval == 0 && strstr(getenv("UF_TARGET"), "R8500")){
    //     uint32_t sp_tmp;
    //     uc_reg_read(uc, uf_conv_regs[arch][UF_REG_SP], &sp_tmp);
    //     regval = sp_tmp+0x3c;
    //     uc_mem_write(uc, sp_tmp+0x2128-0x2104, &regval, sizeof(regval));
    // } 
    // if (regval == 0 && strstr(getenv("UF_TARGET"), "AC18")){
    //     uint32_t sp_tmp;
    //     uc_reg_read(uc, uf_conv_regs[arch][UF_REG_SP], &sp_tmp);
    //     regval = sp_tmp+0x3c;
    //     uc_mem_write(uc, sp_tmp+0x2128-0x2104, &regval, sizeof(regval));
    // } 
    // if (regval == 0 && strstr(getenv("UF_TARGET"), "AC15")){
    //     uint32_t sp_tmp;
    //     uc_reg_read(uc, uf_conv_regs[arch][UF_REG_SP], &sp_tmp);
    //     regval = sp_tmp+0x3c;
    //     uc_mem_write(uc, sp_tmp+0x2128-0x2104, &regval, sizeof(regval));
    // } 
    // if (regval == 0 && strstr(getenv("UF_TARGET"), "W20E")){
    //     uint32_t sp_tmp;
    //     uc_reg_read(uc, uf_conv_regs[arch][UF_REG_SP], &sp_tmp);
    //     regval = sp_tmp+0x3c;
    //     uc_mem_write(uc, sp_tmp+0x2128-0x2104, &regval, sizeof(regval));
    // } 
    // if (regval == 0 && strstr(getenv("UF_TARGET"), "R6400")){
    //     uint32_t sp_tmp;
    //     uc_reg_read(uc, uf_conv_regs[arch][UF_REG_SP], &sp_tmp);
    //     regval = sp_tmp+0x3c;
    //     uc_mem_write(uc, sp_tmp+0x2128-0x2104, &regval, sizeof(regval));
    // } 
    // if (regval == 0 && strstr(getenv("UF_TARGET"), "R7000")){
    //     uint32_t sp_tmp;
    //     uc_reg_read(uc, uf_conv_regs[arch][UF_REG_SP], &sp_tmp);
    //     regval = sp_tmp+0x3c;
    //     uc_mem_write(uc, sp_tmp+0x2128-0x2104, &regval, sizeof(regval));
    // } 
    // if (regval == 0 && strstr(getenv("UF_TARGET"), "XR300")){
    //     uint32_t sp_tmp;
    //     uc_reg_read(uc, uf_conv_regs[arch][UF_REG_SP], &sp_tmp);
    //     regval = sp_tmp+0x3c;
    //     uc_mem_write(uc, sp_tmp+0x2128-0x2104, &regval, sizeof(regval));
    // } 
    if (regval < 0x10000 ){
        uf_debug("detect too small address 0x%08x, find and change all possible reg value to dataAddr...\n", regval);
        findRegsAndChangeValue(uc, regval);
        uc_reg_write(uc, uf_conv_regs[arch][UF_REG_A3], &dataAddr);
    } else {
        uf_debug("Writing to address 0x%08x\n", regval);
        if ((err=uc_mem_write(uc, regval, dataAddr, inject_len))!=UC_ERR_OK){
            fprintf(stderr, "Failed to write fuzzing data to target register\n");
            raiseCrashSignal(uc, err);
        }
        if ((err=uc_reg_write(uc, uf_conv_regs[arch][UF_REG_RV], &inject_len))!=UC_ERR_OK){
            fprintf(stderr, "Failed to write fuzzing data to target register\n");
            raiseCrashSignal(uc, err);
        }
    }
}

// callback: setup the env before emulation starts
int uniFuzzerInit(uc_engine *uc, enum uf_arch arch, uint64_t start_addr, char* os, uint64_t inject_addr, uint64_t input_idx, uint64_t input_max_len, uint32_t imagebase, uint32_t imagesize) {
    uc_err err;
    // setup heap area
    if (!strcmp(os,"linux")){
        heapBase = mmap(NULL, HEAP_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
        if(heapBase == MAP_FAILED) {
            perror("mapping heap");
            return -1;
        }
        if(uc_mem_map_ptr(uc, (uint64_t)heapBase, HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE, heapBase) != UC_ERR_OK) {
            fprintf(stderr, "uc mapping heap failed\n");
            return -1;
        }
        uf_debug("heap is at %p\n", heapBase);
    }

    // setup stack area
    stackTop = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if(stackTop == MAP_FAILED) {
        perror("mapping stack");
        return -1;
    }
    if(uc_mem_map_ptr(uc, (uint64_t)stackTop, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE, stackTop) != UC_ERR_OK) {
        fprintf(stderr, "uc mapping stack failed\n");
        return -1;
    }
    uf_debug("stack is at %p\n", stackTop+STACK_SIZE);

    dataAddr = mmap(NULL, DATA_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if(dataAddr == MAP_FAILED) {
        perror("mapping data");
        return -1;
    }
    if(uc_mem_map_ptr(uc, (uint64_t)dataAddr, DATA_SIZE, UC_PROT_READ | UC_PROT_WRITE, dataAddr) != UC_ERR_OK) {
        fprintf(stderr, "uc mapping data failed\n");
        return -1;
    }
    uf_debug("data is at %p\n", dataAddr);

    inject_idx = input_idx;

    // add syscall hook
    uc_hook hook;
    if (!strcmp(os,"linux")){
        uc_hook_add(uc, &hook, UC_HOOK_INTR, hook_syscall, NULL, 1, 0);
    }
    // uc_hook_add(uc, &hook, UC_HOOK_INSN_INVALID, hook_invalidInstr, NULL, 1, 0);

    // dynamic mmap hook
    if (arch == UF_ARCH_ARM)
        uc_hook_add(uc, &hook, UC_HOOK_MEM_UNMAPPED, hook_unmappedmem, strdup("arm"), 1, 0);
    else if (arch == UF_ARCH_MIPS)
        uc_hook_add(uc, &hook, UC_HOOK_MEM_UNMAPPED, hook_unmappedmem, strdup("mips"), 1, 0);

    // uc_hook_add(uc, &hook, UC_HOOK_MEM_PROT, hook_unmappedmem, NULL, 1, 0)  ;

    


    // for the registers and stack ret address deploy
    uint32_t reg;
    reg = (unsigned int)(stackTop+STACK_SIZE - 0x8000);
    if ((err = uc_reg_write(uc, uf_conv_regs[arch][UF_REG_SP], &reg)) != UC_ERR_OK){
        fprintf(stderr, "%s", uc_strerror(err));
        return -1;
    }
    if (deploy_stack_retaddr(reg, uc)){
        fprintf(stderr, "deploy_stack_retaddr failed.\n");
        return -1;
    };
    
    uint32_t end_addr = END_ADDR;
    if (((err = uc_reg_write(uc, uf_conv_regs[arch][UF_REG_LR], &end_addr)) != UC_ERR_OK)){
        // also, write the value to UF_REG_LR
        fprintf(stderr, "Unable to deploy init ret addr value to UF_REG_LR.\n");
        return -1;
    }
    reg += 4;
    if ((err = uc_reg_write(uc, uf_conv_regs[arch][UF_REG_BP], &reg)) != UC_ERR_OK){
        fprintf(stderr, "%s", uc_strerror(err));
        return -1;
    }

    start_addr_global = imagebase;
    image_size_global = imagesize;
    // set start_addr and image_size for ELF testing
    if (strstr(getenv("UF_TARGET"), "R8500_upnpd")){ 
        start_addr_global = 0x10000;
        image_size_global = 0x64000;
    }
    if (strstr(getenv("UF_TARGET"), "AC18_httpd")){
        start_addr_global = 0x10000;
        image_size_global = 0xf2000;
    }
    if (strstr(getenv("UF_TARGET"), "AC15_httpd")){
        start_addr_global = 0x10000;
        image_size_global = 0xf2000;
    }
    if (strstr(getenv("UF_TARGET"), "W20E_httpd")){
        start_addr_global = 0x10000;
        image_size_global = 0xea000;
    }
    if (strstr(getenv("UF_TARGET"), "DIR878_prog.cgi")){
        start_addr_global = 0x400000;
        image_size_global = 0xd7000;
    }
    if (strstr(getenv("UF_TARGET"), "R6400_httpd")){
        start_addr_global = 0x10000;
        image_size_global = 0x18a000;
    }
    if (strstr(getenv("UF_TARGET"), "R6400_httpd")){
        start_addr_global = 0x10000;
        image_size_global = 0x80000;
    }
    if (strstr(getenv("UF_TARGET"), "R7000P_httpd")){
        start_addr_global = 0x10000;
        image_size_global = 0x1b9000;
    }
    if (strstr(getenv("UF_TARGET"), "R7000P_upnpd")){
        start_addr_global = 0x10000;
        image_size_global = 0x55000;
    }
    if (strstr(getenv("UF_TARGET"), "XR300_httpd")){
        start_addr_global = 0x10000;
        image_size_global = 0x20c000;
    }
    if (strstr(getenv("UF_TARGET"), "XR300_upnpd")){
        start_addr_global = 0x10000;
        image_size_global = 0x7d000;
    }
    reg = start_addr;
    if ((err = uc_reg_write(uc, uf_conv_regs[arch][UF_REG_PC], &reg)) != UC_ERR_OK){
        fprintf(stderr, "%s", uc_strerror(err));
        return -1;
    }

    // We dont need it in code fragment fuzzing
    // reg = end_addr;
    // if ((err = uc_reg_write(uc, uf_conv_regs[arch][UF_REG_LR], &reg)) != UC_ERR_OK){
    //     fprintf(stderr, "%s", uc_strerror(err));
    // }

    // Instead, hook this address and directly check the ret value on stack
    uc_hook hh;
    uf_debug("inject data @ 0x%08lx\n",inject_addr);
    if ((err = uc_hook_add(uc, &hh, UC_HOOK_CODE, inject_data, NULL, inject_addr, inject_addr))!=UC_ERR_OK){
        fprintf(stderr, "%s", uc_strerror(err));
        return -1;
    }

    /*
    TODO: need reconstruct code
    we change this code snippet since we dont want avoid_addrs disturb the judge on sink function
           0x000103a0      020053e1       cmp r3, r2
       ,=< 0x000103a4      0400001a       bne 0x103bc
       |   0x000103a8      422f4be2       sub r2, fp, 0x108
       |   0x000103ac      623f4be2       sub r3, fp, 0x188
       |   0x000103b0      0210a0e1       mov r1, r2                  ; const char * src
       |   0x000103b4      0300a0e1       mov r0, r3                  ; char * dest
       |   0x000103b8      a45500eb       bl sym.strcpy               ; char *strcpy(char *dest, const char *src)
       |      ; JMP XREF from 0x000103a4 (main)
       `-> 0x000103bc      0030a0e3       mov r3, 0
           0x000103c0      0300a0e1       mov r0, r3
    if we hook sink addr at 0x000103bc and set 0x000103bc as avoid addr, it will overwrite the sink check hook(since the sink check hook is the 2nd hook added), which is not the result we want
    */
    for (uint32_t i=0;i<end_count;i++){
        uf_debug("add checkStackRet at 0x%08x\n", end_addrs[i]);
        if ((err = uc_hook_add(uc, &hh, UC_HOOK_CODE, checkStackRet, NULL, end_addrs[i], end_addrs[i]))!=UC_ERR_OK){
            fprintf(stderr, "failed to add sink hook at 0x%08x: %s\n", end_addrs[i], uc_strerror(err));
            return -1;
        }
    }

    for (uint32_t i=0;i<exec_end_count;i++){
        uf_debug("add exit emulation hook at exec_end_addr(0x%08x)\n", exec_end_addr[i]);
        if ((err = uc_hook_add(uc, &hh, UC_HOOK_CODE, exitemulation, NULL, exec_end_addr[i], exec_end_addr[i]))!=UC_ERR_OK){
            fprintf(stderr, "failed to add exit emulation hook: %s\n", uc_strerror(err));
            return -1;
        }
    }

    if (init_cbranch_randomization(uc)){
        perror("deploy_cbranch_randomization failed with");
        return -1;
    }
    if (deploy_set_get_connect(uc)){
        perror("deploy_set_get_connect failed with");
        return -1;
    }


    // alloc and save cpu context for restore
    if(uc_context_alloc(uc, &context) != UC_ERR_OK) {
        fprintf(stderr, "uc_context_alloc failed\n");
        return -1;
    }
     
    uc_context_save(uc, context);

    return 0;
}


// callback: invoked before each round of fuzzing(after fork, before fuzzing)
int uniFuzzerBeforeExec(uc_engine *uc, const uint8_t *data, size_t len, const char* os) {
    // filter on input size
    if(len == 0 || len > 0x2000) return 1;

    // reset heap base addr in preload library
    if (!strcmp(os,"linux")){
        *heapBoundaryGOT = (uint32_t)heapBase;
    }

    // restore cpu context
    uc_context_restore(uc, context);

    // copy input to buffer
    inject_len = len;
    memcpy(dataAddr, data, len);

    // uncomment the following line to ignore heap overflow in the function vuln
    // memset((char *)dataAddr+4, 0, 1);

    // uncomment the following line to ignore stack overflow in the function vuln
    // memset(dataAddr, 0x20, 1);

    uint32_t random_seed = 0;

    getrandom((void*)&random_seed, sizeof(random_seed), 0);
    // read(random_fd, &random_seed, 4);

    srand(random_seed);
        // int fd = open("/tmp/randomseed_log", O_WRONLY|O_APPEND);
        // char ss[0x200]={0};
        // sprintf(ss,"random srand with seed 0x%08x\n",random_seed);
        // write(fd, ss, strlen(ss));
        // close(fd);
    deploy_cbranch_randomization(uc);
    return 0;
}

// callback: invoked after each round of fuzzing
int uniFuzzerAfterExec(uc_engine *uc, const char* os) {
    // check all heap allocations to see if there's an overflow
    
    // current boundary for used heap area
    if (!strcmp(os,"linux")){
        uint32_t *boundary = (uint32_t*)*heapBoundaryGOT;

        // start addr for used heap are
        uint32_t *start = (uint32_t*)heapBase;

        size_t chunk_len;
        char *canary;

        // check canary for all chunks
        while(start < boundary) {
            chunk_len = *start;
            canary = (char *)start + chunk_len + 4; // with header

            // overflow
            if(*(uint32_t *)canary != HEAP_CANARY) {
                fprintf(stderr, "heap overflow!\n");
                return 1;
            }

            start = (uint32_t*)((char *)start + chunk_len + 8);
        }
    }
    return 0;
}
