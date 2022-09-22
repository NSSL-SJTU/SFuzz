#ifndef ELFLOADER_H
#define ELFLOADER_H
#include "common.h"
uc_engine *loadELF(const char *target, char *preload, char *libPath, enum uf_arch arch);
uc_engine *loadRTOS(const char *target, enum uf_arch arch, const char *archstr, uint64_t base_addr, uint32_t* image_base, uint32_t* image_size);
/*
uc_engine *createUE(Elf *elf, int is32bits);
int checkBits(Elf *elf);
setupMem(Elf *elf, uc_engine *uc, int is32bits, uint64_t baseAddr, int fd);
*/

#endif
