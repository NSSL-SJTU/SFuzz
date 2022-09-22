CC := clang
CFLAGS := -Wno-int-to-pointer-cast 
CFLAGS += -IuniFuzzer/elfLoader
CFLAGS += -fPIE -pie
CFLAGS += -L . -lnvram -Wno-unused-command-line-argument # NVRAM related logic(if needed)
CFLAGS += -O3
CFLAGS += $(UFDBG)
#CFLAGS += -g -DUF_DEBUG
CFLAGS += -DUF_USE_STDIN
LDFLAGS := -lunicorn -pthread -fPIC -pie

OUT := uf
.DEFAULT_GOAL := all

SRC := $(wildcard callback/*.c) \
		$(wildcard uniFuzzer/uniFuzzGo.c) \
		$(wildcard uniFuzzer/elfLoader/*.c)
OBJ := $(SRC:.c=.o)

MAIN_SRC := uniFuzzer/uniFuzzGo.c
MAIN_OBJ := uniFuzzer/uniFuzzGo.o
$(MAIN_OBJ): CFLAGS += -IuniFuzzer/elfLoader

OTHER_SRC := $(filter-out $(MAIN_SRC),$(SRC))
OTHER_OBJ := $(OTHER_SRC:.c=.o)

%.o:%.c
	$(CC) -o $@ $(CFLAGS) -c $<

all:$(OUT)

$(OUT):$(OBJ)
	$(CC) -o $@ $(LDFLAGS) $^

clean:
	-rm -f $(OUT) $(OBJ)
	-rm -f core
	-rm peda-session*
	-rm .gdb_history

.PHONY: all clean

