CFLAGS  += -std=c99 -Wall -O2 -D_REENTRANT -g
LIBS    := -lm -lssl -lcrypto -lpthread

TARGET  := $(shell uname -s | tr '[A-Z]' '[a-z]' 2>/dev/null || echo unknown)

ifeq ($(TARGET), sunos)
	CFLAGS += -D_PTHREADS -D_POSIX_C_SOURCE=200112L
	LIBS   += -lsocket
else ifeq ($(TARGET), darwin)
	export MACOSX_DEPLOYMENT_TARGET = $(shell sw_vers -productVersion)
else ifeq ($(TARGET), linux)
	CFLAGS  += -D_POSIX_C_SOURCE=200112L -D_BSD_SOURCE -D_DEFAULT_SOURCE
	LIBS    += -ldl
	LDFLAGS += -Wl,-E
else ifeq ($(TARGET), freebsd)
	CFLAGS  += -D_DECLARE_C99_LDBL_MATH
	LDFLAGS += -Wl,-E
endif

SRC  := server.c zmalloc.c ae.c sds.c dict.c siphash.c adlist.c localtime.c anet.c networking.c util.c \
		data.c cJSON.c
		
BIN  := kxykserver
VER  ?= $(shell git describe --tags --always --dirty)

ODIR := obj
OBJ  := $(patsubst %.c,$(ODIR)/%.o,$(SRC))

DEPS    :=
CFLAGS  += -I$(ODIR)/include
LDFLAGS += -L$(ODIR)/lib

# ifneq ($(WITH_LUAJIT),)
# 	CFLAGS  += -I$(WITH_LUAJIT)/include
# 	LDFLAGS += -L$(WITH_LUAJIT)/lib
# else
# 	CFLAGS  += -I$(ODIR)/include/luajit-2.1
# 	DEPS    += $(ODIR)/lib/libluajit-5.1.a
# endif

# ifneq ($(WITH_OPENSSL),)
# 	CFLAGS  += -I$(WITH_OPENSSL)/include
# 	LDFLAGS += -L$(WITH_OPENSSL)/lib
# else
# 	DEPS += $(ODIR)/lib/libssl.a
# endif

all: $(BIN)

clean:
	$(RM) -rf $(BIN) obj/*

$(BIN): $(OBJ)
	@echo LINK $(BIN)
	@$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(OBJ): config.h Makefile $(DEPS) | $(ODIR)

$(ODIR):
	@mkdir -p $@

# $(ODIR)/bytecode.c: src/wrk.lua $(DEPS)
# 	@echo LUAJIT $<
# 	@$(SHELL) -c 'PATH="obj/bin:$(PATH)" luajit -b "$(CURDIR)/$<" "$(CURDIR)/$@"'

# $(ODIR)/version.o:
# 	@echo 'const char *VERSION="$(VER)";' | $(CC) -xc -c -o $@ -

$(ODIR)/%.o : %.c
	@echo CC $<
	@$(CC) $(CFLAGS) -c -o $@ $<

# Dependencies

# LUAJIT  := $(notdir $(patsubst %.zip,%,$(wildcard deps/LuaJIT*.zip)))
# OPENSSL := $(notdir $(patsubst %.tar.gz,%,$(wildcard deps/openssl*.tar.gz)))

# OPENSSL_OPTS = no-shared no-psk no-srp no-dtls no-idea --prefix=$(abspath $(ODIR))

# $(ODIR)/$(LUAJIT): deps/$(LUAJIT).zip | $(ODIR)
# 	echo $(LUAJIT)
# 	@unzip -nd $(ODIR) $<

# $(ODIR)/$(OPENSSL): deps/$(OPENSSL).tar.gz | $(ODIR)
# 	@tar -C $(ODIR) -xf $<

# $(ODIR)/lib/libluajit-5.1.a: $(ODIR)/$(LUAJIT)
# 	@echo Building LuaJIT...
# 	@$(MAKE) -C $< PREFIX=$(abspath $(ODIR)) BUILDMODE=static install
# 	@cd $(ODIR)/bin && ln -s luajit-2.1.0-beta3 luajit

# $(ODIR)/lib/libssl.a: $(ODIR)/$(OPENSSL)
# 	@echo Building OpenSSL...
# 	@$(SHELL) -c "cd $< && ./config $(OPENSSL_OPTS)"
# 	@$(MAKE) -C $< depend
# 	@$(MAKE) -C $<
# 	@$(MAKE) -C $< install_sw
# 	@touch $@

# ------------

.PHONY: all clean

.SUFFIXES:
.SUFFIXES: .c .o 

vpath %.c   src
vpath %.h   src
