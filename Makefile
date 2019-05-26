# Copyright (c) 2006 - 2019 omobus-scgid authors, see the included COPYRIGHT file.

include Makefile.rules

CC		= gcc
AR		= ar
RANLIB		= ranlib
A2X		= a2x
LN		= ln -s -f
INSTALL 	= install
CP		= cp -f -v -P
CHMOD		= chmod -v

CURRENT_DATE 	:= $(shell sh -c 'date +%Y-%m-%d')
PACKAGE_NAME 	= omobus-scgid
PACKAGE_VERSION = 3.4.7
COPYRIGHT 	= Copyright (c) 2006 - 2019 ak obs, ltd. <support@omobus.net>
SUPPORT 	= Support and bug reports: <support@omobus.net>
AUTHOR		= Author: Igor Artemov <i_artemov@omobus.net>
BUGREPORT	= support@omobus.net
PACKAGE_PARAMS_H= package_params.h
IPCSEM_NAME 	= /omobus:ipcsem=%s
L_CORE_LIB	= liblua-5.3-core.so.3
L_CORE_SHARED	= $(L_CORE_LIB).0.1
L_LIBS_LIB	= liblua-5.3-libs.a

PREFIX 		?= /usr/local/omobus
DAEMON_PATH	= $(PREFIX)/sbin
LIB_PATH	= $(PREFIX)/lib/omobus-scgi.d
LIBEXEC_PATH	= $(PREFIX)/libexec/omobus-scgi.d
SHARE_PATH	= $(PREFIX)/share
MAN1_PATH	= $(SHARE_PATH)/man/man1

STRIPPED	= 
TCMALLOC_VER	= 
TCMALLOC_LINK	=
OPTIM 		=
BUILD_RULES	= 

ifeq ($(DEBUG),yes)
OPTIM = -g -ggdb -D_DEBUG
ifeq ($(USE_TCMALLOC),yes)
TCMALLOC_VER 	:= $(shell sh -c 'pkg-config --modversion libtcmalloc_debug 2> /dev/null')
TCMALLOC_LINK 	:= $(shell sh -c 'pkg-config --libs libtcmalloc_debug 2> /dev/null')
endif
else
OPTIM = -O2
STRIPPED = -s
ifeq ($(USE_TCMALLOC),yes)
TCMALLOC_VER 	:= $(shell sh -c 'pkg-config --modversion libtcmalloc 2> /dev/null')
TCMALLOC_LINK 	:= $(shell sh -c 'pkg-config --libs libtcmalloc 2> /dev/null')
endif
endif

CFLAGS		= -std=c99 -pedantic $(OPTIM) -fPIC -Wall -D_GNU_SOURCE -D__STDC_FORMAT_MACROS $(PROF)
CCLINK		= $(TCMALLOC_LINK) -Wl,-rpath,$(LIB_PATH) 
LDFLAGS		= -shared

L_CORE_OBJ	= l_api.o l_code.o l_ctype.o l_debug.o l_do.o l_dump.o l_func.o l_gc.o l_lex.o \
		  l_mem.o l_object.o l_opcodes.o l_parser.o l_state.o l_string.o l_table.o l_tm.o \
		  l_undump.o l_vm.o l_zio.o l_aux.o 
L_LIBS_OBJ	= fwrite_safe.o crc32.o crc64.o md5.o sha1.o xxhash.o base64.o strtrim.o dynarray.o hashtable.o \
		  memdup.o connect_timed.o lsdir.o tls.o ftp.o \
		  lib_base.o lib_utf8.o lib_debug.o lib_math.o lib_string.o lib_table.o lib_coro.o lib_package.o \
		  lib_os.o lib_iconv.o lib_hash.o lib_zlib.o lib_bzip2.o lib_json.o lib_ftp.o lib_sock.o
OMOBUS_SCGID_OBJ= omobus-scgid.o setproctitle.o make_abstimeout.o
BIND_DUMMY_OBJ	= bind_dummy.o
BIND_LDAP_OBJ	= bind_ldap.o
BIND_PGSQL_OBJ	= bind_pgsql.o
BIND_TDS_OBJ	= bind_tds.o
MANS_OBJ 	= omobus-scgid.1

ifeq ($(USE_LDAP),yes)
MANS_OBJ	+= bind_ldap.1
BUILD_RULES	+= bind_ldap
endif

ifeq ($(USE_PGSQL),yes)
MANS_OBJ	+= bind_pgsql.1
BUILD_RULES	+= bind_pgsql
endif

ifeq ($(USE_TDS),yes)
MANS_OBJ	+= bind_tds.1
BUILD_RULES	+= bind_tds
endif

HEADERCOLOR="\033[32;1m"
PARAMCOLOR="\033[33m"
ENDCOLOR="\033[0m"

all: luaengine $(PACKAGE_NAME) bind_dummy $(BUILD_RULES) \
     $(BUILD_RULES)
	@echo ""
	@echo ""
	@echo "** ********************************************************************************"
	@echo "** "$(HEADERCOLOR)$(PACKAGE_NAME) $(PACKAGE_VERSION)$(ENDCOLOR)" (prefix=$(PREFIX)) summary:"
	@echo "** "
	@echo "**    Build environment:"
ifeq ($(DEBUG),yes)
	@echo "**        debug build. . . . . . "$(PARAMCOLOR)"yes"$(ENDCOLOR)
endif
ifeq ($(TCMALLOC_VER),)
	@echo "**        tcmalloc . . . . . . . no"
else
	@echo "**        tcmalloc . . . . . . . "$(PARAMCOLOR)$(TCMALLOC_VER)", link: "$(TCMALLOC_LINK)$(ENDCOLOR)
endif
	@echo "** "
	@echo "**    Binding modules:"
ifeq ($(USE_LDAP),yes)
	@echo "**        bind_ldap. . . . . . . yes"
else
	@echo "**        bind_ldap. . . . . . . no"
endif
ifeq ($(USE_PGSQL),yes)
	@echo "**        bind_pgsql . . . . . . yes"
else
	@echo "**        bind_pgsql . . . . . . no"
endif
ifeq ($(USE_TDS),yes)
	@echo "**        bind_tds . . . . . . . yes"
else
	@echo "**        bind_tds . . . . . . . no"
endif
	@echo "** "
	@echo "**    Execute environment:"
	@echo "**        script engine. . . . . Lua 5.3.1"
	@echo "**        server libraries . . . $(LIB_PATH)"
	@echo "**        Lua libraries. . . . . $(LIBEXEC_PATH)"
	@echo "**        Lua bindings . . . . . $(LIBEXEC_PATH)"
	@echo "** "
	@echo "** $(COPYRIGHT)"
	@echo "** $(SUPPORT)"
	@echo "** *******************************************************************************"
	@echo ""

help:
	@echo "$(PACKAGE_NAME) $(PACKAGE_VERSION) build acript"
	@echo "$(COPYRIGHT)"
	@echo ""
	@echo "Usage: make [parameters]"
	@echo ""
	@echo "Parameters:"
	@echo "  DEGUG=yes|no           Build debug version (default: no)."
	@echo "  USE_TCMALLOC=yes|no    Use thread-caching malloc (experimental) (default: no)."
	@echo "  USE_LDAP=yes|no        Build OpenLDAP binding module (default: yes)."
	@echo "  USE_PGSQL=yes|no       Build PostgreSQL binding module (default: yes)."
	@echo "  USE_TDS=yes|no         Build Microsoft SQLServer binding module (default: no)."
	@echo ""
	@echo "You may change default behavior in the " $(PARAMCOLOR) "Makefile.rules" $(ENDCOLOR)
	@echo "$(SUPPORT)"
	@echo ""

.PHONY: all clean
.SUFFIXES: .1 .1.txt

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

.1.txt.1:
	a2x --doctype manpage --format manpage $<

deps: package_params
	$(CC) -MM *.c | sed -e 's| package_params.h||g' 1> Makefile.deps

prof:
	$(MAKE) clean
	$(MAKE) DEBUG="$(DEBUG)" USE_TCMALLOC="$(USE_TCMALLOC)" USE_LDAP="$(USE_LDAP)" USE_PGSQL="$(USE_PGSQL)" PROF="-gp"

clean:
	rm -rf *.o *.so *.so.* *.a *.la $(PACKAGE_NAME) $(PACKAGE_PARAMS_H)

mans: $(MANS_OBJ)

package_params:
	@echo "#ifndef __package_params_h__" > $(PACKAGE_PARAMS_H)
	@echo "#define __package_params_h__" >> $(PACKAGE_PARAMS_H)
	@echo "# define PACKAGE_NAME       \"$(PACKAGE_NAME)\"" >> $(PACKAGE_PARAMS_H)
	@echo "# define PACKAGE_VERSION    \"$(PACKAGE_VERSION)\"" >> $(PACKAGE_PARAMS_H)
	@echo "# define PACKAGE_BUGREPORT  \"$(BUGREPORT)\"" >> $(PACKAGE_PARAMS_H)
	@echo "# define PACKAGE_COPYRIGHT  \"$(COPYRIGHT)\"" >> $(PACKAGE_PARAMS_H)
	@echo "# define PACKAGE_AUTHOR     \"$(AUTHOR)\"" >> $(PACKAGE_PARAMS_H)
	@echo "# define LIB_PATH           \"$(LIB_PATH)\"" >> $(PACKAGE_PARAMS_H)
	@echo "# define LIBEXEC_PATH       \"$(LIBEXEC_PATH)\"" >> $(PACKAGE_PARAMS_H)
	@echo "# define OMOBUS_IPCSEM_NAME \"$(IPCSEM_NAME)\"" >> $(PACKAGE_PARAMS_H)
	@echo "#endif /*__package_params_h__*/" >> $(PACKAGE_PARAMS_H)

luaengine: $(L_CORE_LIB) $(L_LIBS_LIB)

$(L_CORE_LIB): package_params $(L_CORE_OBJ)
	$(CC) $(LDFLAGS) -o $(L_CORE_SHARED) -Wl,-soname,$(L_CORE_LIB) $(L_CORE_OBJ) -lrt
	$(LN) $(L_CORE_SHARED) $(L_CORE_LIB)

$(L_LIBS_LIB): $(L_CORE_LIB) $(L_LIBS_OBJ)
	$(AR) rcs $(L_LIBS_LIB) $(L_LIBS_OBJ)
	$(RANLIB) $(L_LIBS_LIB)

$(PACKAGE_NAME): $(L_LIBS_LIB) $(OMOBUS_SCGID_OBJ)
	$(CC) -o $(PACKAGE_NAME) $(CCLINK) $(OMOBUS_SCGID_OBJ) $(L_CORE_LIB) $(L_LIBS_LIB) -pthread -lz -lbz2 -lcrypto -lssl -lrt -lm -ldl

bind_dummy: $(L_CORE_LIB) $(BIND_DUMMY_OBJ)
	$(CC) -o $@.so $(CCLINK) $(LDFLAGS) -Wl,-soname,$@.so $(BIND_DUMMY_OBJ) $(L_CORE_LIB) -lrt

bind_ldap: $(L_CORE_LIB) $(BIND_LDAP_OBJ)
	$(CC) -o $@.so $(CCLINK) $(LDFLAGS) -Wl,-soname,$@.so $(BIND_LDAP_OBJ) $(L_CORE_LIB) -lldap -lrt

bind_pgsql: $(L_CORE_LIB) $(BIND_PGSQL_OBJ)
	$(CC) -o $@.so $(CCLINK) $(LDFLAGS) -Wl,-soname,$@.so $(BIND_PGSQL_OBJ) $(L_CORE_LIB) -lpq -lrt

bind_tds: $(L_CORE_LIB) $(BIND_TDS_OBJ)
	$(CC) -o $@.so $(CCLINK) $(LDFLAGS) -Wl,-soname,$@.so $(BIND_TDS_OBJ) $(L_CORE_LIB) -lsybdb -lrt

install: all
	$(INSTALL) -v -D $(STRIPPED) $(L_CORE_SHARED) $(LIB_PATH)/$(L_CORE_SHARED)
	$(CP) $(L_CORE_LIB) $(LIB_PATH)/$(L_CORE_LIB) && $(CHMOD) 0644 $(LIB_PATH)/$(L_CORE_LIB)
	$(INSTALL) -v -D $(STRIPPED) $(PACKAGE_NAME) $(DAEMON_PATH)/$(PACKAGE_NAME)
	for i in bind_*.so ; do $(INSTALL) -v -D $(STRIPPED) -m 0644 $$i $(LIBEXEC_PATH)/$$i; done
	for i in bind_*.1 ; do $(INSTALL) -v -C -D -m 0644 $$i $(MAN1_PATH)/$$i; done
	$(INSTALL) -v -C -D -m 0644 $(PACKAGE_NAME).1 $(MAN1_PATH)/$(PACKAGE_NAME).1
	for i in *.lua ; do $(INSTALL) -v -C -D -m 0644 $$i $(LIBEXEC_PATH)/$$i; done

distr:
	$(INSTALL) -d $(PACKAGE_NAME)-$(PACKAGE_VERSION)/
	$(INSTALL) -m 0644 *.c* *.h *.1.txt $(PACKAGE_NAME).1 bind_*.1 *.lua Makefile* ChangeLog AUTHO* \
	    COPY* README* $(PACKAGE_NAME)-$(PACKAGE_VERSION)/
	tar -cf $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar $(PACKAGE_NAME)-$(PACKAGE_VERSION)/
	bzip2 $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar
	rm -fr $(PACKAGE_NAME)-$(PACKAGE_VERSION)

include Makefile.deps
