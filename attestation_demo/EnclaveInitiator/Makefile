#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

include ../buildenv.mk

ifneq ($(SGX_MODE), HW)
  Trts_Library_Name := sgx_trts_sim
  Service_Library_Name := sgx_tservice_sim
else
  Trts_Library_Name := sgx_trts
  Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto

ENCLAVE_NAME := libenclave_initiator.so
SIGNED_ENCLAVE_NAME := libenclave_initiator.signed.so

SIGNING_KEY := ../../sgx/pelz_enclave_private.pem

# Message for missing Enclave Signing Key - Fatal Build Error
define err_no_enclave_signing_key
FAIL - No Enclave Signing Key found.
Generate or install $(SIGNING_KEY)
e.g., run 'openssl genrsa -out $(shell pwd)/$(SIGNING_KEY) -3 3072'
endef

$(SIGNED_ENCLAVE_NAME) : $(ENCLAVE_NAME) $(SIGNING_KEY)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(SIGNING_KEY) -enclave $(ENCLAVE_NAME) -out $@ -config EnclaveInitiator.config.xml
	@cp $(SIGNED_ENCLAVE_NAME) $(TOPDIR)/$(OUTDIR)/
	@echo "SIGN =>  $@"

$(SIGNING_KEY):
	$(error $(err_no_enclave_signing_key))

# Enable the security flags
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
ENCLAVE_LINK_FLAGS := $(Enclave_Security_Link_Flags)
ENCLAVE_LINK_FLAGS += -Wl,--no-undefined
ENCLAVE_LINK_FLAGS += -nostdlib
ENCLAVE_LINK_FLAGS += -nodefaultlibs
ENCLAVE_LINK_FLAGS += -nostartfiles
ENCLAVE_LINK_FLAGS += -L$(SGX_LIBRARY_PATH)
ENCLAVE_LINK_FLAGS += -L$(SGX_SSL_LIBRARY_PATH)
ENCLAVE_LINK_FLAGS += -Wl,--whole-archive
ENCLAVE_LINK_FLAGS += -l$(Trts_Library_Name)
ENCLAVE_LINK_FLAGS += -Wl,--no-whole-archive
ENCLAVE_LINK_FLAGS += -Wl,--whole-archive
ENCLAVE_LINK_FLAGS += -lsgx_tsgxssl
ENCLAVE_LINK_FLAGS += -Wl,--no-whole-archive
ENCLAVE_LINK_FLAGS += -lsgx_tsgxssl_crypto
ENCLAVE_LINK_FLAGS += -Wl,--start-group \
                        -lsgx_tstdc \
						-lsgx_tcxx \
						-lsgx_pthread \
						-l$(Crypto_Library_Name) \
						-l$(Service_Library_Name) \
					  -Wl,--end-group
ENCLAVE_LINK_FLAGS += -Wl,-Bstatic
ENCLAVE_LINK_FLAGS += -Wl,-Bsymbolic
ENCLAVE_LINK_FLAGS += -Wl,--no-undefined
ENCLAVE_LINK_FLAGS += -Wl,-pie,-eenclave_entry
ENCLAVE_LINK_FLAGS += -Wl,--export-dynamic
ENCLAVE_LINK_FLAGS += -Wl,--defsym,__ImageBase=0
ENCLAVE_LINK_FLAGS += -Wl,--gc-sections
ENCLAVE_LINK_FLAGS += -Wl,--version-script=EnclaveInitiator.lds

SGX_COMMON_FLAGS := -Wall
SGX_COMMON_FLAGS += -Wextra
SGX_COMMON_FLAGS += -Winit-self
SGX_COMMON_FLAGS += -Wpointer-arith
SGX_COMMON_FLAGS += -Wreturn-type
SGX_COMMON_FLAGS += -Waddress
SGX_COMMON_FLAGS += -Wsequence-point
SGX_COMMON_FLAGS += -Wformat-security
SGX_COMMON_FLAGS += -Wmissing-include-dirs
SGX_COMMON_FLAGS += -Wfloat-equal
SGX_COMMON_FLAGS += -Wundef
SGX_COMMON_FLAGS += -Wshadow
SGX_COMMON_FLAGS += -Wcast-align
SGX_COMMON_FLAGS += -Wconversion
SGX_COMMON_FLAGS += -Wredundant-decls

SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS)
SGX_COMMON_CFLAGS += -Wjump-misses-init
SGX_COMMON_CFLAGS += -Wstrict-prototypes
SGX_COMMON_CFLAGS += -Wunsuffixed-float-constants

SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS)
SGX_COMMON_CXXFLAGS += -Wnon-virtual-dtor
SGX_COMMON_CXXFLAGS += -std=c++11

Enclave_Include_Paths := -I$(SGX_SDK)/include
Enclave_Include_Paths += -I$(SGX_SDK)/include/tlibc
Enclave_Include_Paths += -I$(SGX_SDK)/include/libcxx
Enclave_Include_Paths += -I$(SGX_SSL)/include
Enclave_Include_Paths += -I$(ROOT_DIR)/include

Enclave_C_Flags := $(Enclave_Include_Paths)
Enclave_C_Flags += -nostdinc
Enclave_C_Flags += -fvisibility=hidden
Enclave_C_Flags += -fpie
Enclave_C_Flags += -ffunction-sections
Enclave_C_Flags += -fdata-sections

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
  Enclave_C_Flags += -fstack-protector
else
  Enclave_C_Flags += -fstack-protector-strong
endif

Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++

ifeq ($(LAv2), 1)
  Enclave_C_Flags += -DSGX_USE_LAv2_INITIATOR
  Enclave_Cpp_Flags += -DSGX_USE_LAv2_INITIATOR
endif

Enclave_Cpp_Files := $(wildcard *.cpp)
ENCLAVE_CPP_OBJECTS := $(Enclave_Cpp_Files:.cpp=.o)

.PHONY = all clean target

target = $(SIGNED_ENCLAVE_NAME)

all:
	@make target

clean:
	@rm -f  $(ENCLAVE_NAME) $(SIGNED_ENCLAVE_NAME) *.o *_t.c *_t.h *_u.c *_u.h

$(ENCLAVE_NAME):EnclaveInitiator_t.o $(ENCLAVE_CPP_OBJECTS)
	@$(CXX) $^ -o $@ $(ENCLAVE_LINK_FLAGS)
	@echo "LINK => $@"

######## Enclave Objects ########

EnclaveInitiator_t.h: $(SGX_EDGER8R) EnclaveInitiator.edl
	@$(SGX_EDGER8R) --trusted EnclaveInitiator.edl --search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "GEN  =>  $@"

EnclaveInitiator_t.c: EnclaveInitiator_t.h

EnclaveInitiator_t.o: EnclaveInitiator_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

%.o: %.cpp EnclaveInitiator_t.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

charbuf.o: util/charbuf.c
	@(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
