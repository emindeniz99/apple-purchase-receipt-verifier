# Builds c_src/aprv_nif.c into priv/aprv_nif.so and links it against the
# cdylib cargo produced. Driven by the Mix.Tasks.Compile.AprvNif compiler in
# mix.exs, so `mix compile` is enough; run it by hand with plain `make`.
#
# Like the C++ example's CMakeLists.txt this deliberately does not run cargo:
# the library is built with --locked by the caller, and pointing the compiler
# at the result keeps the two build systems from arguing about profiles.
#
#   cargo build --locked --release --manifest-path rust/ffi/Cargo.toml
#   make -C rust/ffi/examples/elixir
#
# Every path is discovered rather than written down. ERTS_INCLUDE_DIR comes
# from the running Erlang, so the shim compiles against whatever OTP is on
# the machine instead of a version guessed here. APRV_LIB_DIR is cargo's
# release directory for this crate; override it when CARGO_TARGET_DIR points
# elsewhere or when linking a debug build.

ERL_ROOT := $(shell erl -noshell -eval 'io:format("~s~n",[code:root_dir()]),halt().')
ERTS_INCLUDE_DIR ?= $(ERL_ROOT)/usr/include

APRV_CRATE_DIR ?= $(abspath ../..)
APRV_INCLUDE_DIR ?= $(APRV_CRATE_DIR)/include
APRV_LIB_DIR ?= $(APRV_CRATE_DIR)/target/release

CFLAGS ?= -O2 -Wall -Wextra -Wpedantic
CFLAGS += -std=c11 -fPIC -I$(ERTS_INCLUDE_DIR) -I$(APRV_INCLUDE_DIR)
LDLIBS += -L$(APRV_LIB_DIR) -lapple_purchase_receipt_verifier_ffi

# The cdylib is found at load time through an rpath, so nothing has to be
# installed or copied and LD_LIBRARY_PATH stays out of the picture.
ifeq ($(shell uname -s),Darwin)
	SO_FLAGS = -dynamiclib -undefined dynamic_lookup -Wl,-rpath,$(APRV_LIB_DIR)
else
	SO_FLAGS = -shared -Wl,-rpath,$(APRV_LIB_DIR)
endif

NIF = priv/aprv_nif.so

all: $(NIF)

$(NIF): c_src/aprv_nif.c
	@mkdir -p priv
	$(CC) $(CFLAGS) $(SO_FLAGS) -o $@ c_src/aprv_nif.c $(LDLIBS)

clean:
	rm -f $(NIF)

.PHONY: all clean
