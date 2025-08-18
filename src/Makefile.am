# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = secp256k1 univalue bls12-381

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
BITCOIN_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include -I$(srcdir)/bls12-381/include
BITCOIN_INCLUDES += $(UNIVALUE_CFLAGS)

LIBDOGECOIN_SERVER=libdogecoin_server.a
LIBDOGECOIN_COMMON=libdogecoin_common.a
LIBDOGECOIN_CONSENSUS=libdogecoin_consensus.a
LIBDOGECOIN_CLI=libdogecoin_cli.a
LIBDOGECOIN_UTIL=libdogecoin_util.a
LIBDOGECOIN_CRYPTO=crypto/libdogecoin_crypto.a
LIBDOGECOINQT=qt/libdogecoinqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBBLS=bls12-381/libbls.la

if ENABLE_ZMQ
LIBDOGECOIN_ZMQ=libdogecoin_zmq.a
endif
if BUILD_BITCOIN_LIBS
LIBDOGECOINCONSENSUS=libdogecoinconsensus.la
endif
if ENABLE_WALLET
LIBDOGECOIN_WALLET=libdogecoin_wallet.a
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

$(LIBBLS): $(wildcard bls12-381/src/*) $(wildcard bls12-381/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBDOGECOIN_CRYPTO) \
  $(LIBDOGECOIN_UTIL) \
  $(LIBDOGECOIN_COMMON) \
  $(LIBDOGECOIN_CONSENSUS) \
  $(LIBDOGECOIN_SERVER) \
  $(LIBDOGECOIN_CLI) \
  $(LIBDOGECOIN_WALLET) \
  $(LIBDOGECOIN_ZMQ)

lib_LTLIBRARIES = $(LIBDOGECOINCONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_BITCOIND
  bin_PROGRAMS += dogecoind
endif

if BUILD_BITCOIN_UTILS
  bin_PROGRAMS += dogecoin-cli dogecoin-tx
endif

# bitcoin core #
BITCOIN_CORE_H = \
  addrdb.h \
  addrman.h \
  attributes.h \
  auxpow.h \
  base58.h \
  bloom.h \
  blockencodings.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  dogecoin.cpp \
  dogecoin.h \
  dogecoin-fees.cpp \
  dogecoin-fees.h \
  fs.h \
  httprpc.h \
  httpserver.h \
  indirectmap.h \
  init.h \
  key.h \
  keystore.h \
  dbwrapper.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  net_processing.h \
  netaddress.h \
  netbase.h \
  netmessagemaker.h \
  noui.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  pow.h \
  primitives/block.h \
  primitives/pureheader.h \
  protocol.h \
  random.h \
  reverselock.h \
  rpc/blockchain.h \
  rpc/client.h \
  rpc/protocol.h \
  rpc/server.h \
  rpc/register.h \
  scheduler.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  script/ismine.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/experimental.h \
  support/lockedpool.h \
  sync.h \
  threadsafety.h \
  threadinterrupt.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  txrequest.h \
  ui_interface.h \
  undo.h \
  util.h \
  utilmemory.h \
  utilmoneystr.h \
  utiltime.h \
  utilstring.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  wallet/coincontrol.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/rpcutil.h \
  wallet/rpcwallet.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libdogecoin_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between bitcoind and bitcoin-qt
libdogecoin_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libdogecoin_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libdogecoin_server_a_SOURCES = \
  addrman.cpp \
  addrdb.cpp \
  bloom.cpp \
  blockencodings.cpp \
  chain.cpp \
  checkpoints.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  dbwrapper.cpp \
  merkleblock.cpp \
  miner.cpp \
  net.cpp \
  net_processing.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  pow.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  script/sigcache.cpp \
  script/ismine.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  txrequest.cpp \
  ui_interface.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(BITCOIN_CORE_H)

if ENABLE_ZMQ
libdogecoin_zmq_a_CPPFLAGS = $(BITCOIN_INCLUDES) $(ZMQ_CFLAGS)
libdogecoin_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libdogecoin_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif


# wallet: shared between bitcoind and bitcoin-qt, but only linked
# when wallet enabled
libdogecoin_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libdogecoin_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libdogecoin_wallet_a_SOURCES = \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcutil.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  policy/rbf.cpp \
  $(BITCOIN_CORE_H)

# crypto primitives library
crypto_libdogecoin_crypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_CONFIG_INCLUDES)
crypto_libdogecoin_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libdogecoin_crypto_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/common.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/scrypt.cpp \
  crypto/scrypt.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h

# only include SSE2 scrypt sources if USE_SCRYPT_SSE2 is defined
if USE_SCRYPT_SSE2
crypto_libdogecoin_crypto_a_SOURCES += crypto/scrypt-sse2.cpp
endif

# consensus: shared between all executables that validate any consensus rules.
libdogecoin_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libdogecoin_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libdogecoin_consensus_a_SOURCES = \
  amount.h \
  arith_uint256.cpp \
  arith_uint256.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/validation.h \
  hash.cpp \
  hash.h \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/pureheader.cpp \
  primitives/pureheader.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/bitcoinconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  utilstrencodings.cpp \
  utilstrencodings.h \
  version.h

# common: shared between bitcoind, and bitcoin-qt and non-server tools
libdogecoin_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libdogecoin_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libdogecoin_common_a_SOURCES = \
  amount.cpp \
  arith_uint256.cpp \
  auxpow.cpp \
  base58.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  key.cpp \
  keystore.cpp \
  netaddress.cpp \
  netbase.cpp \
  primitives/block.cpp \
  primitives/pureheader.cpp \
  primitives/transaction.cpp \
  protocol.cpp \
  scheduler.cpp \
  script/sign.cpp \
  script/standard.cpp \
  warnings.cpp \
  $(BITCOIN_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libdogecoin_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libdogecoin_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libdogecoin_util_a_SOURCES = \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  fs.cpp \
  random.cpp \
  rpc/protocol.cpp \
  support/cleanse.cpp \
  sync.cpp \
  threadinterrupt.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  $(BITCOIN_CORE_H)

if GLIBC_BACK_COMPAT

libdogecoin_util_a_SOURCES += compat/glibc_compat.cpp
AM_LDFLAGS += $(COMPAT_LDFLAGS)

endif

# cli: shared between bitcoin-cli and bitcoin-qt
libdogecoin_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libdogecoin_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libdogecoin_cli_a_SOURCES = \
  rpc/client.cpp \
  $(BITCOIN_CORE_H)

nodist_libdogecoin_util_a_SOURCES = $(srcdir)/obj/build.h
#

# bitcoind binary #
dogecoind_SOURCES = bitcoind.cpp
dogecoind_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
dogecoind_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
dogecoind_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
dogecoind_SOURCES += bitcoind-res.rc
endif

dogecoind_LDADD = \
  $(LIBDOGECOIN_SERVER) \
  $(LIBDOGECOIN_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBDOGECOIN_UTIL) \
  $(LIBDOGECOIN_WALLET) \
  $(LIBDOGECOIN_ZMQ) \
  $(LIBDOGECOIN_CONSENSUS) \
  $(LIBDOGECOIN_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1) \
  $(LIBBLS)

dogecoind_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS)

# bitcoin-cli binary #
dogecoin_cli_SOURCES = bitcoin-cli.cpp
dogecoin_cli_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS)
dogecoin_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
dogecoin_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
dogecoin_cli_SOURCES += bitcoin-cli-res.rc
endif

dogecoin_cli_LDADD = \
  $(LIBDOGECOIN_CLI) \
  $(LIBUNIVALUE) \
  $(LIBDOGECOIN_UTIL) \
  $(LIBDOGECOIN_CRYPTO)

dogecoin_cli_LDADD += $(BOOST_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS)
#

# bitcoin-tx binary #
dogecoin_tx_SOURCES = bitcoin-tx.cpp
dogecoin_tx_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
dogecoin_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
dogecoin_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
dogecoin_tx_SOURCES += bitcoin-tx-res.rc
endif

dogecoin_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBDOGECOIN_COMMON) \
  $(LIBDOGECOIN_UTIL) \
  $(LIBDOGECOIN_CONSENSUS) \
  $(LIBDOGECOIN_CRYPTO) \
  $(LIBSECP256K1) \
  $(LIBBLS)

dogecoin_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# bitcoinconsensus library #
if BUILD_BITCOIN_LIBS
include_HEADERS = script/bitcoinconsensus.h
libdogecoinconsensus_la_SOURCES = $(crypto_libdogecoin_crypto_a_SOURCES) $(libdogecoin_consensus_a_SOURCES)

if GLIBC_BACK_COMPAT
  libdogecoinconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libdogecoinconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)

if TARGET_WINDOWS
libdogecoinconsensus_la_LDFLAGS += -Wl,--allow-multiple-definition
endif

libdogecoinconsensus_la_LIBADD = $(LIBSECP256K1) $(LIBBLS)
libdogecoinconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -I$(srcdir)/bls12-381/include -DBUILD_BITCOIN_INTERNAL
libdogecoinconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = $(CTAES_DIST)


config/bitcoin-config.h: config/stamp-h1
	@$(MAKE) -C $(top_builddir) $(subdir)/$(@)
config/stamp-h1: $(top_srcdir)/$(subdir)/config/bitcoin-config.h.in $(top_builddir)/config.status
	$(AM_V_at)$(MAKE) -C $(top_builddir) $(subdir)/$(@)
$(top_srcdir)/$(subdir)/config/bitcoin-config.h.in:  $(am__configure_deps)
	$(AM_V_at)$(MAKE) -C $(top_srcdir) $(subdir)/config/bitcoin-config.h.in

clean-local:
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C bls12-381 clean
	-$(MAKE) -C univalue clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__
	-rm -rf $(CARGO_TARGET_DIR)
	-rm -f $(ZKP_VERIFIER_LIB)

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

check-symbols: $(bin_PROGRAMS)
	@echo "Checking glibc back compat..."
	$(AM_V_at) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) $(PYTHON) $(top_srcdir)/contrib/devtools/security-check.py $(bin_PROGRAMS)
endif

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(<D) $<

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif



# ZKP Verifier Rust library integration
if HAVE_RUST

# Map autotools host triplet to Rust target triplet
RUST_TARGET_MAP_aarch64_linux_gnu = aarch64-unknown-linux-gnu
RUST_TARGET_MAP_arm_linux_gnueabihf = armv7-unknown-linux-gnueabihf
RUST_TARGET_MAP_i686_pc_linux_gnu = i686-unknown-linux-gnu
RUST_TARGET_MAP_x86_64_unknown_linux_gnu = x86_64-unknown-linux-gnu
RUST_TARGET_MAP_i686_w64_mingw32 = i686-pc-windows-gnu
RUST_TARGET_MAP_x86_64_w64_mingw32 = x86_64-pc-windows-gnu
RUST_TARGET_MAP_x86_64_apple_darwin11 = x86_64-apple-darwin
RUST_TARGET_MAP_aarch64_apple_darwin = aarch64-apple-darwin

# Determine Rust target - fallback to host if no mapping exists
RUST_TARGET = $(or $(RUST_TARGET_MAP_$(subst -,_,$(host_alias))),$(host_alias))

# Set Cargo target directory according to build system pattern
CARGO_TARGET_DIR = $(abs_top_builddir)/depends/$(host_alias)/cargo-target

# Define paths and includes
ZKP_INCLUDE = -I$(top_srcdir)/src/zkp-verifier/include
# Use platform-specific shared library extension
if TARGET_DARWIN
ZKP_VERIFIER_LIB = $(CARGO_TARGET_DIR)/release/libzkp_verifier.dylib
else
if TARGET_WINDOWS
# Link against the import library for the DLL on MinGW targets
ZKP_VERIFIER_LIB = $(CARGO_TARGET_DIR)/release/libzkp_verifier.dll.a
else
ZKP_VERIFIER_LIB = $(CARGO_TARGET_DIR)/release/libzkp_verifier.so
endif
endif

# Add include paths
AM_CPPFLAGS += $(ZKP_INCLUDE)

# Compute GCC_LIBDIR with fallback for CI
GCC_LIBDIR = $(shell $(host_alias)-g++ -print-libgcc-file-name | xargs dirname || echo "/usr/lib/gcc/$(host_alias)/10")

# For Windows, add flag to allow multiple definitions in static link
if TARGET_WINDOWS
dogecoind_LDFLAGS += -Wl,--allow-multiple-definition -lbcrypt -luserenv -lntdll
dogecoin_tx_LDFLAGS += -Wl,--allow-multiple-definition
endif

# Gate stub inclusion: exclude for Windows to avoid C++ runtime conflicts
if TARGET_WINDOWS
# no stub for Windows: rely on Rust C ABI
else
libdogecoin_consensus_a_SOURCES += zkp_stub.cpp
endif

# Add explicit dependency for consensus lib on ZKP lib if BUILD_BITCOIN_LIBS
if BUILD_BITCOIN_LIBS
libdogecoinconsensus_la_LIBADD += $(ZKP_VERIFIER_LIB)
endif

# Make library the target, add Rust sources as prereqs
$(ZKP_VERIFIER_LIB): $(top_srcdir)/src/zkp-verifier/src/lib.rs $(top_srcdir)/src/zkp-verifier/Cargo.toml
	@echo "Building Rust ZKP verifier shared library for target $(RUST_TARGET)..."
	@mkdir -p $(CARGO_TARGET_DIR)
	@cd $(top_srcdir)/src/zkp-verifier && \
	if [ "$(RUST_TARGET)" != "$(host_alias)" ] && [ "$(RUST_TARGET)" != "" ]; then \
		echo "Cross-compiling for $(RUST_TARGET)"; \
		CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) \
		CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
		CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc \
		CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_LINKER=gcc \
		CARGO_TARGET_I686_PC_WINDOWS_GNU_LINKER=i686-w64-mingw32-gcc \
		CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
		CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER=clang \
		CXX_x86_64_apple_darwin=x86_64-apple-darwin11-clang++ \
		CC_x86_64_apple_darwin=x86_64-apple-darwin11-clang \
		AR_x86_64_apple_darwin=x86_64-apple-darwin11-ar \
		CXX_i686_pc_windows_gnu=i686-w64-mingw32-g++ \
		CC_i686_pc_windows_gnu=i686-w64-mingw32-gcc \
		AR_i686_pc_windows_gnu=i686-w64-mingw32-ar \
		CXX_x86_64_pc_windows_gnu=x86_64-w64-mingw32-g++ \
		CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc \
		AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar \
		RUSTFLAGS="$$(if echo "$(RUST_TARGET)" | grep -q windows; then echo "-C panic=unwind -C lto=off -C link-arg=-lgcc_eh -C link-arg=-lgcc_s -C link-arg=-lpthread"; fi)" \
		cargo build --release --target $(RUST_TARGET) || echo "Warning: Rust build failed"; \
		mkdir -p $(CARGO_TARGET_DIR)/release && \
		if echo "$(RUST_TARGET)" | grep -q "windows"; then \
			cp $(CARGO_TARGET_DIR)/$(RUST_TARGET)/release/libzkp_verifier.dll.a $@ 2>/dev/null || true; \
			cp $(CARGO_TARGET_DIR)/$(RUST_TARGET)/release/zkp_verifier.dll $(CARGO_TARGET_DIR)/release/ 2>/dev/null || true; \
		elif echo "$(RUST_TARGET)" | grep -q "darwin"; then \
			cp $(CARGO_TARGET_DIR)/$(RUST_TARGET)/release/libzkp_verifier.dylib $@ 2>/dev/null || true; \
		else \
			cp $(CARGO_TARGET_DIR)/$(RUST_TARGET)/release/libzkp_verifier.so $@ 2>/dev/null || true; \
		fi; \
	else \
		echo "Native build for $(host_alias)"; \
		CARGO_TARGET_DIR=$(CARGO_TARGET_DIR) RUSTFLAGS="$$(if echo "$(RUST_TARGET)" | grep -q windows; then echo "-C panic=unwind -C lto=off -C link-arg=-lgcc_eh -C link-arg=-lgcc_s -C link-arg=-lpthread"; fi)" cargo build --release || echo "Warning: Rust build failed"; \
		cp $(CARGO_TARGET_DIR)/release/libzkp_verifier.so $@ 2>/dev/null || true; \
	fi
	@touch $@

# $(ZKP_VERIFIER_LIB): $(ZKP_STAMP)

# Add ZKP library to executables and shared libraries
if TARGET_WINDOWS
dogecoind_LDADD += $(ZKP_VERIFIER_LIB)
dogecoin_tx_LDADD += $(ZKP_VERIFIER_LIB)
if BUILD_BITCOIN_LIBS
libdogecoinconsensus_la_LIBADD += $(ZKP_VERIFIER_LIB)
endif
else
if TARGET_DARWIN
dogecoind_LDADD += $(ZKP_VERIFIER_LIB)
dogecoin_tx_LDADD += $(ZKP_VERIFIER_LIB)
if BUILD_BITCOIN_LIBS
libdogecoinconsensus_la_LDFLAGS += -L$(CARGO_TARGET_DIR)/release -lzkp_verifier
endif
else
dogecoind_LDADD += $(ZKP_VERIFIER_LIB)
dogecoin_tx_LDADD += $(ZKP_VERIFIER_LIB)
if BUILD_BITCOIN_LIBS
libdogecoinconsensus_la_LIBADD += $(ZKP_VERIFIER_LIB)
endif
endif
endif

else
# Rust not available - create dummy target
.PHONY: build-zkp-verifier-dummy
build-zkp-verifier-dummy:
	@echo "Rust not available, skipping ZKP verifier build"
endif

# Force target for dependencies
FORCE:
