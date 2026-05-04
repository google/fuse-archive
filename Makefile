PROJECT = fuse-archive
PKG_CONFIG ?= pkg-config

FUSE_MAJOR_VERSION ?= 3

ifeq ($(FUSE_MAJOR_VERSION), 3)
DEPS = fuse3
FUSE_CXXFLAGS = -DFUSE_USE_VERSION=30
else ifeq ($(FUSE_MAJOR_VERSION), 2)
DEPS = fuse
FUSE_CXXFLAGS = -DFUSE_USE_VERSION=26
endif

DEPS += libarchive
UNIT_TEST_DEPS = gtest gtest_main

PKG_CXXFLAGS := $(shell $(PKG_CONFIG) --cflags $(DEPS))
PKG_LDFLAGS := $(shell $(PKG_CONFIG) --libs $(DEPS))

UNIT_TEST_PKG_CXXFLAGS := $(shell $(PKG_CONFIG) --cflags $(UNIT_TEST_DEPS))
UNIT_TEST_PKG_LDFLAGS := $(shell $(PKG_CONFIG) --libs $(UNIT_TEST_DEPS))

COMMON_CXXFLAGS = -std=c++20 -Wall -Wextra -Wno-missing-field-initializers -Wno-sign-compare -Wno-unused-parameter -I.
COMMON_CXXFLAGS += -D_FILE_OFFSET_BITS=64 -D_TIME_BITS=64 $(FUSE_CXXFLAGS)

ifeq ($(DEBUG), 1)
COMMON_CXXFLAGS += -O0 -g
else
COMMON_CXXFLAGS += -O2 -DNDEBUG
endif

ifeq ($(ASAN), 1)
COMMON_CXXFLAGS += -fsanitize=address
PKG_LDFLAGS += -fsanitize=address
endif

ifeq ($(UBSAN), 1)
COMMON_CXXFLAGS += -fsanitize=undefined
PKG_LDFLAGS += -fsanitize=undefined
endif

ifeq ($(COVERAGE), 1)
COMMON_CXXFLAGS += -fprofile-arcs -ftest-coverage
LDFLAGS += --coverage
endif

PREFIX ?= /usr
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man/man1
MAN = $(PROJECT).1
INSTALL = install

# ---- Formatting

FORMAT = clang-format
CC_FILES = $(wildcard *.cc lib/*.cc test/*.cc)
H_FILES = $(wildcard lib/*.h)
ALL_CXX_FILES = $(CC_FILES) $(H_FILES)

format:
	$(FORMAT) -i -style=file $(ALL_CXX_FILES)

check-format:
	$(FORMAT) --dry-run -Werror -style=file $(ALL_CXX_FILES)

# ---- Library

LIB_DIR = lib
LIB_OUT = out/$(LIB_DIR)
LIB_SOURCES = $(wildcard $(LIB_DIR)/*.cc)
LIB_OBJECTS = $(addprefix out/,$(LIB_SOURCES:.cc=.o))
LIB_ARCHIVE = out/lib$(PROJECT).a

$(LIB_ARCHIVE): $(LIB_OBJECTS)
	$(AR) $(ARFLAGS) $@ $(LIB_OBJECTS)

out/$(LIB_DIR)/%.o: $(LIB_DIR)/%.cc
	@mkdir -p $(dir $@)
	$(CXX) -c $(COMMON_CXXFLAGS) $(PKG_CXXFLAGS) $(CPPFLAGS) $(CXXFLAGS) $< -o $@ -MMD -MP -MF $(@:.o=.d)

# ---- Binaries

all: out/$(PROJECT)

out/$(PROJECT): $(PROJECT).cc $(LIB_ARCHIVE)
	mkdir -p out
	$(CXX) $(COMMON_CXXFLAGS) $(PKG_CXXFLAGS) $(CPPFLAGS) $(CXXFLAGS) $< $(LIB_ARCHIVE) $(PKG_LDFLAGS) $(LDFLAGS) -o $@

# ---- Unit Tests

UNIT_TEST = unit_tests
UNIT_TEST_SOURCES = test/unit_tests.cc
UNIT_TEST_OBJECTS = $(addprefix out/,$(UNIT_TEST_SOURCES:.cc=.o))

out/$(UNIT_TEST): $(UNIT_TEST_OBJECTS) $(LIB_ARCHIVE)
	$(CXX) $(COMMON_CXXFLAGS) $(PKG_CXXFLAGS) $(UNIT_TEST_PKG_CXXFLAGS) $(CPPFLAGS) $(CXXFLAGS) $^ $(PKG_LDFLAGS) $(UNIT_TEST_PKG_LDFLAGS) $(LDFLAGS) -o $@

out/test/%.o: test/%.cc
	@mkdir -p $(dir $@)
	$(CXX) -c $(COMMON_CXXFLAGS) $(PKG_CXXFLAGS) $(UNIT_TEST_PKG_CXXFLAGS) $(CPPFLAGS) $(CXXFLAGS) $< -o $@ -MMD -MP -MF $(@:.o=.d)

# ---- Standard targets

check: out/$(PROJECT) out/$(UNIT_TEST) test/data/big.zip test/data/collisions.zip test/data/deep.tar test/data/many_nodes.zip
	out/$(UNIT_TEST)
	python3 test/test.py

check-fast: out/$(PROJECT) out/$(UNIT_TEST)
	out/$(UNIT_TEST)
	python3 test/test.py --fast

valgrind: out/$(PROJECT) out/$(UNIT_TEST)
	valgrind -q --leak-check=full --error-exitcode=33 out/$(UNIT_TEST)
	MOUNT_WRAPPER="valgrind -q --leak-check=full --error-exitcode=33" python3 test/test.py --fast

coverage:
	$(MAKE) clean
	$(MAKE) DEBUG=1 COVERAGE=1 check-fast
	lcov --capture --directory out --output-file out/coverage.info --ignore-errors mismatch,inconsistent
	lcov --remove out/coverage.info '/usr/include/*' '/usr/lib/*' 'test/*' --output-file out/coverage.info --ignore-errors unused,inconsistent
	genhtml out/coverage.info --output-directory out/coverage --ignore-errors inconsistent
	@echo "Coverage report generated at out/coverage/index.html"

test: check

unit_tests: out/$(UNIT_TEST)
	out/$(UNIT_TEST)

clean:
	rm -rf out

clean-data:
	rm -f test/data/big.zip test/data/collisions.zip test/data/deep.tar test/data/many_nodes.zip

doc: $(MAN)
	@if [ -z "$(QUIET)" ]; then man -l $(MAN); fi

release:
	python3 release.py $(VERSION)

$(MAN): README.md
	pandoc $< -s -t man | \
	sed -e 's/^\.IP \\\[bu\]/.PD 0\n.IP \\\[bu\]/g' \
	    -e 's/^\.SH/.PD\n.SH/g' \
	    -e 's/^\.SS/.PD\n.SS/g' \
	    -e 's/^\.PP/.PD\n.PP/g' \
	    -e 's/^\.TP/.PD\n.TP/g' > $@

ifneq ($(filter clean%,$(MAKECMDGOALS)),)
else
-include $(LIB_OBJECTS:.o=.d)
-include $(UNIT_TEST_OBJECTS:.o=.d)
endif

install: out/$(PROJECT)
	$(INSTALL) -D "out/$(PROJECT)" "$(DESTDIR)$(BINDIR)/$(PROJECT)"
	$(INSTALL) -D -m 644 $(MAN) "$(DESTDIR)$(MANDIR)/$(MAN)"

install-strip: out/$(PROJECT)
	$(INSTALL) -D -s "out/$(PROJECT)" "$(DESTDIR)$(BINDIR)/$(PROJECT)"
	$(INSTALL) -D -m 644 $(MAN) "$(DESTDIR)$(MANDIR)/$(MAN)"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(PROJECT)" "$(DESTDIR)$(MANDIR)/$(MAN)"


test/data/big.zip: test/make_big_zip.py
	python3 test/make_big_zip.py

test/data/collisions.zip: test/make_collisions.py
	python3 test/make_collisions.py

test/data/deep.tar: test/make_deep.py
	python3 test/make_deep.py

test/data/many_nodes.zip: test/make_many_nodes.py
	python3 test/make_many_nodes.py

.PHONY: all check check-fast check-format clean clean-data coverage doc format install install-strip release test uninstall unit_tests valgrind

