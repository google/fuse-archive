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

PKG_CXXFLAGS := $(shell $(PKG_CONFIG) --cflags $(DEPS))
PKG_LDFLAGS := $(shell $(PKG_CONFIG) --libs $(DEPS))

COMMON_CXXFLAGS = -std=c++20 -Wall -Wextra -Wno-missing-field-initializers -Wno-sign-compare -Wno-unused-parameter
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

PREFIX ?= /usr
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man/man1
MAN = $(PROJECT).1
INSTALL = install


all: out/$(PROJECT)

check: out/$(PROJECT) test/data/big.zip test/data/collisions.zip test/data/deep.tar test/data/many_nodes.zip
	python3 test/test.py

check-fast: out/$(PROJECT)
	python3 test/test.py --fast

test: check

clean:
	rm -rf out

clean-data:
	rm -f test/data/big.zip test/data/collisions.zip test/data/deep.tar test/data/many_nodes.zip

doc: $(MAN)
	man -l $(MAN)

$(MAN): README.md
	pandoc $< -s -t man -o $@

install: out/$(PROJECT)
	$(INSTALL) -D "out/$(PROJECT)" "$(DESTDIR)$(BINDIR)/$(PROJECT)"
	$(INSTALL) -D -m 644 $(MAN) "$(DESTDIR)$(MANDIR)/$(MAN)"

install-strip: out/$(PROJECT)
	$(INSTALL) -D -s "out/$(PROJECT)" "$(BINDIR)/$(PROJECT)"
	$(INSTALL) -D -m 644 $(MAN) "$(DESTDIR)$(MANDIR)/$(MAN)"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(PROJECT)" "$(DESTDIR)$(MANDIR)/$(MAN)"

out/$(PROJECT): $(PROJECT).cc
	mkdir -p out
	$(CXX) $(COMMON_CXXFLAGS) $(PKG_CXXFLAGS) $(CPPFLAGS) $(CXXFLAGS) $< $(PKG_LDFLAGS) $(LDFLAGS) -o $@


test/data/big.zip: test/make_big_zip.py
	python3 test/make_big_zip.py

test/data/collisions.zip: test/make_collisions.py
	python3 test/make_collisions.py

test/data/deep.tar: test/make_deep.py
	python3 test/make_deep.py

test/data/many_nodes.zip: test/make_many_nodes.py
	python3 test/make_many_nodes.py

.PHONY: all check check-fast clean clean-data doc install install-strip test uninstall
