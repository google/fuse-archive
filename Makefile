PROJECT = fuse-archive
PKG_CONFIG ?= pkg-config
DEPS = fuse libarchive
CXXFLAGS += $(shell $(PKG_CONFIG) --cflags $(DEPS))
LDFLAGS += $(shell $(PKG_CONFIG) --libs $(DEPS))
CXXFLAGS += -std=c++20 -Wall -Wextra -Wno-missing-field-initializers -Wno-sign-compare -Wno-unused-parameter

ifeq ($(DEBUG), 1)
CXXFLAGS += -O0 -g
else
CXXFLAGS += -O2 -DNDEBUG
endif

PREFIX = $(DESTDIR)/usr
BINDIR = $(PREFIX)/bin
MAN = $(PROJECT).1
MANDIR = $(PREFIX)/share/man/man1
INSTALL = install


all: out/$(PROJECT)

check: all
	go run test/go/check.go

clean:
	rm -rf out

doc: $(MAN)
	man -l $(MAN)

$(MAN): README.md
	pandoc $< -s -t man -o $@

install: out/$(PROJECT)
	$(INSTALL) -D "out/$(PROJECT)" "$(BINDIR)/$(PROJECT)"
	$(INSTALL) -D -m 644 $(MAN) "$(MANDIR)/$(MAN)"

uninstall:
	rm "$(BINDIR)/$(PROJECT)" "$(MANDIR)/$(MAN)"

out/fuse-archive: src/main.cc
	mkdir -p out
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< $(LDFLAGS) -o $@

.PHONY: all check clean doc install uninstall
