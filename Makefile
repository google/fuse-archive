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
MAN = fuse-archive.1

prefix=/usr
bindir=$(prefix)/bin
mandir=$(prefix)/share/man/man1

all: out/fuse-archive

check: all
	go run test/go/check.go

clean:
	rm -rf out

doc: $(MAN)
	man -l $(MAN)

$(MAN): README.md
	pandoc $< -s -t man -o $@

install: all
	mkdir -p "$(DESTDIR)$(bindir)"
	install out/fuse-archive "$(DESTDIR)$(bindir)"
	mkdir -p "$(DESTDIR)$(mandir)"
	install fuse-archive.1 "$(DESTDIR)$(mandir)"

uninstall:
	rm "$(DESTDIR)$(prefix)/bin/fuse-archive"

out/fuse-archive: src/main.cc
	mkdir -p out
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< $(LDFLAGS) -o $@

.PHONY: all check clean doc install uninstall
