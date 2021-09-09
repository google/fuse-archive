PKG_CONFIG?=pkg-config
pkgcflags=$(shell $(PKG_CONFIG) libarchive fuse --cflags)
pkglibs=$(shell   $(PKG_CONFIG) libarchive fuse --libs)

prefix=/usr/local
bindir=$(prefix)/bin

override CXXFLAGS := -O3 $(CXXFLAGS)

all: out/fuse-archive

check: all
	go run test/go/check.go

clean:
	rm -rf out

install: all
	mkdir -p "$(DESTDIR)$(bindir)"
	install out/fuse-archive "$(DESTDIR)$(bindir)"

uninstall:
	rm "$(DESTDIR)$(prefix)/bin/fuse-archive"

out/fuse-archive: src/main.cc
	mkdir -p out
	$(CXX) $(CXXFLAGS) $(pkgcflags) $< $(LDFLAGS) $(pkglibs) -o $@

.PHONY: all check clean install uninstall
