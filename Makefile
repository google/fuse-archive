pkgcflags=`pkg-config libarchive fuse --cflags`
pkglibs=  `pkg-config libarchive fuse --libs`
prefix=/usr/local

override CXXFLAGS := -O3 $(CXXFLAGS)

all: out/fuse-archive

clean:
	rm -rf out

install: all
	mkdir -p "$(DESTDIR)$(prefix)/bin"
	install out/fuse-archive "$(DESTDIR)$(prefix)/bin"

uninstall:
	rm "$(DESTDIR)$(prefix)/bin/fuse-archive"

out/fuse-archive: src/main.cc
	mkdir -p out
	$(CXX) $(CXXFLAGS) $(pkgcflags) $< $(LDFLAGS) $(pkglibs) -o $@

.PHONY: all clean install uninstall
