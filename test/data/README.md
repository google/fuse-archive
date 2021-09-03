`archive.*` was copied from the github.com/google/wuffs test/data directory,
released under the same Apache 2 license.

`romeo.txt` is an excerpt of Shakespeare's "Romeo and Juliet", copied from
[shakespeare.mit.edu](http://shakespeare.mit.edu/romeo_juliet/romeo_juliet.2.2.html).

`zeroes-256mib.tar.gz` was created by:

    $ truncate --size=256M zeroes
    $ tar cfz zeroes-256mib.tar.gz zeroes
