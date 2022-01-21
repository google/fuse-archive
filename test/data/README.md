`archive.*` was copied from the github.com/google/wuffs test/data directory,
released under the same Apache 2 license.

`as-i-was-going-to-st-ives.tar.bz2` is an archive containing a rich directory
tree (but the 2401 leaves are empty files) inspired by the traditional rhyme:

    As I was going to St Ives,
    I met a man with seven wives,
    Each wife had seven sacks,
    Each sack had seven cats,
    Each cat had seven kits:
    Kits, cats, sacks, and wives,
    How many were there going to St Ives?

It was created by:

    for w in {1..7}; do
        for s in {1..7}; do
            for c in {1..7}; do
                mkdir -p m/w$w/s$s/c$c;
                for k in {1..7}; do
                    touch m/w$w/s$s/c$c/k$k;
                done
            done
        done
    done
    tar cvjf as-i-was-going-to-st-ives.tar.bz2 m

`dot-slash-foo` was created by:

    touch foo
    tar cf dot-slash-foo.tar ./foo

`romeo.txt` is an excerpt of Shakespeare's "Romeo and Juliet", copied from
[shakespeare.mit.edu](http://shakespeare.mit.edu/romeo_juliet/romeo_juliet.2.2.html).

`zeroes-256mib.tar.gz` was created by:

    truncate --size=256M zeroes
    tar cfz zeroes-256mib.tar.gz zeroes
