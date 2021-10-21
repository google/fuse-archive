#!/bin/bash -eu
# Copyright 2021 The Fuse-Archive Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# ----------------

# This script exercises the asyncprogress=foo.bar command line option. The
# output should show an artificial foo.bar file (whose mtime ticks up to 12
# January 1970, one million seconds since Unix epoch) followed by the real
# contents of the archive file argument $1. It should look something like:
#
# make: Nothing to be done for 'all'.
# total 0
# ---------- 1 user user 0 Jan  1  1970 foo.bar
# total 0
# ---------- 1 user user 0 Jan  4  1970 foo.bar
# total 0
# ---------- 1 user user 0 Jan  8  1970 foo.bar
# total 0
# ---------- 1 user user 0 Jan 12  1970 foo.bar
# total 0
# drwxrwxr-x 1 user user 0 Mar 10  2019 linux-5.0.1
# total 0
# drwxrwxr-x 1 user user 0 Mar 10  2019 linux-5.0.1
# total 0
# drwxrwxr-x 1 user user 0 Mar 10  2019 linux-5.0.1
# total 0
# drwxrwxr-x 1 user user 0 Mar 10  2019 linux-5.0.1
# total 0
# drwxrwxr-x 1 user user 0 Mar 10  2019 linux-5.0.1
# total 0
# drwxrwxr-x 1 user user 0 Mar 10  2019 linux-5.0.1

if [ ! -e src/main.cc ]; then
  echo "$0 should be run from the Fuse-Archive root directory."
  exit 1
fi

if [ -z "${1-}" ]; then
  echo "Pass a large (100s of MiBs) tar.xz file as an argument, e.g. download"
  echo "  https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.0.1.tar.xz"
  echo "and then run"
  echo "  $0 linux-5.0.1.tar.xz"
  exit 1
fi

make
out/fuse-archive -o nonempty,asyncprogress=foo.bar $1 test/mnt
for i in {0..9}; do
  ls -l test/mnt
  sleep 2
done
fusermount -u test/mnt
