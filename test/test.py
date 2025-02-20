#!/usr/bin/python3

# Copyright 2024 The Fuse-Archive Authors.
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

import hashlib
import logging
import os
import pprint
import random
import stat
import subprocess
import sys
import tempfile
import time


# Computes the MD5 hash of the given file.
# Returns the MD5 hash as an hexadecimal string.
# Throws OSError if the file cannot be read.
def md5(path):
    h = hashlib.md5()
    with open(path, 'rb') as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()


# Walks the given directory.
# Returns a dict representing all the files and directories.
def GetTree(root, use_md5=True):
    result = {}

    def scan(path, st):
        mode = st.st_mode
        line = {
            'ino': st.st_ino,
            'mode': stat.filemode(mode),
            'nlink': st.st_nlink,
            'uid': st.st_uid,
            'gid': st.st_gid,
            'atime': st.st_atime_ns,
            'mtime': st.st_mtime_ns,
            'ctime': st.st_ctime_ns,
        }
        result[os.path.relpath(path, root)] = line
        if stat.S_ISREG(mode):
            line['size'] = st.st_size
            try:
                if use_md5:
                    line['md5'] = md5(path)
            except OSError as e:
                line['errno'] = e.errno
        elif stat.S_ISLNK(mode):
            line['target'] = os.readlink(path)
        elif stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
            line['rdev'] = st.st_rdev
        elif stat.S_ISDIR(mode):
            for entry in os.scandir(path):
                scan(entry.path, entry.stat(follow_symlinks=False))

    st = os.stat(root, follow_symlinks=False)

    # On some systems, the mount point is not immediately functional.
    while st.st_ino == 0:
        time.sleep(0.1)
        st = os.stat(root, follow_symlinks=False)

    scan(root, st)
    return result


# Total number of errors.
error_count = 0


# Logs the given error.
def LogError(msg):
    logging.error(msg)
    global error_count
    error_count += 1


# Compares got_tree with want_tree. If strict is True, checks that got_tree
# doesn't contain any extra entries that aren't in want_tree.
def CheckTree(got_tree, want_tree, strict=False):
    for name, want_entry in want_tree.items():
        try:
            got_entry = got_tree.pop(name)
            for key, want_value in want_entry.items():
                got_value = got_entry.get(key)
                if got_value != want_value:
                    LogError(
                        f'Mismatch for {name!r}[{key}] got: {got_value!r}, want:'
                        f' {want_value!r}'
                    )
        except KeyError:
            LogError(f'Missing entry {name!r}')

    if strict and got_tree:
        LogError(f'Found {len(got_tree)} unexpected entries: {got_tree}')


# Directory of this test program.
script_dir = os.path.dirname(os.path.realpath(__file__))

# Directory containing the archives to mount.
data_dir = os.path.join(script_dir, 'data')

# Path of the FUSE mounter.
mount_program = os.path.join(script_dir, '..', 'out', 'fuse-archive')


# Mounts the given archive, walks the mounted archive and unmounts.
# Returns a pair where:
# - member 0 is a dict representing the mounted archive.
# - member 1 is the result of os.statvfs
#
# Throws subprocess.CalledProcessError if the archive cannot be mounted.
def MountArchiveAndGetTree(zip_name, options=[], password='', use_md5=True):
    with tempfile.TemporaryDirectory() as mount_point:
        zip_path = os.path.join(script_dir, 'data', zip_name)
        logging.debug(f'Mounting {zip_path!r} on {mount_point!r}...')
        subprocess.run(
            [mount_program, *options, zip_path, mount_point],
            check=True,
            capture_output=True,
            input=password,
            encoding='UTF-8',
        )
        try:
            logging.debug(f'Mounted archive {zip_path!r} on {mount_point!r}')
            return GetTree(mount_point, use_md5=use_md5), os.statvfs(mount_point)
        finally:
            logging.debug(f'Unmounting {zip_path!r} from {mount_point!r}...')
            subprocess.run(['fusermount', '-u', '-z', mount_point], check=True)
            logging.debug(f'Unmounted {zip_path!r} from {mount_point!r}')


# Mounts the given archive, checks the mounted archive tree and unmounts.
# Logs an error if the archive cannot be mounted.
def MountArchiveAndCheckTree(
    zip_name,
    want_tree,
    want_blocks=None,
    want_inodes=None,
    options=[],
    password='',
    strict=True,
    use_md5=True,
):
    s = f'Test {zip_name!r}'
    if options: s += f', options = {" ".join(options)!r}'
    if password: s += f', password = {password!r}'
    logging.info(s)
    try:
        got_tree, st = MountArchiveAndGetTree(
            zip_name, options=options, password=password, use_md5=use_md5
        )

        want_block_size = 512
        if st.f_bsize < want_block_size:
            LogError(
                f'Mismatch for st.f_bsize: got: {st.f_bsize}, want at least: {want_block_size}'
            )
        if st.f_frsize != want_block_size:
            LogError(
                'Mismatch for st.f_frsize: '
                f'got: {st.f_frsize}, want: {want_block_size}'
            )

        want_name_max = 255
        if st.f_namemax != want_name_max:
            LogError(
                'Mismatch for st.f_namemax: '
                f'got: {st.f_namemax}, want: {want_name_max}'
            )

        if want_blocks is not None and st.f_blocks != want_blocks:
            LogError(
                f'Mismatch for st.f_blocks: got: {st.f_blocks}, want: {want_blocks}'
            )

        if want_inodes is not None and st.f_files != want_inodes:
            LogError(
                f'Mismatch for st.f_files: got: {st.f_files}, want: {want_inodes}'
            )

        CheckTree(got_tree, want_tree, strict=strict)
    except subprocess.CalledProcessError as e:
        LogError(f'Cannot test {zip_name}: {e.stderr}')


# Try to mount the given archive, and expects an error.
# Logs an error if the archive can be mounted, or if the returned error code doesn't match.
def CheckArchiveMountingError(zip_name, want_error_code, options=[], password=''):
    s = f'Test {zip_name!r}'
    if options: s += f', options = {" ".join(options)!r}'
    if password: s += f', password = {password!r}'
    logging.info(s)
    try:
        got_tree, _ = MountArchiveAndGetTree(
            zip_name, options=options, password=password
        )
        LogError(f'Want error, Got tree: {got_tree}')
    except subprocess.CalledProcessError as e:
        if e.returncode != want_error_code:
            LogError(
                f'Want error: {want_error_code}, Got error: {e.returncode} in {e}'
            )


def GenerateReferenceData():
    for zip_name in os.listdir(os.path.join(script_dir, 'data')):
        tree, _ = MountArchiveAndGetTree(zip_name, password='password')
        all_zips[zip_name] = tree

    pprint.pprint(all_zips, compact=True, sort_dicts=False)


# Tests most of the archive files in data_dir using default mounting options.
def TestArchiveWithOptions(options=[]):
    want_trees = {
        'empty.tar': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
        },
        'empty.tar.gz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
        },
        'empty.tgz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
        },
        # This should not be mistaken for an mtree archive.
        # https://github.com/google/fuse-archive/issues/43
        'test.csv.gz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'test.csv': {'mode': '-rw-r--r--', 'mtime': 1739773077000000000, 'size': 88, 'md5': '9359ea183fa52719372753e6ca34e3b1'}
        },
        'archive.zip': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.zip.gz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'archive.zip': {'ino': 2, 'mode': '-rw-r--r--', 'mtime': 1701219888000000000, 'size': 3480, 'md5': 'e43a4ee1eb970d00b6c0ebf6e25347d5'},
        },
        'archive.rar': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tar': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tar.gz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tgz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tar.bz2': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tbz2': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tbz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tb2': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tz2': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tar.lrz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tar.lz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tar.lz4': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tlz4': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tar.lzma': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tlzma': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tar.lzo': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tar.xz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.txz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tar.zst': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tzst': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tar.Z': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.taz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.tz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.7z': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.cab': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rw-r--r--', 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'archive.iso': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 4},
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'},
        },
        'data_descriptor.zip': {
            '.': {'mode': 'drwxr-xr-x'},
            '-': {'mode': '-rw-r--r--', 'size': 305, 'md5': 'c60b77c7b1cad939d1dee69925b2e47b'},
            'second.txt': {'mode': '-rw-r--r--', 'size': 320, 'md5': 'da1344f8f5f2e52fae7671250d81376e'}
        },
        'mixed-paths.zip': {
            '.': {'mode': 'drwxr-xr-x'},
            "Quote ' (1)": {'md5': '3ca0f2a7d572f3ad256fcd13e39bd8da'},
            "Quote ' (2)": {'md5': '60e20f9b84bf0fe96e7d226341aaf72d'},
            "Quote '": {'md5': '71e103fda7cffdb58b4aa44fa540efce'},
            '  (1)': {'md5': 'fc520ede1760d4e64770b48ba8f859fb'},
            '  (2)': {'md5': '9d0c61de9c0cdc3aec1221d3b00f6af1'},
            ' ': {'md5': '4ecf69a9cb2cce4469fbea4cab35277d'},
            ' (1)': {'md5': 'd4afca8308970d15340aa4f83fcd1503'},
            ' (2)': {'md5': 'ce7bda717aef111cace3a9687b474b15'},
            ' (3)': {'md5': 'dbb5fe07c92222392511fc3ce4ca0240'},
            ' ←Space (1)': {'md5': '42f00634c4115c5f67d9be6a1cfa414c'},
            ' ←Space (2)': {'md5': 'a4506a1c46eaab6a62de9d5ddb80666b'},
            ' ←Space': {'md5': '9f407c9493c1ccc2458ab776b0e3efcf'},
            '$HOME (1)': {'md5': 'c41dc9371b2be069bd8e013c428ace13'},
            '$HOME (2)': {'md5': 'e40b01b5ff1cc66197d3428919a18da4'},
            '$HOME': {'md5': 'aedeaeef1d21c8bb6afe8c1252f7d3c8'},
            '%TMP% (1)': {'md5': '8ecc4766c79654383ed3e1ec4cefd5ce'},
            '%TMP% (2)': {'md5': 'edb312c5d6d077b0a27f5bf1e7117206'},
            '%TMP%': {'md5': 'a0e10b52aca6cc8b673d6eeb72f2f95f'},
            '- (1)': {'md5': '704efc6cc347fcdf01585e2ee91c80fa'},
            '- (2)': {'md5': '6c561d06c7890a70215c3f253cb6bb02'},
            '-': {'md5': '0015ecf55d7da11c150a666e0583c9fa'},
            '.' * 251 + ' (1)': {'md5': 'd73c3af2bb73f18416eae424d2bb1226'},
            '.' * 251 + ' (2)': {'md5': 'ab6a815c651781866cf22f96699954cb'},
            '.' * 251 + ' (3)': {'md5': '35eef262524368b8c99d28d1b9018629'},
            '.' * 251 + ' (4)': {'md5': '804600f4aa79357fe896a10773bf78fa'},
            '.' * 251 + ' (5)': {'md5': '707b9ac9459e6dda9da9abd0957a21bc'},
            '.' * 255: {'md5': 'cc3b7dadd6280c4586748318e2ee6b1e'},
            '... (1)': {'md5': '24b8fb13b27ae0e9d0da9cc411c279c6'},
            '... (2)': {'md5': '05e8526f15d1bee44e8e0f526fb93f3a'},
            '... (3)': {'md5': 'd554ecc8f6a782ab311a81f38b095ef5'},
            '... (4)': {'md5': '7a51680c3febd5563773fe9a8090ee73'},
            '... (5)': {'md5': '66a818b0b78bd22bc33f330de5101c00'},
            '...': {'md5': 'b246079eb0c241c0ad50a30873701b7d'},
            '.... (1)': {'md5': 'bf4189b1f38be5379b3c8e330e14ef00'},
            '.... (2)': {'md5': 'c0ddf361e9cce0a3d1ce734023c99852'},
            '....': {'md5': '51cd1872e35401de1969f1c53c32332a'},
            '...Three (1)': {'md5': '205a4fa1968f1a05d90a5810d7daea5a'},
            '...Three (2)': {'md5': 'fed163fdc049f5ba0347e27de9e3b75e'},
            '...Three (3)': {'md5': 'be8c7e5c8149543bfb0b899a63dfd3a5'},
            '...Three (4)': {'md5': 'a32371c48bdd02833ececf98ab629ff1'},
            '...Three (5)': {'md5': '2cdb1981a75f35b3e2c7b35ad04aa461'},
            '...Three': {'md5': 'ea9951c389c3bcd6355df418e6338d86'},
            '..Two (1)': {'md5': 'e2bafe9b9dab8502c8dd91a7cd304aca'},
            '..Two (2)': {'md5': '6372fc10e660a6bf413b9fe3e52cf6df'},
            '..Two': {'md5': '3676540e9ef52c8fec43c1705e547270'},
            '.One (1)': {'md5': '695b92c19227b154a9ad4c7454e60954'},
            '.One (2)': {'md5': '69ef0885b6ec5b8434bf67767b061924'},
            '.One': {'md5': '39c89ab7f825d93e11273cee816983d1'},
            '.foo (1).txt': {'md5': '8ff4eea96f318c3cbe8e6a713c8ad8af'},
            '.foo (2).txt': {'md5': '1c758452430d22a7bb54798873ea854f'},
            '.foo (3).txt': {'md5': '88a416d7c9817c188596d3dcb553c9ca'},
            '.foo (4).txt': {'md5': '568de72385d3ccc1d21fa2ccf4a1517f'},
            '.foo (5).txt': {'md5': '634a6c97ee76c4032c06f0769f0601b6'},
            '.foo.txt': {'md5': '52a1b1c7d65f4d9cdd41425f861150f7'},
            '?': {'md5': 'e3f500a4fad52d4b13d9f5c58b42714b'},
            '? (1)': {'md5': '23158c8ba1b968745324a3634906c7e7'},
            '? (2)': {'md5': 'e6ade0e8b4f62d8d7ea74abd60f18027'},
            '? (3)': {'md5': '3e9c3a7b046474add2da5aa3397c3170'},
            '? (4)': {'md5': '72878fc9a1ae28aef32afff602158d4a'},
            '? (5)': {'md5': 'ebee9acee0ac49c76eb2de67051592c0'},
            'Over The Top (1)': {'md5': 'd597b0c4199d9bdf2e0f7400174d7ebe'},
            'Over The Top (2)': {'md5': '3ce3fb4e0e1c86b1b07f992678a04664'},
            'Over The Top': {'md5': '991393263550ac730626a64f139eddb3'},
            'AUX (1)': {'md5': '7fdc6b9a4f48109c19455764fad5f7a0'},
            'AUX (2)': {'md5': '6b02202ccdafa51eae1f6425d608709c'},
            'AUX': {'md5': '3f69a27bc959159d6911d1d2f44ecfb5'},
            'Ampersand & (1)': {'md5': '7ddd78b542607296a9a5e93745b82297'},
            'Ampersand & (2)': {'md5': '31184f350acc30d15ffac762acde7304'},
            'Ampersand &': {'md5': '255622e1d13e054c5b0e9365c9a723bf'},
            'Angle <> (1)': {'md5': '36fbea036273dc1917a3e7e3b573dd22'},
            'Angle <> (2)': {'md5': 'c98dc6a537865f0896db87452784280b'},
            'Angle <>': {'md5': '1c5cbe4d86c73de115eb48de5cf0eeea'},
            'At @ (1)': {'md5': 'dccf5a36da117a1b9ea52f6aa1d46dca'},
            'At @ (2)': {'md5': '40d05f890dcda5552b7b87f1b1223b1a'},
            'At @': {'md5': 'cabcc9ad22fd30b2fe3220785474d9d8'},
            'At The Top (1)': {'md5': 'ba54e1aca97bad73f835c5d1c858417c'},
            'At The Top (2)': {'md5': '2d56b90a936b4f2b7f9ba2e4ef1fbd83'},
            'At The Top': {'md5': '9ef02862743242d23ce6ed223c38b707'},
            'Backslash ': {'mode': 'drwxr-xr-x'},
            'Backspace \x08 (1)': {'md5': 'a14e44a642e9037c3c298348093ec380'},
            'Backspace \x08 (2)': {'md5': 'a52f6c6706cfe008497efe714eb2a5ff'},
            'Backspace \x08': {'md5': '5d2071685575754babe374981552164b'},
            'Backtick ` (1)': {'md5': 'b92aae294d43c3e081397788bcdeda77'},
            'Backtick ` (2)': {'md5': '714d2283f6384ffabcf1c403ad0ebb3e'},
            'Backtick `': {'md5': '44a52fddfbaf7c0c213c20192744afd5'},
            'Bell \x07 (1)': {'md5': 'd42111a8d9d715d6ca13f870c03bb136'},
            'Bell \x07 (2)': {'md5': 'a9e9d87ea96b4f4e8797820c7ac19df1'},
            'Bell \x07': {'md5': 'aafdd252197512170d856086452836a9'},
            'C:': {'mode': 'drwxr-xr-x'},
            'C:/Temp': {'mode': 'drwxr-xr-x'},
            'C:/Temp/File (1)': {'md5': 'ca11bb68c069615a4b9b6eecedae436b'},
            'C:/Temp/File (2)': {'md5': 'de6cf0f9e21e500d452ca1731148a774'},
            'C:/Temp/File': {'md5': '09e89cca300f6ad14c9c614fb95c33b0'},
            'CASE (1)': {'md5': '00b78d79abf97077fbf025f3355fddb2'},
            'CASE (2)': {'md5': '53e44ae7ecdff196ff18881fae2a4c31'},
            'CASE': {'md5': 'e92836e4b17a39306f51d13ead0a09e4'},
            'CLOCK$ (1)': {'md5': '4a89d1ec340b7984fce1828f32b17a1b'},
            'CLOCK$ (2)': {'md5': 'a10ee44c95468f79c4d76acbc431f2d9'},
            'CLOCK$': {'md5': '306be585c84e6ed5aab5070e9846121d'},
            'COM1 (1)': {'md5': '7126112f4c33e7530fffcf7278a5e719'},
            'COM1 (2)': {'md5': '619a4330a4dd8433f2b27ceb9e2c575c'},
            'COM1': {'md5': 'a613354228a8154a5c980526c82d7efe'},
            'COM9 (1)': {'md5': '7c904dcc4bb875a99e403d6a41d97c2a'},
            'COM9 (2)': {'md5': 'c0a1e5c28a2359f61cc4531df14d0892'},
            'COM9': {'md5': '413d4b59327743bb2d8ce59f41fd1f41'},
            'CON (1)': {'md5': 'a6a5ee67a986dc6270311f631c2d403d'},
            'CON (2)': {'md5': '66673cda9a9e98f3ab3f7194ead33958'},
            'CON': {'md5': '407f3ff633ac1822974ce5e1a07ac9e5'},
            'Café (1)': {'md5': 'b7ce2be1dfb8cf535bccf1036284900c'},
            'Café (2)': {'md5': '637f113e67522f774879f6f63f3093da'},
            'Café (3)': {'md5': 'e9e59d2978d1ffcfc11274fcedea35d6'},
            'Café (4)': {'md5': 'f60233605389c3fc8ba841d202860c38'},
            'Café (5)': {'md5': '4f51f74e22dd4e3a77f965d77daffb4b'},
            'Café': {'md5': '080f684e7afffcc022c53359c1b6d968'},
            'Caret ^ (1)': {'md5': '6ecbe85c819de33f1a1566fc6a49b148'},
            'Caret ^ (2)': {'md5': '4037bf95d8b2a026056c6be3cb88f16d'},
            'Caret ^': {'md5': '327e8a9bae15530ada822c20e6e875f2'},
            'Carriage Return \r (1)': {'md5': '1657ca6d389450c66dcb3737ade632d4'},
            'Carriage Return \r (2)': {'md5': 'f5f79fbe6bd369bb344d2acb1500f3a0'},
            'Carriage Return \r': {'md5': '5b5600d7515e86d01364bc6f066cfc14'},
            'Case (1)': {'md5': 'b33984146a2bb8c8fc337362e91d1911'},
            'Case (2)': {'md5': '2653ca3273626a97a5b9155b83511e44'},
            'Case': {'md5': 'f39791e31c562ce31a325a188c405d02'},
            'Colon : (1)': {'md5': '662fcf045861ca1e9be6466f34f23846'},
            'Colon : (2)': {'md5': '30b9479836d7aab4428db84a4435de2b'},
            'Colon :': {'md5': 'bad98d8795bd453e675ae45cf511cb6f'},
            'Comma , (1)': {'md5': '741313ce46594c276d4dbf8c50a3c242'},
            'Comma , (2)': {'md5': 'dbe2d9051ca9c7ad197acdd39644c151'},
            'Comma ,': {'md5': '8e4e2a35ea3db7e1f0c71e9e260e3f2b'},
            'Curly {} (1)': {'md5': '5e75818b995fac62fd10046e918a6d68'},
            'Curly {} (2)': {'md5': '2526b1e0fdb6a56ef9c7104b0432295a'},
            'Curly {}': {'md5': '7f80122391b3c4f8af113d08784576bb'},
            'Dash - (1)': {'md5': 'c2fe85e07ed29f1907466647d8e7de73'},
            'Dash - (2)': {'md5': '394758376fd6bece3d8c523911d4802f'},
            'Dash -': {'md5': '367fcecd09ee039d04346ca9483f15b0'},
            'Delete \x7f (1)': {'md5': '63f936c1f9b6679f6448d6b9dd6907e9'},
            'Delete \x7f (2)': {'md5': '1e5f71a3210f3572ad57cd0f8db7c773'},
            'Delete \x7f': {'md5': '3ffe534d559861937f43e74252183f7d'},
            'Dollar $ (1)': {'md5': '785fcb195fd44a2d958ab601533aaa93'},
            'Dollar $ (2)': {'md5': 'ad033aafabafeeece964f7558f5e0110'},
            'Dollar $': {'md5': '8e567128bd3120c6b504f0ea1c078591'},
            'Dot . (1)': {'md5': 'd6bbeadd3e2949c9a97863faf7941fd1'},
            'Dot . (2)': {'md5': 'ba3e606d9d97dcaa1903c77b4caa62a7'},
            'Dot .': {'md5': 'f312d5c330e833d409ad05fe206b3099'},
            'Double quote " (1)': {'md5': '843b0fa6d0bd93d58b5a1a0960c4be2f'},
            'Double quote " (2)': {'md5': '94912b944529fe9ac74f1d17ffd685ed'},
            'Double quote "': {'md5': '7b20185b51dbce9398dfbe5b3c5c2f44'},
            'Empty': {'mode': 'drwxr-xr-x'},
            'Equal = (1)': {'md5': '83379a04a3ee4566eb3605bc3f5a4ab4'},
            'Equal = (2)': {'md5': '7891ccb015f7c6daec40bbd16c8075ec'},
            'Equal =': {'md5': '69b9497f9f34aba975699c833d037666'},
            'Escape \x1b (1)': {'md5': '9e3c4cefd408009286d5b418ae9988db'},
            'Escape \x1b (2)': {'md5': '8e7878beac19e997da1ef12bd481cb44'},
            'Escape \x1b': {'md5': '1c1ee3412c62f438d4403816482ed486'},
            'Euro € (1)': {'md5': '54dd622a6f10eed2cd59ed2a6f594ef2'},
            'Euro € (2)': {'md5': '3ee86efa36d8cf102288ad2bf936dfa8'},
            'Euro €': {'md5': '8e79df94fcaf890f6433ecf48152919d'},
            'Exclamation ! (1)': {'md5': '10e762da30d7793ee14e7bf0c154078b'},
            'Exclamation ! (2)': {'md5': '22520ad75ab8d3b28e90fd7a4fc2bfc8'},
            'Exclamation !': {'md5': '255abe4fe8bbb0b4f8411913673388fe'},
            'FileOrDir (1)': {'md5': '616efa472d51b7f5aacab007d9a635be'},
            'FileOrDir (2)': {'md5': 'be82b39076b03bcf3828ab09b1c34582'},
            'FileOrDir (3)': {'md5': 'e503e8e89925339aefb47443581ba4bc'},
            'FileOrDir': {'mode': 'drwxr-xr-x'},
            'Hash # (1)': {'md5': '37715cd1852064027118eb0e466d1172'},
            'Hash # (2)': {'md5': '38730629648b8780fe1f4f90738eb6a1'},
            'Hash #': {'md5': '2c33603f6b59836dc9dd61bbd6f47b6d'},
            'LPT1 (1)': {'md5': '695771298fcc161d5375e7ef65fe0cbf'},
            'LPT1 (2)': {'md5': '4c6478198627fe5d5d8ca588782502ea'},
            'LPT1': {'md5': 'e9aa40253c2cda7319f60e127b7a5d2b'},
            'LPT9 (1)': {'md5': '338ad2a4d01b83966a2d93b84991079c'},
            'LPT9 (2)': {'md5': 'a5ee3dd960f9c0457cc778afdc1bc45e'},
            'LPT9': {'md5': 'b5908fed9f25a430cc17f41058517fd7'},
            'Line Feed \n (1)': {'md5': '3e1c022c4be1b6d982289cbd6aeb9eba'},
            'Line Feed \n (2)': {'md5': 'fc8dfff4cc4757c29ab931d9e7f954e9'},
            'Line Feed \n': {'md5': '72af886a4aed8ad6885a7f786ec5b661'},
            'NUL (1)': {'md5': '95c40e86277b9e90a040c3b302d7562c'},
            'NUL (2)': {'md5': 'd6516225315fb534b075c396016ca039'},
            'NUL': {'md5': '485ca989764c13cf55f8ab3d839cfd1e'},
            'One. (1)': {'md5': 'a85a42df93c1b1365a6a593e07a3f80a'},
            'One. (2)': {'md5': 'a05d70a56ff44a1fa4b42a55d5a29c19'},
            'One.': {'md5': 'ab394e10e5ef36efedc9e415c2c3cb42'},
            'PRN (1)': {'md5': '193b412ab1a91011b5ea7accb3c146c2'},
            'PRN (2)': {'md5': 'dc5ef433ccf07082e793a71e17dd2b1f'},
            'PRN': {'md5': 'c6f96d5f3a7313541646d5d8b951dc0d'},
            'Percent % (1)': {'md5': 'c8dd7a81eaf6d6c8e817657aa45063ef'},
            'Percent % (2)': {'md5': '5dca4785fee3d3cf8b7a090555409e1a'},
            'Percent %': {'md5': 'bc402953f32f33d3e8c17360557bd294'},
            'Pipe | (1)': {'md5': '8f2eaf2f601cfc28087f0826c0d0415d'},
            'Pipe | (2)': {'md5': '715f63380171ee77dd2057cff284edd7'},
            'Pipe |': {'md5': '6dfa11c10b119a6f0bea267804707f59'},
            'Plus + (1)': {'md5': '00a706dba456a2da0c8175498c1c2e0a'},
            'Plus + (2)': {'md5': '9dfada89dcbd35eb95e6d6882f4eb79b'},
            'Plus +': {'md5': '2517d92c6a28e82e53086558f599f7a3'},
            'Question ? (1)': {'md5': '2b04a6c5990e28e981052c2a1b487891'},
            'Question ? (2)': {'md5': '96ae8325f90df4cfb401b3d40c65417d'},
            'Question ?': {'md5': '4762c2deeccd2243cbe2c750f6027608'},
            'Round () (1)': {'md5': '66a98a72d65a794b288469d1b9f5a9c7'},
            'Round () (2)': {'md5': '347ea63daa56787225c2575a277fefcf'},
            'Round ()': {'md5': 'ea2053ca1e8235aec047f2debca62161'},
            'Semicolon ; (1)': {'md5': '3ee36aec082f0d0c9f89145d4d3081f8'},
            'Semicolon ; (2)': {'md5': '7977cacb02ea2bbb75517dde267e6904'},
            'Semicolon ;': {'md5': '789f0142366e24b2ce19c7248b3c1103'},
            'Smile 🙂 (1)': {'md5': 'bafa29d272d040544572ab3b4e5cc497'},
            'Smile 🙂 (2)': {'md5': '581599352cd9dda6a541481952d06048'},
            'Smile 🙂': {'md5': 'a870c6b6877e97c950d18d95505a9769'},
            'Space→  (1)': {'md5': '2c8a1745d3f0add39eb277b539fdfeaa'},
            'Space→  (2)': {'md5': 'e272aa59f06c6b9f3af33c941e6b3c5a'},
            'Space→ ': {'md5': '20f9a99e85968869900467f65298c1ba'},
            'Square [] (1)': {'md5': 'bc066cc3c9934b31a337260efc99d1df'},
            'Square [] (2)': {'md5': 'fc77bf99b696d888e4ca937f8cf5097a'},
            'Square []': {'md5': '47a86abc13e9703ca7457ea9e29b83b1'},
            'Star * (1)': {'md5': '2a9362d8d04ce694c85e4d054fa72763'},
            'Star * (2)': {'md5': '341c4e1e9785c4658250c1a37e9fd04f'},
            'Star *': {'md5': '1e1d1d592ee97949db5fa6d1db01a06f'},
            'String Terminator \x9c (1)': {'md5': 'ba7f76d662af39dfbaeb3899c46978ef'},
            'String Terminator \x9c (2)': {'md5': '33abcf5fd9bff50dc5f97592a133d1d2'},
            'String Terminator \x9c': {'md5': 'ad901030332576dfb289e848d7ef5721'},
            'Tab \t (1)': {'md5': '76635ca0e84ce5af2d08804b81fe33e0'},
            'Tab \t (2)': {'md5': '3f92d47d30f56412f37b81aaf302d5eb'},
            'Tab \t': {'md5': 'f546955680b666f1f4ed2cddb173d142'},
            'Three... (1)': {'md5': '79d37b7eedc1aa7d1d54fdf906ea32f4'},
            'Three... (2)': {'md5': '17715f0b716cf0061fce3c6ac99fa035'},
            'Three... (3)': {'md5': '2cc2c8026d87a4a2ee0175d3977bd9db'},
            'Three... (4)': {'md5': 'cc8a892db5bbb6e00783911a977e49e2'},
            'Three... (5)': {'md5': 'd79667406b09137e02359a22570cc69f'},
            'Three...': {'md5': 'fd7443b6ef5da1fe8229a64ac462fbb9'},
            'Tilde ~ (1)': {'md5': 'b9170048f08dafa6d314ff685cf56396'},
            'Tilde ~ (2)': {'md5': '44a6e1123c523c089a1fb2f622a346d9'},
            'Tilde ~': {'md5': 'd644fb4311c7b1c581ed1cbca0913ff3'},
            'Two.. (1)': {'md5': '561eaf19d31ba9f2f3a93f4a1cf740cd'},
            'Two.. (2)': {'md5': '3bfdba5a9317da55733a3aa3db8788c8'},
            'Two..': {'md5': '8b25e8cb6343c03d3dceeb5287c4414f'},
            'One Level Up (1)': {'md5': '5cfff7eb216252fd9edd35ad58f65807'},
            'One Level Up (2)': {'md5': '8926cc7e8073e1079320f2e0b4b2a05c'},
            'One Level Up': {'md5': 'd530362d8793bd2213702f7a8b9eb391'},
            'Two Levels Up (1)': {'md5': 'c1c08ba600c42750bb25007bd93fcd37'},
            'Two Levels Up (2)': {'md5': '35bdc6589118dee115df941fd9775282'},
            'Two Levels Up': {'md5': 'fefd04175ab55cbf25f4e59a62b44c2a'},
            'Three Levels Up (1)': {'md5': '5d7122fa28bb1886d90cdbaee7b8b630'},
            'Three Levels Up (2)': {'md5': '69baf719bc3af25f12c86a2c146ab491'},
            'Three Levels Up': {'md5': '77798d1b2b8f820dbf742a6416d2fd51'},
            'Underscore _ (1)': {'md5': 'c23f32b919508169a496a093839f0e04'},
            'Underscore _ (2)': {'md5': 'cdf441502a50204b943e0a8f943e0668'},
            'Underscore _': {'md5': '3ef0593f0a008dd757bfc49dc75f3f9a'},
            'a' + '🙂' * 62 + ' (1)': {'md5': '6ca3d8755b658c8c0ffe1c1d43b61b2a'},
            'a' + '🙂' * 62 + ' (2)': {'md5': '56e595f226384b9413361d435b5f5e44'},
            'a' + '🙂' * 63: {'md5': 'e1397fa63e2d64195fcedad9348182e8'},
            'a': {'mode': 'drwxr-xr-x'},
            'a/? (1)': {'size': 34, 'md5': 'fea45576dee3469614a677cac21192e3'},
            'a/? (2)': {'size': 35, 'md5': '3e3d527abc6edc59608f027a1f12e581'},
            'a/? (3)': {'size': 35, 'md5': '71f25b9671fe15d79baab1f17c4872dc'},
            'a/? (4)': {'size': 36, 'md5': '48ca4b2216dca0ec1a5de383481b12a0'},
            'a/? (5)': {'size': 34, 'md5': 'c22db2a461a51236bf132906371a5d31'},
            'a/? (6)': {'size': 35, 'md5': 'd56fdea04fc2c01f6556ed8157e4ce5c'},
            'a/?': {'mode': 'drwxr-xr-x'},
            'a/?/b (1)': {'size': 37, 'md5': 'c5bb219b8e035b24e763e1a409e1e9e8'},
            'a/?/b (2)': {'size': 37, 'md5': '7dbda963a520c0bb261685ac28bba6dd'},
            'a/?/b (3)': {'size': 38, 'md5': 'cb1028cae1d77c324c186482ae9edff5'},
            'a/?/b (4)': {'size': 36, 'md5': '6a49956b8999b6ed64b30171994ac1cf'},
            'a/?/b (5)': {'size': 37, 'md5': 'c3552b56f73b2f0e290b38bdd1fb0c69'},
            'a/?/b': {'size': 36, 'md5': '01fa5cbef17c21be0d127cf70dad97e2'},
            'ab' + '🙂' * 62 + ' (1)': {'md5': '4db72400bf44ff1bf81231513083701d'},
            'ab' + '🙂' * 62 + ' (2)': {'md5': 'f7b12f040637a6dae4263bc2817b56eb'},
            'ab' + '🙂' * 63: {'md5': 'fd0d1895da329d89e2396f8300c4f61f'},
            'abc' + '🙂' * 62 + ' (1)': {'md5': '05937261559a83256ddb4d44480bb5c4'},
            'abc' + '🙂' * 62 + ' (2)': {'md5': '6ac381136adf1f350e667f4753e65f63'},
            'abc' + '🙂' * 63: {'md5': '4d222a84ac3bd28f6efd125337e125f6'},
            'abcd' + '🙂' * 61 + ' (1)': {'md5': 'c573d71784261e3c388d489c915b879a'},
            'abcd' + '🙂' * 61 + ' (2)': {'md5': '5f19970d9d6df57bd84b506e6d81807e'},
            'abcd' + '🙂' * 62: {'md5': '51ee3f362dab5fafdb377657487fa09c'},
            'case (1)': {'md5': 'cf53c713e71b4765ebbe560c8e826868'},
            'case (2)': {'md5': '0f94a61da6aaa86267cd006c6812582a'},
            'case': {'md5': '2c6d2601bfa42243878ef4ddd9940b42'},
            'dev': {'mode': 'drwxr-xr-x'},
            'dev/null (1)': {'md5': '0542f8d179a0a5812cca12f9d1a20768'},
            'dev/null (2)': {'md5': '146840ea79bf74bd86d1e73c3a166d4b'},
            'dev/null': {'md5': '2a62812a0e6f22b55507ef85c0e3e3e4'},
            'foo (1).tar.gz': {'md5': '108c35f79486c56c344d0f064e4a511a'},
            'foo (2).tar.gz': {'md5': '387ccc3f6b2333031dc50e733f7827b2'},
            'foo (3).tar.gz': {'md5': '711ab4fd640632037360f79cda1fdc2b'},
            'foo (4).tar.gz': {'md5': '82fd4edb638dae95d133c2c870bc09eb'},
            'foo (5).tar.gz': {'md5': '0e6b54d7b2997381121a0b943e8243b4'},
            'foo.a b (1)': {'md5': 'b9210e8eda5412bf89a20cdac2e0a104'},
            'foo.a b (2)': {'md5': 'aa32c2818b3e50eda6b8fa566d0fe927'},
            'foo.a b (3)': {'md5': '30ff74a98043c1d2c015210865d456d6'},
            'foo.a b (4)': {'md5': '5e9a95548b5b6b53061ec81719bedd8e'},
            'foo.a b (5)': {'md5': 'b10267c805c7c45a8c5a09c4f36377ea'},
            'foo.a b': {'md5': '786e84bde86ba0eb1606b4df422a791d'},
            'foo.tar.gz': {'md5': '06ab92061c8deeabf83b9aefcd0d59b0'},
            'server': {'mode': 'drwxr-xr-x'},
            'server/share': {'mode': 'drwxr-xr-x'},
            'server/share/file (1)': {'md5': 'bcfef6ccd938358b6db770eb1d3de17f'},
            'server/share/file (2)': {'md5': '422825a9e933d11cf4c2f5c0f03e8224'},
            'server/share/file': {'md5': '6bf0dd24273206e58f6dae18c4e0c5d6'},
            'u': {'mode': 'drwxr-xr-x'},
            'u/v': {'mode': 'drwxr-xr-x'},
            'u/v/w': {'mode': 'drwxr-xr-x'},
            'u/v/w/x': {'mode': 'drwxr-xr-x'},
            'u/v/w/x/y': {'mode': 'drwxr-xr-x'},
            'u/v/w/x/y/z (1)': {'md5': '92ca5594530ebbe26df838c6e789a669'},
            'u/v/w/x/y/z (2)': {'md5': '5780324871ddfae6538bd0d427e1c731'},
            'u/v/w/x/y/z': {'md5': '7913f1d77a8a8d35cb62da4e8cba336a'},
            '~ (1)': {'md5': 'db7971e041320de89f83b3caa3c11c7e'},
            '~ (2)': {'md5': '115d04c23c77c6490bd9aebe9cfde881'},
            '~': {'md5': '5dc8143d7f881a02622daaeabf714329'},
            '🏳\u200d🌈' * 22 + ' (1)': {'md5': 'e15a50f8eb3fccdc26132fa06fa1205f'},
            '🏳\u200d🌈' * 22 + ' (2)': {'md5': 'e5918d1b19a95d6a0724bca2b9e74878'},
            '🏳\u200d🌈' * 23: {'md5': '8c29470e347f44ec20cd684c0f192945'},
            '🙂' * 62 + ' (1)': {'md5': '0ca3c0471e4176f8e223d69ffb67e847'},
            '🙂' * 62 + ' (2)': {'md5': '6c191a9c421da46230b4367e4b8e08d9'},
            '🙂' * 63: {'md5': '9ba840cf76707d55db222c1b90cedbfb'},
        },
        'romeo.txt.gz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1499322406000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'romeo.txt.bz2': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'romeo.txt.lrz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'romeo.txt.lz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'romeo.txt.lz4': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'romeo.txt.lzma': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'romeo.txt.lzo': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'romeo.txt.xz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'romeo.txt.zst': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'romeo.txt.Z': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'romeo.bzip2.zip': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'romeo.lzma.zip': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'romeo.xz.zip': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'zeroes-256mib.tar.gz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'zeroes': {'mode': '-rw-r--r--', 'mtime': 1630037295000000000, 'size': 268435456, 'md5': '1f5039e50bd66b290c56684d8550c6c2'},
        },
        'dot-slash-foo.tar': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            'foo': {'mode': '-rw-r--r--', 'mtime': 1641016352000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
        },
        'sparse.tar.gz': {
            '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
            # https://github.com/google/fuse-archive/issues/40
            'sparse': {'mode': '-rw-r--r--', 'size': 1073741824, 'md5': '5e4001589ffa2c5135f413a13e6800ef'},
        }
    }

    for zip_name, want_tree in want_trees.items():
        MountArchiveAndCheckTree(zip_name, want_tree, options=options)


def TestHardlinks(options=[]):
    zip_name = 'hardlinks.tgz'

    want_tree = {
        '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 3, 'mtime': 1727754916000000000},
        'Dir1': {'ino': 3, 'mode': 'drwxr-xr-x', 'nlink': 3, 'mtime': 1727754809000000000},
        'Dir1/Dir2': {'ino': 4, 'mode': 'drwxr-xr-x', 'nlink': 2, 'mtime': 1727754818000000000},
        'Dir1/Dir2/File': {'ino': 2, 'mode': '-rw-r--r--', 'nlink': 7, 'mtime': 1727754740000000000, 'size': 35, 'md5': '972fc6414a197a62c6c84fe8da0cf5ca'},
        'Dir1/File': {'ino': 2, 'mode': '-rw-r--r--', 'nlink': 7, 'mtime': 1727754740000000000, 'size': 35, 'md5': '972fc6414a197a62c6c84fe8da0cf5ca'},
        'File1': {'ino': 2, 'mode': '-rw-r--r--', 'nlink': 7, 'mtime': 1727754740000000000, 'size': 35, 'md5': '972fc6414a197a62c6c84fe8da0cf5ca'},
        'File2': {'ino': 2, 'mode': '-rw-r--r--', 'nlink': 7, 'mtime': 1727754740000000000, 'size': 35, 'md5': '972fc6414a197a62c6c84fe8da0cf5ca'},
        'File3': {'ino': 2, 'mode': '-rw-r--r--', 'nlink': 7, 'mtime': 1727754740000000000, 'size': 35, 'md5': '972fc6414a197a62c6c84fe8da0cf5ca'},
        'File4': {'ino': 2, 'mode': '-rw-r--r--', 'nlink': 7, 'mtime': 1727754740000000000, 'size': 35, 'md5': '972fc6414a197a62c6c84fe8da0cf5ca'},
        'File5': {'ino': 2, 'mode': '-rw-r--r--', 'nlink': 7, 'mtime': 1727754740000000000, 'size': 35, 'md5': '972fc6414a197a62c6c84fe8da0cf5ca'},
        'Symlink1': {'ino': 5, 'mode': 'lrwxr-xr-x', 'nlink': 3, 'mtime': 1727754873000000000, 'target': 'Target'},
        'Symlink2': {'ino': 5, 'mode': 'lrwxr-xr-x', 'nlink': 3, 'mtime': 1727754873000000000, 'target': 'Target'},
        'Symlink3': {'ino': 5, 'mode': 'lrwxr-xr-x', 'nlink': 3, 'mtime': 1727754873000000000, 'target': 'Target'},
    }

    MountArchiveAndCheckTree(zip_name, want_tree, want_blocks=15, want_inodes=5, options=options)

    want_tree = {
        '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 3, 'mtime': 1727754916000000000},
        'Dir1': {'ino': 3, 'mode': 'drwxr-xr-x', 'nlink': 3, 'mtime': 1727754809000000000},
        'Dir1/Dir2': {'ino': 4, 'mode': 'drwxr-xr-x', 'nlink': 2, 'mtime': 1727754818000000000},
        'File4': {'ino': 2, 'mode': '-rw-r--r--', 'nlink': 1, 'mtime': 1727754740000000000, 'size': 35, 'md5': '972fc6414a197a62c6c84fe8da0cf5ca'},
        'Symlink2': {'ino': 5, 'mode': 'lrwxr-xr-x', 'nlink': 1, 'mtime': 1727754873000000000, 'target': 'Target'},
    }

    MountArchiveAndCheckTree(zip_name, want_tree, want_blocks=7, want_inodes=5, options=options + ['-o', 'nohardlinks'])


# Tests dmask and fmask.
def TestMasks():
    want_tree = {
        '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 24},
        'Dir000': {'mode': 'drwxr-xr-x'},
        'Dir001': {'mode': 'drwxr-xr-x'},
        'Dir002': {'mode': 'drwxr-xr-x'},
        'Dir003': {'mode': 'drwxr-xr-x'},
        'Dir004': {'mode': 'drwxr-xr-x'},
        'Dir005': {'mode': 'drwxr-xr-x'},
        'Dir006': {'mode': 'drwxr-xr-x'},
        'Dir007': {'mode': 'drwxr-xr-x'},
        'Dir010': {'mode': 'drwxr-xr-x'},
        'Dir020': {'mode': 'drwxr-xr-x'},
        'Dir030': {'mode': 'drwxr-xr-x'},
        'Dir040': {'mode': 'drwxr-xr-x'},
        'Dir050': {'mode': 'drwxr-xr-x'},
        'Dir060': {'mode': 'drwxr-xr-x'},
        'Dir070': {'mode': 'drwxr-xr-x'},
        'Dir100': {'mode': 'drwxr-xr-x'},
        'Dir200': {'mode': 'drwxr-xr-x'},
        'Dir300': {'mode': 'drwxr-xr-x'},
        'Dir400': {'mode': 'drwxr-xr-x'},
        'Dir500': {'mode': 'drwxr-xr-x'},
        'Dir600': {'mode': 'drwxr-xr-x'},
        'Dir700': {'mode': 'drwxr-xr-x'},
        'File000': {'mode': '-rw-r--r--'},
        'File001': {'mode': '-rwxr-xr-x'},
        'File002': {'mode': '-rw-r--r--'},
        'File003': {'mode': '-rwxr-xr-x'},
        'File004': {'mode': '-rw-r--r--'},
        'File005': {'mode': '-rwxr-xr-x'},
        'File006': {'mode': '-rw-r--r--'},
        'File007': {'mode': '-rwxr-xr-x'},
        'File010': {'mode': '-rwxr-xr-x'},
        'File020': {'mode': '-rw-r--r--'},
        'File030': {'mode': '-rwxr-xr-x'},
        'File040': {'mode': '-rw-r--r--'},
        'File050': {'mode': '-rwxr-xr-x'},
        'File060': {'mode': '-rw-r--r--'},
        'File070': {'mode': '-rwxr-xr-x'},
        'File100': {'mode': '-rwxr-xr-x'},
        'File200': {'mode': '-rw-r--r--'},
        'File300': {'mode': '-rwxr-xr-x'},
        'File400': {'mode': '-rw-r--r--'},
        'File500': {'mode': '-rwxr-xr-x'},
        'File600': {'mode': '-rw-r--r--'},
        'File700': {'mode': '-rwxr-xr-x'},
    }

    MountArchiveAndCheckTree('permissions.tgz', want_tree, use_md5=False)

    want_tree = {
        '.': {'ino': 1, 'mode': 'drwx------', 'nlink': 24},
        'Dir000': {'mode': 'drwx------'},
        'Dir001': {'mode': 'drwx------'},
        'Dir002': {'mode': 'drwx------'},
        'Dir003': {'mode': 'drwx------'},
        'Dir004': {'mode': 'drwx------'},
        'Dir005': {'mode': 'drwx------'},
        'Dir006': {'mode': 'drwx------'},
        'Dir007': {'mode': 'drwx------'},
        'Dir010': {'mode': 'drwx------'},
        'Dir020': {'mode': 'drwx------'},
        'Dir030': {'mode': 'drwx------'},
        'Dir040': {'mode': 'drwx------'},
        'Dir050': {'mode': 'drwx------'},
        'Dir060': {'mode': 'drwx------'},
        'Dir070': {'mode': 'drwx------'},
        'Dir100': {'mode': 'drwx------'},
        'Dir200': {'mode': 'drwx------'},
        'Dir300': {'mode': 'drwx------'},
        'Dir400': {'mode': 'drwx------'},
        'Dir500': {'mode': 'drwx------'},
        'Dir600': {'mode': 'drwx------'},
        'Dir700': {'mode': 'drwx------'},
        'File000': {'mode': '-rw-r--r--'},
        'File001': {'mode': '-rwxr-xr-x'},
        'File002': {'mode': '-rw-r--r--'},
        'File003': {'mode': '-rwxr-xr-x'},
        'File004': {'mode': '-rw-r--r--'},
        'File005': {'mode': '-rwxr-xr-x'},
        'File006': {'mode': '-rw-r--r--'},
        'File007': {'mode': '-rwxr-xr-x'},
        'File010': {'mode': '-rwxr-xr-x'},
        'File020': {'mode': '-rw-r--r--'},
        'File030': {'mode': '-rwxr-xr-x'},
        'File040': {'mode': '-rw-r--r--'},
        'File050': {'mode': '-rwxr-xr-x'},
        'File060': {'mode': '-rw-r--r--'},
        'File070': {'mode': '-rwxr-xr-x'},
        'File100': {'mode': '-rwxr-xr-x'},
        'File200': {'mode': '-rw-r--r--'},
        'File300': {'mode': '-rwxr-xr-x'},
        'File400': {'mode': '-rw-r--r--'},
        'File500': {'mode': '-rwxr-xr-x'},
        'File600': {'mode': '-rw-r--r--'},
        'File700': {'mode': '-rwxr-xr-x'},
    }

    MountArchiveAndCheckTree('permissions.tgz', want_tree, use_md5=False, options=['-o', 'dmask=077'])

    want_tree = {
        '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 24},
        'Dir000': {'mode': 'drwxr-xr-x'},
        'Dir001': {'mode': 'drwxr-xr-x'},
        'Dir002': {'mode': 'drwxr-xr-x'},
        'Dir003': {'mode': 'drwxr-xr-x'},
        'Dir004': {'mode': 'drwxr-xr-x'},
        'Dir005': {'mode': 'drwxr-xr-x'},
        'Dir006': {'mode': 'drwxr-xr-x'},
        'Dir007': {'mode': 'drwxr-xr-x'},
        'Dir010': {'mode': 'drwxr-xr-x'},
        'Dir020': {'mode': 'drwxr-xr-x'},
        'Dir030': {'mode': 'drwxr-xr-x'},
        'Dir040': {'mode': 'drwxr-xr-x'},
        'Dir050': {'mode': 'drwxr-xr-x'},
        'Dir060': {'mode': 'drwxr-xr-x'},
        'Dir070': {'mode': 'drwxr-xr-x'},
        'Dir100': {'mode': 'drwxr-xr-x'},
        'Dir200': {'mode': 'drwxr-xr-x'},
        'Dir300': {'mode': 'drwxr-xr-x'},
        'Dir400': {'mode': 'drwxr-xr-x'},
        'Dir500': {'mode': 'drwxr-xr-x'},
        'Dir600': {'mode': 'drwxr-xr-x'},
        'Dir700': {'mode': 'drwxr-xr-x'},
        'File000': {'mode': '-rw-------'},
        'File001': {'mode': '-rwx------'},
        'File002': {'mode': '-rw-------'},
        'File003': {'mode': '-rwx------'},
        'File004': {'mode': '-rw-------'},
        'File005': {'mode': '-rwx------'},
        'File006': {'mode': '-rw-------'},
        'File007': {'mode': '-rwx------'},
        'File010': {'mode': '-rwx------'},
        'File020': {'mode': '-rw-------'},
        'File030': {'mode': '-rwx------'},
        'File040': {'mode': '-rw-------'},
        'File050': {'mode': '-rwx------'},
        'File060': {'mode': '-rw-------'},
        'File070': {'mode': '-rwx------'},
        'File100': {'mode': '-rwx------'},
        'File200': {'mode': '-rw-------'},
        'File300': {'mode': '-rwx------'},
        'File400': {'mode': '-rw-------'},
        'File500': {'mode': '-rwx------'},
        'File600': {'mode': '-rw-------'},
        'File700': {'mode': '-rwx------'},
    }

    MountArchiveAndCheckTree('permissions.tgz', want_tree, use_md5=False, options=['-o', 'fmask=077'])

    want_tree = {
        '.': {'ino': 1, 'mode': 'drwxrwxrwx', 'nlink': 24},
        'Dir000': {'mode': 'drwxrwxrwx'},
        'Dir001': {'mode': 'drwxrwxrwx'},
        'Dir002': {'mode': 'drwxrwxrwx'},
        'Dir003': {'mode': 'drwxrwxrwx'},
        'Dir004': {'mode': 'drwxrwxrwx'},
        'Dir005': {'mode': 'drwxrwxrwx'},
        'Dir006': {'mode': 'drwxrwxrwx'},
        'Dir007': {'mode': 'drwxrwxrwx'},
        'Dir010': {'mode': 'drwxrwxrwx'},
        'Dir020': {'mode': 'drwxrwxrwx'},
        'Dir030': {'mode': 'drwxrwxrwx'},
        'Dir040': {'mode': 'drwxrwxrwx'},
        'Dir050': {'mode': 'drwxrwxrwx'},
        'Dir060': {'mode': 'drwxrwxrwx'},
        'Dir070': {'mode': 'drwxrwxrwx'},
        'Dir100': {'mode': 'drwxrwxrwx'},
        'Dir200': {'mode': 'drwxrwxrwx'},
        'Dir300': {'mode': 'drwxrwxrwx'},
        'Dir400': {'mode': 'drwxrwxrwx'},
        'Dir500': {'mode': 'drwxrwxrwx'},
        'Dir600': {'mode': 'drwxrwxrwx'},
        'Dir700': {'mode': 'drwxrwxrwx'},
        'File000': {'mode': '-rw-rw-rw-'},
        'File001': {'mode': '-rwxrwxrwx'},
        'File002': {'mode': '-rw-rw-rw-'},
        'File003': {'mode': '-rwxrwxrwx'},
        'File004': {'mode': '-rw-rw-rw-'},
        'File005': {'mode': '-rwxrwxrwx'},
        'File006': {'mode': '-rw-rw-rw-'},
        'File007': {'mode': '-rwxrwxrwx'},
        'File010': {'mode': '-rwxrwxrwx'},
        'File020': {'mode': '-rw-rw-rw-'},
        'File030': {'mode': '-rwxrwxrwx'},
        'File040': {'mode': '-rw-rw-rw-'},
        'File050': {'mode': '-rwxrwxrwx'},
        'File060': {'mode': '-rw-rw-rw-'},
        'File070': {'mode': '-rwxrwxrwx'},
        'File100': {'mode': '-rwxrwxrwx'},
        'File200': {'mode': '-rw-rw-rw-'},
        'File300': {'mode': '-rwxrwxrwx'},
        'File400': {'mode': '-rw-rw-rw-'},
        'File500': {'mode': '-rwxrwxrwx'},
        'File600': {'mode': '-rw-rw-rw-'},
        'File700': {'mode': '-rwxrwxrwx'},
    }

    MountArchiveAndCheckTree('permissions.tgz', want_tree, use_md5=False, options=['-o', 'dmask=0,fmask=0'])


# Tests the archive with lots of files.
def TestArchiveWithManyFiles():
    # Only check a few files: the first one, the last one, and one in the middle.
    want_tree = {
        '1': {
            'mode': '-rw-r--r--',
            'mtime': 1371243195000000000,
            'size': 0,
        },
        '30000': {
            'mode': '-rw-r--r--',
            'mtime': 1371243200000000000,
            'size': 0,
        },
        '65536': {
            'mode': '-rw-r--r--',
            'mtime': 1371243206000000000,
            'size': 0,
        },
    }

    MountArchiveAndCheckTree(
        '65536-files.zip',
        want_tree,
        want_blocks=65537,
        want_inodes=65537,
        strict=False,
        use_md5=False,
    )

    want_tree = {
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file': {
            'size': 0,
        },
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file (1)': {
            'size': 0,
        },
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file (2)': {
            'size': 18,
        },
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file (3)': {
            'size': 0,
        },
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file (4)': {
            'size': 19,
        },
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file (5)': {
            'size': 0,
        },
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file (50000)': {
            'size': 0,
        },
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file (99999)': {
            'size': 0,
        },
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file (100000)': {
            'size': 0,
        },
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file (100001)': {
            'size': 0,
        },
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file (100002)': {
            'size': 8,
        },
    }

    MountArchiveAndCheckTree(
        'collisions.zip',
        want_tree,
        want_blocks=100017,
        want_inodes=100014,
        strict=False,
        use_md5=False,
    )


# Tests that a big file can be accessed in random order.
def TestBigArchiveRandomOrder(options=[]):
    zip_name = 'big.zip'
    s = f'Test {zip_name!r}'
    if options: s += f', options = {" ".join(options)!r}'
    logging.info(s)
    with tempfile.TemporaryDirectory() as mount_point:
        zip_path = os.path.join(script_dir, 'data', zip_name)
        logging.debug(f'Mounting {zip_path!r} on {mount_point!r}...')
        subprocess.run(
            [mount_program] + options + [zip_path, mount_point],
            check=True,
            capture_output=True,
            input='',
            encoding='UTF-8',
        )
        try:
            logging.debug(f'Mounted archive {zip_path!r} on {mount_point!r}')

            GetTree(mount_point, use_md5=False)
            st = os.statvfs(mount_point)

            want_blocks = 10546877
            if st.f_blocks != want_blocks:
                LogError(
                    f'Mismatch for st.f_blocks: got: {st.f_blocks}, want: {want_blocks}'
                )

            want_inodes = 2
            if st.f_files != want_inodes:
                LogError(
                    f'Mismatch for st.f_files: got: {st.f_files}, want: {want_inodes}'
                )

            fd = os.open(os.path.join(mount_point, 'big.txt'), os.O_RDONLY)
            try:
                random.seed()
                n = 100000000
                for j in [random.randrange(n) for i in range(100)] + [n - 1, 0, n - 1]:
                    logging.debug(f'Getting line {j}...')
                    want_line = b'%08d The quick brown fox jumps over the lazy dog.\n' % j
                    got_line = os.pread(fd, len(want_line), j * len(want_line))
                    if got_line != want_line:
                        LogError(
                            f'Want line: {want_line!r}, Got line: {got_line!r}')
                got_line = os.pread(fd, 100, j * len(want_line))
                if got_line != want_line:
                    LogError(
                        f'Want line: {want_line!r}, Got line: {got_line!r}')
                got_line = os.pread(fd, 100, n * len(want_line))
                if got_line:
                    LogError(f'Want empty line, Got line: {got_line!r}')
            finally:
                os.close(fd)
        finally:
            logging.debug(f'Unmounting {zip_path!r} from {mount_point!r}...')
            subprocess.run(['fusermount', '-u', '-z', mount_point], check=True)
            logging.debug(f'Unmounted {zip_path!r} from {mount_point!r}')


# Tests that a big file can be accessed in somewhat globally increasing order
# even with no cache file.
def TestBigArchiveStreamed(options=[]):
    zip_name = 'big.zip'
    s = f'Test {zip_name!r}'
    if options: s += f', options = {" ".join(options)!r}'
    logging.info(s)
    with tempfile.TemporaryDirectory() as mount_point:
        zip_path = os.path.join(script_dir, 'data', zip_name)
        logging.debug(f'Mounting {zip_path!r} on {mount_point!r}...')
        subprocess.run(
            [mount_program] + options + [zip_path, mount_point],
            check=True,
            capture_output=True,
            input='',
            encoding='UTF-8',
        )
        try:
            logging.debug(f'Mounted archive {zip_path!r} on {mount_point!r}')
            GetTree(mount_point, use_md5=False)
            fd = os.open(os.path.join(mount_point, 'big.txt'), os.O_RDONLY)
            try:
                random.seed()
                n = 100000000
                for i in [(r * 2 + 1) * n // 20 for r in range(10)] + [n - 1]:
                    for k in range(3):
                        j = i - k * 1000000
                        if j < 0: continue
                        logging.debug(f'Getting line {j}...')
                        want_line = b'%08d The quick brown fox jumps over the lazy dog.\n' % j
                        got_line = os.pread(fd, len(want_line), j * len(want_line))
                        if got_line != want_line:
                            LogError(
                                f'Want line: {want_line!r}, Got line: {got_line!r}')
            finally:
                os.close(fd)
        finally:
            logging.debug(f'Unmounting {zip_path!r} from {mount_point!r}...')
            subprocess.run(['fusermount', '-u', '-z', mount_point], check=True)
            logging.debug(f'Unmounted {zip_path!r} from {mount_point!r}')


# Tests encrypted archive.
def TestEncryptedArchive(options=[]):
    zip_name = 'different-encryptions.zip'

    # With correct password.
    want_tree = {
        '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
        'Encrypted ZipCrypto.txt': {
            'mode': '-rw-r--r--',
            'size': 34,
            'md5': '275e8c5aed7e7ce2f32dd1e5e9ee4a5b',
        },
        'Encrypted AES-256.txt': {
            'mode': '-rw-r--r--',
            'size': 32,
            'md5': 'ca5e064a0835d186f2f6326f88a7078f',
        },
        'Encrypted AES-192.txt': {
            'mode': '-rw-r--r--',
            'size': 32,
            'md5': 'e48d57930ef96ff2ad45867202d3250d',
        },
        'Encrypted AES-128.txt': {
            'mode': '-rw-r--r--',
            'size': 32,
            'md5': '07c4edd2a55c9d5614457a21fb40aa56',
        },
        'ClearText.txt': {
            'mode': '-rw-r--r--',
            'size': 23,
            'md5': '7a542815e2c51837b3d8a8b2ebf36490',
        },
    }

    for password in ['password', 'password\n', 'password\nThis line is ignored...\n']:
        MountArchiveAndCheckTree(
            zip_name, want_tree, want_blocks=11, want_inodes=6, options=options, password=password,
        )

    # With wrong or no password.
    CheckArchiveMountingError(zip_name, 21, options=options, password='wrong password')
    CheckArchiveMountingError(zip_name, 20, options=options, password='\n')
    CheckArchiveMountingError(zip_name, 20, options=options)

    # With wrong or no password and `-o force` option.
    want_tree = {
        '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
        'Encrypted ZipCrypto.txt': {
            'mode': '-rw-r--r--',
            'size': 34,
            'errno': 5,
        },
        'Encrypted AES-256.txt': {
            'mode': '-rw-r--r--',
            'size': 32,
            'errno': 5,
        },
        'Encrypted AES-192.txt': {
            'mode': '-rw-r--r--',
            'size': 32,
            'errno': 5,
        },
        'Encrypted AES-128.txt': {
            'mode': '-rw-r--r--',
            'size': 32,
            'errno': 5,
        },
        'ClearText.txt': {
            'mode': '-rw-r--r--',
            'size': 23,
            'md5': '7a542815e2c51837b3d8a8b2ebf36490',
        },
    }
    for password in ['wrong password', '\n', '']:
        MountArchiveAndCheckTree(
            zip_name, want_tree, want_inodes=6, options=options + ['-o', 'force'], password=password,
        )


# Tests the default_permissions, nosymlinks and nospecials mount options.
def TestArchiveWithSpecialFiles():
    zip_name = 'specials.tar.gz'

    want_tree = {
        '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
        'block': {'mode': 'brw-r--r--', 'mtime': 1564833480000000000, 'rdev': 2049},
        'char': {'mode': 'crw-r--r--', 'mtime': 1564833480000000000, 'rdev': 1024},
        'fifo': {'mode': 'prw-r--r--', 'mtime': 1565809123000000000},
        'regular': {'mode': '-rw-r--r--', 'mtime': 1565290018000000000, 'size': 32, 'md5': '456e611a5420b7dd09bae143a7b2deb0'},
        'symlink': {'mode': 'lrwxr-xr-x', 'mtime': 1564834729000000000, 'target': 'regular'},
    }

    MountArchiveAndCheckTree(
        zip_name, want_tree, want_blocks=8, want_inodes=6)

    # Test -o default_permissions
    want_tree = {
        '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
        'block': {'mode': 'brw-rw----', 'uid': 0, 'gid': 6, 'rdev': 2049},
        'char': {'mode': 'crw--w----', 'uid': 0, 'gid': 5, 'rdev': 1024},
        'fifo': {'mode': 'prw-r--r--', 'uid': 1000, 'gid': 1000},
        'regular': {'mode': '-rw-r--r--', 'uid': 1000, 'gid': 1000, 'size': 32, 'md5': '456e611a5420b7dd09bae143a7b2deb0'},
        'symlink': {'mode': 'lrwxrwxrwx', 'uid': 1000, 'gid': 1000, 'target': 'regular'},
    }

    MountArchiveAndCheckTree(
        zip_name, want_tree, want_blocks=8, want_inodes=6, options=['-o', 'default_permissions'],)

    # Test -o nosymlinks
    want_tree = {
        '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
        'block': {'mode': 'brw-r--r--', 'mtime': 1564833480000000000, 'rdev': 2049},
        'char': {'mode': 'crw-r--r--', 'mtime': 1564833480000000000, 'rdev': 1024},
        'fifo': {'mode': 'prw-r--r--', 'mtime': 1565809123000000000},
        'regular': {'mode': '-rw-r--r--', 'mtime': 1565290018000000000, 'size': 32, 'md5': '456e611a5420b7dd09bae143a7b2deb0'},
    }

    MountArchiveAndCheckTree(
        zip_name,
        want_tree,
        want_blocks=6,
        want_inodes=5,
        options=['-o', 'nosymlinks'],
    )

    # Test -o nospecials
    want_tree = {
        '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
        'regular': {'mode': '-rw-r--r--', 'mtime': 1565290018000000000, 'size': 32, 'md5': '456e611a5420b7dd09bae143a7b2deb0'},
        'symlink': {'mode': 'lrwxr-xr-x', 'mtime': 1564834729000000000, 'target': 'regular'},
    }

    MountArchiveAndCheckTree(
        zip_name,
        want_tree,
        want_blocks=5,
        want_inodes=3,
        options=['-o', 'nospecials'],
    )

    # Tests -o nosymlinks and -o nospecials together
    want_tree = {
        '.': {'ino': 1, 'mode': 'drwxr-xr-x', 'nlink': 2},
        'regular': {'mode': '-rw-r--r--', 'mtime': 1565290018000000000, 'size': 32, 'md5': '456e611a5420b7dd09bae143a7b2deb0'},
    }

    MountArchiveAndCheckTree(
        zip_name,
        want_tree,
        want_blocks=3,
        want_inodes=2,
        options=['-o', 'nosymlinks,nospecials'],
    )


# Tests invalid and absent archives.
def TestInvalidArchive():
    CheckArchiveMountingError('', 11)
    CheckArchiveMountingError('absent.zip', 11)
    CheckArchiveMountingError('romeo.txt', 30)

    # https://github.com/google/fuse-archive/issues/38
    CheckArchiveMountingError('empty', 30)
    CheckArchiveMountingError('empty.gz', 30)

    # https://github.com/google/fuse-archive/issues/36
    CheckArchiveMountingError('truncated.7z', 32)

    if os.getuid() != 0:
        with tempfile.NamedTemporaryFile() as f:
            os.chmod(f.name, 0)
            CheckArchiveMountingError(f.name, 11)


logging.getLogger().setLevel('INFO')

TestArchiveWithOptions()
TestArchiveWithOptions(['-o', 'nocache'])
TestHardlinks()
TestHardlinks(['-o', 'nocache'])
TestArchiveWithSpecialFiles()
TestEncryptedArchive()
TestEncryptedArchive(['-o', 'nocache'])
TestInvalidArchive()
TestMasks()
TestArchiveWithManyFiles()
TestBigArchiveRandomOrder(['-o', 'direct_io'])
TestBigArchiveStreamed(['-o', 'nocache,direct_io'])

if error_count:
    LogError(f'FAIL: There were {error_count} errors')
    sys.exit(1)
else:
    logging.info('PASS: All tests passed')
