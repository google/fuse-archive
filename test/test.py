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

    def scan(dir):
        for entry in os.scandir(dir):
            path = entry.path
            st = entry.stat(follow_symlinks=False)
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
                continue
            if stat.S_ISDIR(mode):
                scan(path)
                continue
            if stat.S_ISLNK(mode):
                line['target'] = os.readlink(path)
                continue
            if stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
                line['rdev'] = st.st_rdev
                continue

    scan(root)
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
                if key in ('atime', 'ctime'):
                    continue  # For the time being
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
    logging.info(
        f'Checking {zip_name!r} with options {options} and password {password!r}...')
    try:
        got_tree, st = MountArchiveAndGetTree(
            zip_name, options=options, password=password, use_md5=use_md5
        )

        want_block_size = 512
        if st.f_bsize != want_block_size:
            LogError(
                f'Mismatch for st.f_bsize: got: {st.f_bsize}, want: {want_block_size}'
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
    logging.info(
        f'Checking {zip_name!r} with options {options} and password {password!r}...')
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
def TestArchiveWithDefaultOptions():
    want_trees = {
        'archive.zip': {
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'}},
        'archive.rar': {
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'}},
        'archive.tar': {
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'}},
        'archive.tar.gz': {
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'}},
        'archive.tar.bz2': {
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'}},
        'archive.7z': {
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022983000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'}},
        'archive.cab': {
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rw-r--r--', 'mtime': 1620022794000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022604000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'non-ascii/😻.txt': {'mode': '-rw-r--r--', 'mtime': 1620022982000000000, 'size': 151, 'md5': '5d18e0e461374191825c6e7898af5634'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'}},
        'archive.iso': {
            'artificial': {'mode': 'drwxr-xr-x'},
            'artificial/0.bytes': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
            'github-tags.json': {'mode': '-rw-r--r--', 'mtime': 1597241062000000000, 'size': 853, 'md5': 'b2d7993ed99c65296bf95824c57b4fdc'},
            'hello.sh': {'mode': '-rwxr-xr-x', 'mtime': 1620022795000000000, 'size': 693, 'md5': '72d710dd3766a67401a79f8d3df3114c'},
            'non-ascii': {'mode': 'drwxr-xr-x'},
            'non-ascii/αβ.txt': {'mode': '-rw-r--r--', 'mtime': 1620022605000000000, 'size': 104, 'md5': '3369a4163a436de59e23daedd371b5f0'},
            'pjw-thumbnail.png': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 208, 'md5': 'f7017e60a0af6d7ad3128c149624aac5'},
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
            'romeo.txt.gz': {'mode': '-rw-r--r--', 'mtime': 1580883024000000000, 'size': 558, 'md5': 'f261bc929b34f58d8138413ed6252f2d'}},
        'romeo.txt.gz': {
            'romeo.txt': {'mode': '-rw-r--r--', 'mtime': 1499322406000000000, 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'romeo.txt.bz2': {
            'romeo.txt': {'mode': '-rw-r--r--', 'size': 942, 'md5': '80f1521c4533d017df063c623b75cde3'},
        },
        'zeroes-256mib.tar.gz': {
            'zeroes': {'mode': '-rw-r--r--', 'mtime': 1630037295000000000, 'size': 268435456, 'md5': '1f5039e50bd66b290c56684d8550c6c2'},
        },
        'dot-slash-foo.tar': {
            'foo': {'mode': '-rw-r--r--', 'mtime': 1641016352000000000, 'size': 0, 'md5': 'd41d8cd98f00b204e9800998ecf8427e'},
        },
    }

    for cache in [True, False]:
        for direct_io in [False, True]:
            options = []
            if not cache:
                options += ['-o', 'nocache']
            if direct_io:
                options += ['-o', 'direct_io']
            for zip_name, want_tree in want_trees.items():
                MountArchiveAndCheckTree(zip_name, want_tree, options=options)


# Tests dmask and fmask.
def TestMasks():
    want_tree = {
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
def TestBigArchive(options=[]):
    zip_name = 'big.zip'
    logging.info(f'Checking {zip_name!r} with options {options}...')
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

            tree = GetTree(mount_point, use_md5=False)
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


# Tests that a big file can be accessed in somewhat random order even with no
# cache file.
def TestBigArchiveNoCache():
    zip_name = 'big.zip'
    logging.info(f'Checking {zip_name!r}...')
    with tempfile.TemporaryDirectory() as mount_point:
        zip_path = os.path.join(script_dir, 'data', zip_name)
        logging.debug(f'Mounting {zip_path!r} on {mount_point!r}...')
        subprocess.run(
            [mount_program, '--nocache', zip_path, mount_point],
            check=True,
            capture_output=True,
            input='',
            encoding='UTF-8',
        )
        try:
            logging.debug(f'Mounted archive {zip_path!r} on {mount_point!r}')
            tree = GetTree(mount_point, use_md5=False)
            fd = os.open(os.path.join(mount_point, 'big.txt'), os.O_RDONLY)
            try:
                random.seed()
                n = 100000000
                for j in (
                    sorted([random.randrange(n) for i in range(50)])
                    + [n - 1, 0]
                    + sorted([random.randrange(n) for i in range(50)])
                    + [n - 1, 0]
                ):
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
def TestEncryptedArchive():
    zip_name = 'different-encryptions.zip'

    # With correct password.
    want_tree = {
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

    MountArchiveAndCheckTree(
        zip_name, want_tree, want_blocks=11, want_inodes=6, password='password'
    )

    MountArchiveAndCheckTree(
        zip_name, want_tree, want_blocks=11, want_inodes=6, password='password\n'
    )

    MountArchiveAndCheckTree(
        zip_name,
        want_tree,
        want_blocks=11,
        want_inodes=6,
        password='password\nThis line is ignored...\n',
    )

    # With wrong or no password.
    CheckArchiveMountingError(zip_name, 21, password='wrong password')
    CheckArchiveMountingError(zip_name, 20)


# Tests the default_permissions, nosymlinks and nospecials mount options.
def TestArchiveWithSpecialFiles():
    zip_name = 'specials.tar.gz'

    want_tree = {
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
    CheckArchiveMountingError('', 31)
    CheckArchiveMountingError('absent.zip', 11)
    CheckArchiveMountingError('romeo.txt', 30)
    if os.getuid() != 0:
        with tempfile.NamedTemporaryFile() as f:
            os.chmod(f.name, 0)
            CheckArchiveMountingError(f.name, 11)


logging.getLogger().setLevel('INFO')

TestArchiveWithDefaultOptions()
TestArchiveWithSpecialFiles()
TestEncryptedArchive()
TestArchiveWithManyFiles()
TestInvalidArchive()
TestMasks()
# TestBigArchive()
# TestBigArchiveNoCache()

if error_count:
    LogError(f'There were {error_count} errors')
    sys.exit(1)
else:
    logging.info('All tests passed Ok')
