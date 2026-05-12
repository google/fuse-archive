#!/bin/python3

# Copyright 2026 The Fuse-Archive Authors.
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

import io
import os.path
import tarfile

dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
with tarfile.open(os.path.join(dir, 'deep.tar'), 'w') as t:
    n = 30000
    while n > 0:
        ti = tarfile.TarInfo(name='a/' * n + 'pwn.txt')
        data = b'At depth of %d\n' % n
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
        n = n * 3 // 4
