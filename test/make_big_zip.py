#!/bin/python3

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

import os
import os.path
from zipfile import ZIP_DEFLATED, ZipFile

dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
tmp = os.path.join(dir, 'big.zip~')

try:
  with ZipFile(tmp, 'w', compression=ZIP_DEFLATED, allowZip64=True) as z:
    with z.open('big.txt', mode='w', force_zip64=True) as f:
      for i in range(100):
        print('\rWriting big.zip... %3d %%' % i, end='', flush=True)
        for j in range(1000000):
          f.write(
              b'%02d%06d The quick brown fox jumps over the lazy dog.\n'
              % (i, j)
          )

  print('\r\033[2KDone', flush=True)
  os.replace(tmp, os.path.join(dir, 'big.zip'))
except:
  os.remove(tmp)
