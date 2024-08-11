from __future__ import annotations

import argparse
import pathlib
import sys
from typing import Collection
from typing import Sequence

import imagehash
import numpy
from PIL import Image

ap = argparse.ArgumentParser()

ap.add_argument('--file', type=pathlib.Path)
ap.add_argument('--debug', action='store_true')

opts = ap.parse_args()
opts.file = pathlib.Path(opts.file)

hash_size = 8

image = Image.open(opts.file)
gray = image.copy().convert('L')
resized = gray.copy().resize((hash_size, hash_size), Image.Resampling.LANCZOS)


def print_image(image: Image.Image) -> None:
    for row in numpy.asarray(image):
        print('[ ', end='', file=sys.stderr)
        for i in row:
            if isinstance(i, Collection):
                print('{ ', end='', file=sys.stderr)
                for idx, x in enumerate(i):
                    if idx == len(i) - 1:
                        print(f'{int(x):03d} ', end='', file=sys.stderr)
                    else:
                        print(f'{int(x):03d}, ', end='', file=sys.stderr)
                print('}, ', end='', file=sys.stderr)
            else:
                print(f'{int(i):03d}, ', end='', file=sys.stderr)
        print(']', file=sys.stderr)


def bin_str(hash):
    return ''.join(str(b) for b in 1 * hash.hash.flatten())


if opts.debug:
    image.save('py.rgb.png')
    print('rgb', file=sys.stderr)
    print_image(image)
    print(file=sys.stderr)

if opts.debug:
    gray.save('py.gray.png')
    print('gray', file=sys.stderr)
    print_image(gray)
    print(file=sys.stderr)

if opts.debug:
    resized.save('py.resized.png')
    print('resized', file=sys.stderr)
    print_image(resized)
    print(file=sys.stderr)

print('ahash: ', str(imagehash.average_hash(image)))
print('dhash: ', str(imagehash.dhash(image)))
print('phash: ', str(imagehash.phash(image)))
