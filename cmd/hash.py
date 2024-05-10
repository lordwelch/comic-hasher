from typing import Collection, Sequence
from PIL import Image
import argparse,pathlib,numpy,imagehash

ap = argparse.ArgumentParser()

ap.add_argument("--file", type=pathlib.Path)

opts = ap.parse_args()
opts.file = pathlib.Path(opts.file)

hash_size = 8

image = Image.open(opts.file)
gray = image.copy().convert('L')
resized = gray.copy().resize((hash_size, hash_size), Image.Resampling.LANCZOS)


def print_image(image: Image.Image) -> None:
    for row in numpy.asarray(image):
        print('[ ', end='')
        for i in row:
            if isinstance(i, Collection):
                print('{ ', end='')
                for idx, x in enumerate(i):
                    if idx == len(i)-1:
                        print(f'{int(x):03d} ', end='')
                    else:
                        print(f'{int(x):03d}, ', end='')
                print('}, ', end='')
            else:
                print(f'{int(i):03d}, ', end='')
        print(']')

def bin_str(hash):
    return ''.join(str(b) for b in 1 * hash.hash.flatten())


print("rgb")
print_image(image)
print()
image.save("py.rgb.png")

print("gray")
print_image(gray)
gray.save("py.gray.png")
print()

print("resized")
print_image(resized)
resized.save("py.resized.png")
print()

print('ahash: ', bin_str(imagehash.average_hash(image)))
print('dhash: ', bin_str(imagehash.dhash(image)))
print('phash: ', bin_str(imagehash.phash(image)))
