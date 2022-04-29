import py_bindings
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('--file', type=str, required=True)

args = parser.parse_args()

for (key, data, inc) in py_bindings.Reass(args.file):
    print( key.src, " -> ", key.dst)
    print(data)
    if inc:
        print(inc)

