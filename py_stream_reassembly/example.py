import py_stream_reassembly
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('--file', type=str, required=True)

args = parser.parse_args()

for (key, data, inc) in py_stream_reassembly.Reass(args.file):
    print( key.src, " -> ", key.dst)
    print(data)
    if inc:
        print(inc)

