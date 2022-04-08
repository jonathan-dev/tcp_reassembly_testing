import os, getopt, sys, subprocess
import codecs

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:f:")
    except getopt.GetoptError:
        # print help information and exit:
        # usage()
        sys.exit(2)

    for o, a in opts:
        if o == "-f":
            out = subprocess.run(["tshark", "-r", f"{a}", "-z", "follow,tcp,raw,0",  "-q"], stdout=subprocess.PIPE)
            x = "\n".join(out.stdout.decode("utf-8").split("\n")[6:-2]).replace("\n", "")
            out = codecs.decode(x, "hex")
            print(out.decode("ascii"), end ="")


if __name__ == '__main__':
    main()
