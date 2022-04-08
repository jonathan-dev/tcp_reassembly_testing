cd "$(dirname "$0")"
go build
mkdir -p ../../bins_to_test/
cp gopacket_reassembly ../../bins_to_test/gopacket_reassembly
