cd "$(dirname "$0")"
cmake .
make
mkdir -p tins
cp -r external tins
cp tins_reassembly tins/tins
mkdir -p ../../bins_to_test/
cp -r ./tins/ ../../bins_to_test/
