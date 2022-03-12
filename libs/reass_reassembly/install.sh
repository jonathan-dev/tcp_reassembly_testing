cd "$(dirname "$0")"
cmake -DCMAKE_BUILD_TYPE=Release -G 'Unix Makefiles'
make
mkdir -p ../../bins_to_test/
cp main ../../bins_to_test/reass_reassembly
