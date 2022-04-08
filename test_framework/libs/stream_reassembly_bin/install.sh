cd "$(dirname "$0")"
cargo build --release
mkdir -p ../../bins_to_test/
cp ./target/release/stream_reassembly_bin ../../bins_to_test/
