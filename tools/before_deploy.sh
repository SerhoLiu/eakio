#!/usr/bin/env bash
# Building and packaging for release

set -ex

build() {
    cargo build --target "$TARGET" --release
}

copy() {
    local out_dir=$(pwd)
    local out_bin="$out_dir/$PROJECT_NAME-$TRAVIS_TAG-$TARGET"

    # copy to output
    cp "target/$TARGET/release/$PROJECT_NAME" "$out_bin"
    strip "$out_bin"
}

main() {
    build
    copy
}

main
