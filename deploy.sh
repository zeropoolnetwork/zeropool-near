#!/usr/bin/env bash

CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
TX_VK="$(base64 < "$CURRENT_DIR"/params/transfer_verification_key.bin)"
TREE_VK="$(base64 < "$CURRENT_DIR"/params/tree_verification_key.bin)"

near deploy --wasmFile "$CURRENT_DIR"/out/main.wasm \
  --initArgs "{\"tx_vk\": \"$TX_VK\", \"tree_vk\": \"$TREE_VK\"}" \
  --accountId $1