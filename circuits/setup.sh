#!/bin/bash
# Trusted setup for Ekubo Privacy Pool withdrawal circuit
# Generates proving/verification keys using Hermez Phase 1 ptau (trusted).
#
# DONE: This setup has already been run. Artifacts are in circuits/target/:
#   pool_js/pool.wasm   (compiled circuit)
#   pool_final.zkey     (proving key)
#   verification_key.json
#
# Re-run only if you need to regenerate (e.g. circuit changes).
#
# Requirements:
#   circom v2.x binary at ~/bin/circom (or on PATH)
#   npx snarkjs v0.7.x (from node_modules)
#
# Usage:
#   cd wraith-protocol && bash circuits/setup.sh

set -e

CIRCUITS_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="$CIRCUITS_DIR/target"
POOL_CIRCOM="$CIRCUITS_DIR/pool.circom"

mkdir -p "$TARGET_DIR"

# Step 1: Compile circuit (circom v2.x binary required)
if [ ! -f "$TARGET_DIR/pool.r1cs" ]; then
  echo "=== Step 1: Compile circuit ==="
  # Add ~/bin to PATH in case circom binary is there
  export PATH="$PATH:$HOME/bin"
  circom "$POOL_CIRCOM" --r1cs --wasm --sym -o "$TARGET_DIR" -l "$CIRCUITS_DIR"
  echo "r1cs: $TARGET_DIR/pool.r1cs"
  echo "wasm: $TARGET_DIR/pool_js/pool.wasm"
else
  echo "=== Step 1: Skipped (pool.r1cs exists) ==="
fi

# Step 2: Download Hermez Phase 1 final ptau (n=16, 65536 capacity)
# Pool circuit: 29138 wires → needs 2^16 = 65536 capacity
PTAU_FILE="$TARGET_DIR/hermez_final_16.ptau"
if [ ! -f "$PTAU_FILE" ]; then
  echo "=== Step 2: Download Hermez Phase 1 ptau (72MB) ==="
  curl -fsSL "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau" \
    -o "$PTAU_FILE" --progress-bar
  echo "ptau: $PTAU_FILE"
else
  echo "=== Step 2: Skipped (hermez ptau exists) ==="
fi

# Step 3: Generate initial proving key
if [ ! -f "$TARGET_DIR/pool_0000.zkey" ]; then
  echo "=== Step 3: Groth16 setup (~30s) ==="
  npx snarkjs groth16 setup "$TARGET_DIR/pool.r1cs" "$PTAU_FILE" "$TARGET_DIR/pool_0000.zkey"
  echo "Initial zkey: $TARGET_DIR/pool_0000.zkey"
else
  echo "=== Step 3: Skipped (pool_0000.zkey exists) ==="
fi

# Step 4: Contribute entropy to proving key
if [ ! -f "$TARGET_DIR/pool_final.zkey" ]; then
  echo "=== Step 4: Contribute to zkey ==="
  npx snarkjs zkey contribute "$TARGET_DIR/pool_0000.zkey" "$TARGET_DIR/pool_final.zkey" \
    --name="Wraith Protocol" -e="wraith-$(date +%s)"
  echo "Final zkey: $TARGET_DIR/pool_final.zkey"
else
  echo "=== Step 4: Skipped (pool_final.zkey exists) ==="
fi

# Step 5: Export verification key
if [ ! -f "$TARGET_DIR/verification_key.json" ]; then
  echo "=== Step 5: Export verification key ==="
  npx snarkjs zkey export verificationkey "$TARGET_DIR/pool_final.zkey" "$TARGET_DIR/verification_key.json"
  echo "Verification key: $TARGET_DIR/verification_key.json"
else
  echo "=== Step 5: Skipped (verification_key.json exists) ==="
fi

echo ""
echo "=== DONE ==="
echo ""
echo "Set these environment variables before running the withdrawal queue:"
echo "  export CIRCUIT_WASM_PATH=$(realpath "$TARGET_DIR/pool_js/pool.wasm")"
echo "  export CIRCUIT_ZKEY_PATH=$(realpath "$TARGET_DIR/pool_final.zkey")"
echo ""
echo "NOTE: The verification key must match what your pool contract uses."
echo "Deploy your own pool instance from github.com/EkuboProtocol/privacy-pools"
echo "and pass verification_key.json when deploying the Groth16 verifier."
