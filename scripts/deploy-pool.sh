#!/bin/bash
# Deploy Ekubo Privacy Pool + Groth16 Verifier to Starknet (devnet or testnet)
#
# Prerequisites:
#   scarb 2.9.1   (install: curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh)
#   starkli       (install: curl https://get.starkli.sh | sh && starkliup)
#   garaga 1.0.1  (install: pip install garaga  [requires Python 3.10-3.11])
#
# Environment variables:
#   STARKNET_RPC_URL   — RPC endpoint (e.g. https://free-rpc.nethermind.io/sepolia-juno/)
#   STARKNET_ACCOUNT   — Path to account keystore file
#   STARKNET_KEYSTORE  — Path to starkli keystore
#   TOKEN_ADDRESS      — ERC20 token address (USDC on Sepolia or devnet-deployed ERC20)
#
# Usage:
#   export STARKNET_RPC_URL=...
#   export STARKNET_ACCOUNT=~/.starkli/account.json
#   export STARKNET_KEYSTORE=~/.starkli/keystore.json
#   export TOKEN_ADDRESS=0x...
#   bash scripts/deploy-pool.sh

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VK_PATH="$REPO_ROOT/circuits/target/verification_key.json"
GARAGA_OUTPUT="/tmp/wraith-garaga-verifier"

echo "=== Step 1: Validate prerequisites ==="
command -v scarb >/dev/null || { echo "ERROR: scarb not found. Install scarb 2.9.1"; exit 1; }
command -v starkli >/dev/null || { echo "ERROR: starkli not found. Run: curl https://get.starkli.sh | sh"; exit 1; }
command -v garaga >/dev/null || { echo "ERROR: garaga not found. Run: pip install garaga"; exit 1; }

SCARB_VERSION=$(scarb --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
echo "scarb: $SCARB_VERSION (need 2.9.1)"
echo "starkli: $(starkli --version)"
echo "garaga: $(garaga --version)"

if [ ! -f "$VK_PATH" ]; then
  echo "ERROR: verification_key.json not found at $VK_PATH"
  echo "Run: bash circuits/setup.sh"
  exit 1
fi

echo ""
echo "=== Step 2: Clone Ekubo privacy-pools ==="
POOL_REPO="/tmp/wraith-pool-deploy"
if [ ! -d "$POOL_REPO" ]; then
  git clone --depth 1 https://github.com/EkuboProtocol/privacy-pools.git "$POOL_REPO"
fi

echo ""
echo "=== Step 3: Generate Cairo verifier constants from our vk.json ==="
rm -rf "$GARAGA_OUTPUT"
mkdir -p "$GARAGA_OUTPUT"
cd "$GARAGA_OUTPUT"
garaga gen --project-name verifier --system groth16 --vk "$VK_PATH" 2>/dev/null || true
# garaga fmt fails with our scarb version — the file is still written
if [ ! -f "$GARAGA_OUTPUT/verifier/src/groth16_verifier_constants.cairo" ]; then
  echo "ERROR: garaga did not generate verifier constants"
  exit 1
fi
echo "Verifier constants generated"

echo ""
echo "=== Step 4: Replace verifier constants in pool repo ==="
cp "$GARAGA_OUTPUT/verifier/src/groth16_verifier_constants.cairo" \
   "$POOL_REPO/pool/src/verifier/groth16_verifier_constants.cairo"
echo "Constants replaced"

echo ""
echo "=== Step 5: Build pool contract ==="
cd "$POOL_REPO"
scarb build
echo "Build complete"
ls target/dev/*.contract_class.json

echo ""
echo "=== Step 6: Deploy pool contract ==="
if [ -z "$STARKNET_RPC_URL" ]; then
  echo "STARKNET_RPC_URL not set — skipping deployment"
  echo "To deploy:"
  echo "  export STARKNET_RPC_URL=https://free-rpc.nethermind.io/sepolia-juno/"
  echo "  export STARKNET_ACCOUNT=~/.starkli/account.json"
  echo "  export STARKNET_KEYSTORE=~/.starkli/keystore.json"
  echo "  export TOKEN_ADDRESS=0x..."
  echo "  bash scripts/deploy-pool.sh"
  exit 0
fi

# Declare pool contract class
POOL_ARTIFACT="$POOL_REPO/target/dev/pool_Pool.contract_class.json"
echo "Declaring pool class..."
POOL_CLASS_HASH=$(starkli declare "$POOL_ARTIFACT" \
  --account "$STARKNET_ACCOUNT" \
  --keystore "$STARKNET_KEYSTORE" \
  --rpc "$STARKNET_RPC_URL" \
  --watch 2>&1 | grep -oE '0x[0-9a-f]{64}' | tail -1)
echo "Pool class hash: $POOL_CLASS_HASH"

# Deploy pool with token address
# Constructor: fn constructor(ref self: ContractState, token: ContractAddress, owner: ContractAddress)
OWNER=$(starkli account fetch --account "$STARKNET_ACCOUNT" 2>/dev/null | grep address | grep -oE '0x[0-9a-f]+')
echo "Deploying pool (token=$TOKEN_ADDRESS, owner=$OWNER)..."
POOL_ADDRESS=$(starkli deploy "$POOL_CLASS_HASH" \
  "$TOKEN_ADDRESS" "$OWNER" \
  --account "$STARKNET_ACCOUNT" \
  --keystore "$STARKNET_KEYSTORE" \
  --rpc "$STARKNET_RPC_URL" \
  --watch 2>&1 | grep -oE '0x[0-9a-f]{64}' | tail -1)

echo ""
echo "=== DONE ==="
echo "Pool deployed at: $POOL_ADDRESS"
echo ""
echo "Set this in your environment:"
echo "  export POOL_ADDRESS=$POOL_ADDRESS"
echo ""
echo "Update PrivacyPoolsAdapter constructor:"
echo "  new PrivacyPoolsAdapter(account, '$POOL_ADDRESS')"
