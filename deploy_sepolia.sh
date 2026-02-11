#!/bin/bash
set -e

echo "=========================================="
echo "  RISC0FLOW - Deploy to Sepolia Testnet"
echo "=========================================="
echo ""

# Check and request required environment variables
if [ -z "$API_KEY" ]; then
    read -p "Enter your Alchemy API Key: " API_KEY
    export API_KEY
fi

if [ -z "$ETH_WALLET_PRIVATE_KEY" ]; then
    read -sp "Enter your wallet private key (hidden): " ETH_WALLET_PRIVATE_KEY
    echo ""
    export ETH_WALLET_PRIVATE_KEY
fi

echo ""
echo "Configuration:"
echo "  - Alchemy API Key: ${API_KEY:0:8}..."
echo "  - Private Key:     [hidden]"
echo ""

read -p "Proceed with deploy? (y/n): " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "Deploy cancelled."
    exit 0
fi

echo ""
echo "Deploying contract to Sepolia..."

# Deploy contract
forge script script/Deploy.s.sol --rpc-url https://eth-sepolia.g.alchemy.com/v2/${API_KEY} --broadcast

# Extract contract address from deploy log
export CONTRACT_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "Contract") | .contractAddress' ./broadcast/Deploy.s.sol/11155111/run-latest.json 2>/dev/null || echo "")

if [ -z "$CONTRACT_ADDRESS" ]; then
    echo "Warning: Could not extract contract address automatically."
    echo "Check broadcast/Deploy.s.sol/11155111/run-latest.json manually."
else
    echo ""
    echo "=========================================="
    echo "  Deploy completed successfully!"
    echo "  Contract Address: $CONTRACT_ADDRESS"
    echo "=========================================="
    
    # Save to .env_vars for future reference
    echo "export CONTRACT_ADDRESS=$CONTRACT_ADDRESS" >> .env_vars
fi




