#!/bin/bash
set -e

# 4. Deploy contratto
forge script script/Deploy.s.sol --rpc-url https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY:?} --broadcast

# 5. Estrai indirizzo HeapSort dal log di deploy
export CONTRACT_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "ContractSort") | .contractAddress' ./broadcast/Deploy.s.sol/11155111/run-latest.json)

echo "export CONTRACT_ADDRESS=$CONTRACT_ADDRESS" >> .env_vars

# 6. Query stato iniziale
# cast call --rpc-url https://eth-sepolia.g.alchemy.com/v2/${ALCHEMY_API_KEY:?} ${CONTRACT_ADDRESS:?} 'get()(int256[])'




