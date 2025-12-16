#!/bin/bash
set -e

# 1. Avvia Anvil solo se non è già in esecuzione
if pgrep -f anvil > /dev/null; then
  echo "[INFO] Anvil già in esecuzione"
else
  echo "[INFO] Avvio anvil..."
  nohup anvil > anvil.log 2>&1 &
  sleep 2
fi
# 2. Esporta variabili d'ambiente
export ETH_WALLET_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Crea file per esportare variabili nel terminale principale
echo "export ETH_WALLET_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" > .env_vars

# 4. Deploy contratto
forge script --rpc-url http://localhost:8545 --broadcast script/Deploy.s.sol

# 5. Estrai indirizzo HeapSort dal log di deploy
export CONTRACT_ADDRESS=$(jq -re '.transactions[] | select(.contractName == "Contract") | .contractAddress' ./broadcast/Deploy.s.sol/31337/run-latest.json)

# Aggiorna il file delle variabili d'ambiente
echo "export ETH_WALLET_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" > .env_vars
echo "export CONTRACT_ADDRESS=$CONTRACT_ADDRESS" >> .env_vars

# 6. Query stato iniziale
# cast call --rpc-url http://localhost:8545 $CONTRACT_ADDRESS 'get()(uint256)'
