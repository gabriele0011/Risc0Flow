// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {RiscZeroGroth16Verifier, ControlID} from "risc0/groth16/RiscZeroGroth16Verifier.sol";

contract DeployVerifier is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("ETH_WALLET_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        RiscZeroGroth16Verifier verifier = new RiscZeroGroth16Verifier(
            ControlID.CONTROL_ROOT,
            ControlID.BN254_CONTROL_ID
        );

        console.log("RiscZeroGroth16Verifier deployed to:", address(verifier));

        vm.stopBroadcast();
    }
}
