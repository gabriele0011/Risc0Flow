// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol"; // auto-generated contract after running `cargo build`.

/// @title A starter application using RISC Zero.
/// @notice This basic application holds a number, guaranteed to be even.
/// @dev This contract demonstrates one pattern for offloading the computation of an expensive
///      or difficult to implement function to a RISC Zero guest running on the zkVM.
contract Contract {
    /// @notice RISC Zero verifier contract address.
    IRiscZeroVerifier public immutable verifier;
    /// @notice Image ID of the only zkVM binary to accept verification from.
    ///         The image ID is similar to the address of a smart contract.
    ///         It uniquely represents the logic of that guest program,
    ///         ensuring that only proofs generated from a pre-defined guest program
    ///         (in this case, checking if a number is even) are considered valid.
    bytes32 public constant imageId = ImageID.GUEST_ID;

    /// @notice Generic storage for any data type and format from the guest
    /// @dev These provide a universal way to store and retrieve any guest output
    string public dataType;        // e.g., "uint256", "uint256[]", "string", etc.
    bytes public rawData;          // ABI-encoded data according to dataType
    /// @notice The SHA-256 digest of the last verified journal (for reference/correlation).
    bytes32 public lastJournalDigest;

    /// @notice Initialize the contract, binding it to a specified RISC Zero verifier.
    constructor(IRiscZeroVerifier _verifier) {
        verifier = _verifier;
    }

    /// @notice Verify a RISC Zero proof and store the generic result.
    /// @dev Expects the journal to be ABI-encoded as: (string dataType, bytes rawData).
    ///      Works with ANY data type - uint256, uint256[], string, bytes, tuples, etc.
    function set(bytes calldata journal, bytes calldata seal) public {
        // Verify the receipt, ensuring the journal matches the commitment.
        bytes32 digest = sha256(journal);
        verifier.verify(seal, imageId, digest);

        // Decode the generic structure: (dataType, rawData).
        (string memory _dataType, bytes memory _rawData) = abi.decode(journal, (string, bytes));

        // Store everything generically - no type-specific logic needed!
        dataType = _dataType;
        rawData = _rawData;
        lastJournalDigest = digest;
    }

    /// @notice Universal getter - returns raw data and its type for any guest output
    /// @dev This is the ONLY way to consume data from the guest - works with any type
    /// @return data The raw ABI-encoded bytes from the guest
    /// @return dataType The data type string (e.g., "uint256", "uint256[]", "string")
    function get() public view returns (bytes memory data, string memory dataType) {
        return (rawData, dataType);
    }
}
