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

/// @title A starter application using RISC Zero.
/// @notice This basic application holds a number, guaranteed to be even.
/// @dev This contract demonstrates one pattern for offloading the computation of an expensive
///      or difficult to implement function to a RISC Zero guest running on the zkVM.
interface IContract {
    /// @notice Verify a RISC Zero proof and store generic data from guest.
    /// @dev Expects the journal to be ABI-encoded as: (string dataType, bytes rawData).
    function set(bytes calldata journal, bytes calldata seal) external;

    /// @notice Universal getter - works with any data type from guest.
    /// @return data The raw ABI-encoded bytes from the guest
    /// @return dataType The data type string (e.g., "uint256", "uint256[]", "string")
    function get() external view returns (bytes memory data, string memory dataType);
}
