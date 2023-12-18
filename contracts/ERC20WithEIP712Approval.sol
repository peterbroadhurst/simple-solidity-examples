pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

// SPDX-License-Identifier: MIT
contract ERC20WithEIP712Approval is EIP712, ERC20, Ownable {

    bytes32 private constant TRANSFER_TYPEHASH =
        keccak256("Transfer(address from,address to,uint256 amount)");

    bytes32 private constant MINT_TYPEHASH =
        keccak256("Mint(address to,uint256 amount)");

    address private verifier;

    constructor(address _verifier)
      EIP712("demo","1")
      ERC20("Demo", "DMO")
      Ownable(msg.sender)
    {
       verifier = _verifier;
    }

    function mintWithApproval(
        address to,
        uint256 amount,
        bytes calldata signature
    ) public onlyOwner {
        address signer = ECDSA.recover(
            _hashTypedDataV4(
                keccak256(abi.encode(MINT_TYPEHASH, to, amount))
            ),
            signature
        );
        require(signer == verifier, "Failed to validate verifier signature");

        _mint(to, amount);
    }

    function transferWithApproval(
        address from,
        address to,
        uint256 amount,
        bytes calldata signature
    ) public {
        address signer = ECDSA.recover(
            _hashTypedDataV4(
                keccak256(abi.encode(TRANSFER_TYPEHASH, from, to, amount))
            ),
            signature
        );
        require(signer == verifier, "Failed to validate verifier signature");

        _transfer(from, to, amount);
    }

    function transfer(address, uint256) public virtual override returns (bool) {
        revert("Not allowed");
    }

    function transferFrom(address, address, uint256) public virtual override returns (bool) {
        revert("Not allowed");
    }

}