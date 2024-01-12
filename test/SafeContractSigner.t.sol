// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import { PRBTest } from "@prb/test/src/PRBTest.sol";
import { console2 } from "forge-std/src/console2.sol";
import { StdCheats } from "forge-std/src/StdCheats.sol";


abstract contract Enum {
    enum Operation {
        Call,
        DelegateCall
    }
}
interface ISafe {
    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    )
        external;

    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool success);

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);

    function encodeTransactionData(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes memory);

    function nonce() external view returns (uint256);
    function domainSeparator() external view returns (bytes32);

    function getMessageHashForSafe(ISafe safe, bytes memory message) external view returns (bytes32);
    function encodeMessageDataForSafe(ISafe safe, bytes memory message) external view returns (bytes memory);
}

interface ISafeProxyFactory {
    function createProxyWithNonce(
        address _singleton,
        bytes memory initializer,
        uint256 saltNonce
    )
        external
        returns (address proxy);
}

interface IWETH9 {
    function deposit() external payable;
    function transfer(address dst, uint wad) external returns (bool);
    function withdraw(uint wad) external;
}

/// @dev If this is your first time with Forge, read this tutorial in the Foundry Book:
/// https://book.getfoundry.sh/forge/writing-tests
contract SafeContractSignerTest is PRBTest, StdCheats {

    string internal constant TEST_MNEMONIC = "test test test test test test test test test test test junk";

    address internal constant SAFE_SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    address internal constant COMPATABILITY_FALLBACK_HANDLER = 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99;

    ISafeProxyFactory internal safeProxyFactory = ISafeProxyFactory(0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67);

    IWETH9 internal constant WETH9 = IWETH9(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    address internal alice;
    address internal bob;
    address internal carol;
    address internal dave;

    uint256 internal aliceKey;
    uint256 internal bobKey;
    uint256 internal carolKey;
    uint256 internal daveKey;

    address internal daoSafe;
    address internal daoContractSigner;
    address internal aliceSafe;

    string internal mnemonic;

    function setUp() public virtual {


        // Select fork (needed for Safe.global contracts)
        vm.createSelectFork({ urlOrAlias: "mainnet", blockNumber: 18_985_536 });

        // Initialize signers.
        mnemonic = vm.envOr("MNEMONIC", TEST_MNEMONIC);
        (alice, aliceKey) = deriveRememberKey({ mnemonic: mnemonic, index: 1 });
        (bob, bobKey) = deriveRememberKey({ mnemonic: mnemonic, index: 2 });
        (carol, carolKey) = deriveRememberKey({ mnemonic: mnemonic, index: 3 });
        (dave, daveKey) = deriveRememberKey({ mnemonic: mnemonic, index: 4 });

        // Deploy alice safe.
        address[] memory signers = new address[](1);
        signers[0] = alice;
        aliceSafe = _deploySafe(signers, 1, 0);

        // Deploy contract signer safe.
        signers = new address[](3);
        signers[0] = aliceSafe;
        signers[1] = bob;
        signers[2] = carol;
        daoContractSigner = _deploySafe(signers, 2, 1);

        // Deploy Dao safe.
        signers = new address[](2);
        signers[0] = daoContractSigner;
        signers[1] = dave;
        daoSafe = _deploySafe(signers, 2, 2);

        vm.label(COMPATABILITY_FALLBACK_HANDLER, "COMPATABILITY_FALLBACK_HANDLER");
        vm.label(daoSafe, "daoSafe");
        vm.label(daoContractSigner, "daoContractSigner");
        vm.label(aliceSafe, "aliceSafe");
        vm.label(SAFE_SINGLETON, "SAFE_SINGLETON");
    }


    function test_SignFromContract() external {
        deal(daoSafe, 100 ether);

        // Get hashes.
        bytes memory txHashData = ISafe(daoSafe)
            .encodeTransactionData(
                address(WETH9), // to
                100 ether, // value
                abi.encodeWithSelector(WETH9.deposit.selector), // data
                Enum.Operation.Call, // operation
                0, // safeTxGas
                0, // baseGas
                0, // gasPrice
                address(0), // gasToken
                address(0), // refundReceiver
                ISafe(daoSafe).nonce() // nonce
            );

        bytes32 txHash = keccak256(txHashData);

        bytes memory daoContractSignerHashData = ISafe(daoContractSigner)
            .encodeMessageDataForSafe(ISafe(daoContractSigner), txHashData);

        bytes32 daoContractSignerHash = ISafe(daoContractSigner)
            .getMessageHashForSafe(ISafe(daoContractSigner), txHashData);

        bytes32 alicesHash = ISafe(aliceSafe)
            .getMessageHashForSafe(ISafe(aliceSafe), daoContractSignerHashData);


        // Sign.
        bytes memory aliceSig = _signPacked(aliceKey, alicesHash);
        bytes memory bobSig = _signPacked(bobKey, daoContractSignerHash);
        bytes memory daveSig = _signPacked(daveKey, txHash);

        // Assemble signatures.
        bytes memory contractSignerSig = bytes.concat(
            _sortTwoSigs(bob, aliceSafe, // Need to be sorted.
                bobSig, // EOA sig
                abi.encodePacked( // Contract sig
                    abi.encode(aliceSafe), // r 32-bytes signature verifier
                    uint256(130), // s 32-bytes data position
                    uint8(0) // v 1-byte signature type
                )
            ),
            abi.encode(aliceSig.length), // Length of bytes
            aliceSig
        );

        bytes memory signatures = bytes.concat(
            _sortTwoSigs(dave, daoContractSigner, // Need to be sorted.
            daveSig, // EOA sig
                abi.encodePacked( // Contract sig
                    abi.encode(daoContractSigner), // r 32-bytes signature verifier
                    uint256(130), // s 32-bytes data position
                    uint8(0) // v 1-byte signature type
                )
            ),
            abi.encode(contractSignerSig.length), // Length of bytes
            contractSignerSig
        );

        // Execute.
        ISafe(daoSafe).execTransaction(
            address(WETH9), // to
            100 ether, // value
            abi.encodeWithSelector(WETH9.deposit.selector), // data
            Enum.Operation.Call, // operation
            0, // safeTxGas
            0, // baseGas
            0, // gasPrice
            address(0), // gasToken
            payable(address(0)), // refundReceiver
            signatures // signatures
        );

    }

    function _signPacked(uint256 key, bytes32 hashToSign) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hashToSign);
        return abi.encodePacked(r, s, v);
    }

    function _deploySafe(address[] memory signers, uint256 m, uint256 salt) internal returns (address) {

        // Deploy.
        bytes memory initializer = abi.encodeWithSelector(
            ISafe.setup.selector,
            signers,
            m,
            address(0), // Delegate call `to`
            address(0), // Delegate call `data`
            COMPATABILITY_FALLBACK_HANDLER, // `fallbackHandler`
            address(0), // `paymentToken`
            address(0), // `payment`
            address(0) // `paymentReceiver`
        );
        return address(safeProxyFactory.createProxyWithNonce(SAFE_SINGLETON, initializer, salt));
    }

    function _sortTwoSigs(address a, address b, bytes memory sigA, bytes memory sigB)
        internal
        pure
        returns (bytes memory)
    {
        return a < b ? bytes.concat(sigA, sigB) : bytes.concat(sigB, sigA);
    }


}
