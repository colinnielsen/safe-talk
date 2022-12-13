// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import "safe-contracts/external/GnosisSafeMath.sol";
import "safe-contracts/interfaces/ERC1155TokenReceiver.sol";
import "safe-contracts/interfaces/ERC721TokenReceiver.sol";
import "safe-contracts/interfaces/ERC777TokensRecipient.sol";
import "safe-contracts/interfaces/IERC165.sol";

enum Operation {
    Call,
    DelegateCall
}

/// @notice EIP1271 interface
interface ISignatureValidator {
    function isValidSignature(bytes memory _data, bytes memory _signature) external view returns (bytes4);
}

/// @notice GuardInterface
interface Guard {
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external;

    function checkAfterExecution(bytes32 txHash, bool success) external;
}

//
////// CONSTANTS //////
//
address constant SENTINEL_MODULES = address(0x1);
address constant SENTINEL_OWNERS = address(0x1);
bytes4 constant EIP1271_MAGIC_VALUE = 0x20c13b0b;
// keccak256("fallback_manager.handler.address")
bytes32 constant FALLBACK_HANDLER_STORAGE_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
// keccak256("guard_manager.guard.address")
bytes32 constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
// keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
bytes32 constant DOMAIN_SEPARATOR_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
// keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)");
bytes32 constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;
// keccak256("SafeMessage(bytes message)");
bytes32 constant SAFE_MSG_TYPEHASH = 0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;
bytes4 constant SIMULATE_SELECTOR = bytes4(keccak256("simulate(address,bytes)"));
bytes4 constant UPDATED_MAGIC_VALUE = 0x1626ba7e;

contract FlatSafe {
    using GnosisSafeMath for uint256;

    //
    ////// STORAGE //////
    //

    /// @notice Singleton/GnosisSafeProxy
    /// @dev singleton always needs to be first declared variable, to ensure that it is at the same location as in the Proxy contract.
    ///      It should also always be ensured that the address is stored alone (uses a full word)
    address private singleton;

    /// @notice ModuleManager
    mapping(address => address) internal modules;

    /// @notice OwnerManager
    mapping(address => address) internal owners;
    uint256 internal ownerCount;
    uint256 internal threshold;

    /// @notice GnosisSafe
    string public constant VERSION = "1.3.0";
    uint256 public nonce;
    bytes32 private _deprecatedDomainSeparator;
    // Mapping to keep track of all message hashes that have been approve by ALL REQUIRED owners
    mapping(bytes32 => uint256) public signedMessages;
    // Mapping to keep track of all hashes (message or transaction) that have been approve by ANY owners
    mapping(address => mapping(bytes32 => uint256)) public approvedHashes;

    constructor() {
        threshold = 1;
    }

    ////// EVENTS //////

    /// EtherPaymentFallback
    event SafeReceived(address indexed sender, uint256 value);

    /// ModuleManager
    event EnabledModule(address module);
    event DisabledModule(address module);
    event ExecutionFromModuleSuccess(address indexed module);
    event ExecutionFromModuleFailure(address indexed module);

    /// OwnerManager
    event AddedOwner(address owner);
    event RemovedOwner(address owner);
    event ChangedThreshold(uint256 threshold);

    /// FallbackManager
    event ChangedFallbackHandler(address handler);

    /// GuardManager
    event ChangedGuard(address guard);

    /// GnosisSafe
    event SafeSetup(
        address indexed initiator, address[] owners, uint256 threshold, address initializer, address fallbackHandler
    );
    event ApproveHash(bytes32 indexed approvedHash, address indexed owner);
    event SignMsg(bytes32 indexed msgHash);
    event ExecutionFailure(bytes32 txHash, uint256 payment);
    event ExecutionSuccess(bytes32 txHash, uint256 payment);

    //
    ////// WRITE FUNCTIONS //////
    //

    /// @notice GnosisSafe.setup
    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external {
        setupOwners(_owners, _threshold);
        if (fallbackHandler != address(0)) {
            internalSetFallbackHandler(fallbackHandler);
        }
        setupModules(to, data);

        if (payment > 0) {
            handlePayment(payment, 0, 1, paymentToken, paymentReceiver);
        }

        emit SafeSetup(msg.sender, _owners, _threshold, to, fallbackHandler);
    }

    /// @notice Executor.execute
    function execute(address to, uint256 value, bytes memory data, Operation operation, uint256 txGas)
        internal
        returns (bool success)
    {
        if (operation == Operation.DelegateCall) {
            assembly {
                success := delegatecall(txGas, to, add(data, 0x20), mload(data), 0, 0)
            }
        } else {
            assembly {
                success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
            }
        }
    }

    /// @notice GnosisSafe.execTransaction
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) public payable virtual returns (bool success) {
        bytes32 txHash;
        {
            bytes memory txHashData = encodeTransactionData(
                // Transaction info
                to,
                value,
                data,
                operation,
                safeTxGas,
                // Payment info
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                // Signature info
                nonce
            );
            // Increase nonce and execute transaction.
            nonce++;
            txHash = keccak256(txHashData);
            checkSignatures(txHash, txHashData, signatures);
        }
        address guard = getGuard();
        {
            if (guard != address(0)) {
                Guard(guard).checkTransaction(
                    // Transaction info
                    to,
                    value,
                    data,
                    operation,
                    safeTxGas,
                    // Payment info
                    baseGas,
                    gasPrice,
                    gasToken,
                    refundReceiver,
                    // Signature info
                    signatures,
                    msg.sender
                );
            }
        }
        // We require some gas to emit the events (at least 2500) after the execution and some to perform code until the execution (500)
        // We also include the 1/64 in the check that is not send along with a call to counteract potential shortings because of EIP-150
        require(gasleft() >= ((safeTxGas * 64) / 63).max(safeTxGas + 2500) + 500, "GS010");
        {
            uint256 gasUsed = gasleft();
            // If the gasPrice is 0 we assume that nearly all available gas can be used (it is always more than safeTxGas)
            // We only substract 2500 (compared to the 3000 before) to ensure that the amount passed is still higher than safeTxGas
            success = execute(to, value, data, operation, gasPrice == 0 ? (gasleft() - 2500) : safeTxGas);
            gasUsed = gasUsed.sub(gasleft());
            // If no safeTxGas and no gasPrice was set (e.g. both are 0), then the internal tx is required to be successful
            // This makes it possible to use `estimateGas` without issues, as it searches for the minimum gas where the tx doesn't revert
            require(success || safeTxGas != 0 || gasPrice != 0, "GS013");
            // We transfer the calculated tx costs to the tx.origin to avoid sending it to intermediate contracts that have made calls
            uint256 payment = 0;
            if (gasPrice > 0) {
                payment = handlePayment(gasUsed, baseGas, gasPrice, gasToken, refundReceiver);
            }
            if (success) emit ExecutionSuccess(txHash, payment);
            else emit ExecutionFailure(txHash, payment);
        }
        {
            if (guard != address(0)) {
                Guard(guard).checkAfterExecution(txHash, success);
            }
        }
    }

    /// @notice ModuleManager.execTransactionFromModule
    function execTransactionFromModule(address to, uint256 value, bytes memory data, Operation operation)
        public
        virtual
        returns (bool success)
    {
        // Only whitelisted modules are allowed.
        require(msg.sender != SENTINEL_MODULES && modules[msg.sender] != address(0), "GS104");
        // Execute transaction without further confirmations.
        success = execute(to, value, data, operation, gasleft());
        if (success) emit ExecutionFromModuleSuccess(msg.sender);
        else emit ExecutionFromModuleFailure(msg.sender);
    }

    /// @notice ModuleManager.execTransactionFromModuleReturnData
    function execTransactionFromModuleReturnData(address to, uint256 value, bytes memory data, Operation operation)
        public
        returns (bool success, bytes memory returnData)
    {
        success = execTransactionFromModule(to, value, data, operation);
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Load free memory location
            let ptr := mload(0x40)
            // We allocate memory for the return data by setting the free memory location to
            // current free memory location + data size + 32 bytes for data size value
            mstore(0x40, add(ptr, add(returndatasize(), 0x20)))
            // Store the size
            mstore(ptr, returndatasize())
            // Store the data
            returndatacopy(add(ptr, 0x20), 0, returndatasize())
            // Point the return data to the correct memory location
            returnData := ptr
        }
    }

    /// @notice GnosisSafe.handlePayment
    function handlePayment(
        uint256 gasUsed,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver
    ) private returns (uint256 payment) {
        address payable receiver = refundReceiver == address(0) ? payable(tx.origin) : refundReceiver;
        if (gasToken == address(0)) {
            // For ETH we will only adjust the gas price to not be higher than the actual used gas price
            payment = gasUsed.add(baseGas).mul(gasPrice < tx.gasprice ? gasPrice : tx.gasprice);
            require(receiver.send(payment), "GS011");
        } else {
            payment = gasUsed.add(baseGas).mul(gasPrice);
            require(transferToken(gasToken, receiver, payment), "GS012");
        }
    }

    /// @notice GnosisSafe.approveHash
    function approveHash(bytes32 hashToApprove) external {
        require(owners[msg.sender] != address(0), "GS030");
        approvedHashes[msg.sender][hashToApprove] = 1;
        emit ApproveHash(hashToApprove, msg.sender);
    }

    /// @notice GuardManager.setGuard
    function setGuard(address guard) external authorized {
        bytes32 slot = GUARD_STORAGE_SLOT;
        assembly {
            sstore(slot, guard)
        }
        emit ChangedGuard(guard);
    }

    /// @notice ModuleManager.setupModules
    function setupModules(address to, bytes memory data) internal {
        require(modules[SENTINEL_MODULES] == address(0), "GS100");
        modules[SENTINEL_MODULES] = SENTINEL_MODULES;
        if (to != address(0)) {
            // Setup has to complete successfully or transaction fails.
            require(execute(to, 0, data, Operation.DelegateCall, gasleft()), "GS000");
        }
    }

    /// @notice ModuleManager.enableModule
    function enableModule(address module) public authorized {
        // Module address cannot be null or sentinel.
        require(module != address(0) && module != SENTINEL_MODULES, "GS101");
        // Module cannot be added twice.
        require(modules[module] == address(0), "GS102");
        modules[module] = modules[SENTINEL_MODULES];
        modules[SENTINEL_MODULES] = module;
        emit EnabledModule(module);
    }

    /// @notice ModuleManager.disableModule
    function disableModule(address prevModule, address module) public authorized {
        // Validate module address and check that it corresponds to module index.
        require(module != address(0) && module != SENTINEL_MODULES, "GS101");
        require(modules[prevModule] == module, "GS103");
        modules[prevModule] = modules[module];
        modules[module] = address(0);
        emit DisabledModule(module);
    }

    /// @notice FallbackManager.fallback
    fallback() external {
        bytes32 slot = FALLBACK_HANDLER_STORAGE_SLOT;
        assembly {
            let handler := sload(slot)
            if iszero(handler) { return(0, 0) }
            calldatacopy(0, 0, calldatasize())
            // The msg.sender address is shifted to the left by 12 bytes to remove the padding
            // Then the address without padding is stored right after the calldata
            mstore(calldatasize(), shl(96, caller()))
            // Add 20 bytes for the address appended add the end
            let success := call(gas(), handler, 0, 0, add(calldatasize(), 20), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(success) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }

    /// @notice EtherPaymentFallback.receive
    receive() external payable {
        emit SafeReceived(msg.sender, msg.value);
    }

    /// @notice OwnerManager.setupOwners
    function setupOwners(address[] memory _owners, uint256 _threshold) internal {
        // Threshold can only be 0 at initialization.
        // Check ensures that setup function can only be called once.
        require(threshold == 0, "GS200");
        // Validate that threshold is smaller than number of added owners.
        require(_threshold <= _owners.length, "GS201");
        // There has to be at least one Safe owner.
        require(_threshold >= 1, "GS202");
        // Initializing Safe owners.
        address currentOwner = SENTINEL_OWNERS;
        for (uint256 i = 0; i < _owners.length; i++) {
            // Owner address cannot be null.
            address owner = _owners[i];
            require(
                owner != address(0) && owner != SENTINEL_OWNERS && owner != address(this) && currentOwner != owner,
                "GS203"
            );
            // No duplicate owners allowed.
            require(owners[owner] == address(0), "GS204");
            owners[currentOwner] = owner;
            currentOwner = owner;
        }
        owners[currentOwner] = SENTINEL_OWNERS;
        ownerCount = _owners.length;
        threshold = _threshold;
    }

    /// @notice OwnerManager.addOwnerWithThreshold
    function addOwnerWithThreshold(address owner, uint256 _threshold) public authorized {
        // Owner address cannot be null, the sentinel or the Safe itself.
        require(owner != address(0) && owner != SENTINEL_OWNERS && owner != address(this), "GS203");
        // No duplicate owners allowed.
        require(owners[owner] == address(0), "GS204");
        owners[owner] = owners[SENTINEL_OWNERS];
        owners[SENTINEL_OWNERS] = owner;
        ownerCount++;
        emit AddedOwner(owner);
        // Change threshold if threshold was changed.
        if (threshold != _threshold) changeThreshold(_threshold);
    }

    /// @notice OwnerManager.removeOwner
    function removeOwner(address prevOwner, address owner, uint256 _threshold) public authorized {
        // Only allow to remove an owner, if threshold can still be reached.
        require(ownerCount - 1 >= _threshold, "GS201");
        // Validate owner address and check that it corresponds to owner index.
        require(owner != address(0) && owner != SENTINEL_OWNERS, "GS203");
        require(owners[prevOwner] == owner, "GS205");
        owners[prevOwner] = owners[owner];
        owners[owner] = address(0);
        ownerCount--;
        emit RemovedOwner(owner);
        // Change threshold if threshold was changed.
        if (threshold != _threshold) changeThreshold(_threshold);
    }

    /// @notice OwnerManager.swapOwner
    function swapOwner(address prevOwner, address oldOwner, address newOwner) public authorized {
        // Owner address cannot be null, the sentinel or the Safe itself.
        require(newOwner != address(0) && newOwner != SENTINEL_OWNERS && newOwner != address(this), "GS203");
        // No duplicate owners allowed.
        require(owners[newOwner] == address(0), "GS204");
        // Validate oldOwner address and check that it corresponds to owner index.
        require(oldOwner != address(0) && oldOwner != SENTINEL_OWNERS, "GS203");
        require(owners[prevOwner] == oldOwner, "GS205");
        owners[newOwner] = owners[oldOwner];
        owners[prevOwner] = newOwner;
        owners[oldOwner] = address(0);
        emit RemovedOwner(oldOwner);
        emit AddedOwner(newOwner);
    }

    /// @notice OwnerManager.changeThreshold
    function changeThreshold(uint256 _threshold) public authorized {
        // Validate that threshold is smaller than number of owners.
        require(_threshold <= ownerCount, "GS201");
        // There has to be at least one Safe owner.
        require(_threshold >= 1, "GS202");
        threshold = _threshold;
        emit ChangedThreshold(threshold);
    }

    /// @notice SecuredTokenTransfer.transferToken
    function transferToken(address token, address receiver, uint256 amount) internal returns (bool transferred) {
        // 0xa9059cbb - keccack("transfer(address,uint256)")
        bytes memory data = abi.encodeWithSelector(0xa9059cbb, receiver, amount);
        assembly {
            let success := call(sub(gas(), 10000), token, 0, add(data, 0x20), mload(data), 0, 0x20)
            switch returndatasize()
            case 0 { transferred := success }
            case 0x20 { transferred := iszero(or(iszero(success), iszero(mload(0)))) }
            default { transferred := 0 }
        }
    }

    /// @notice FallbackManager.setFallbackHandler
    function setFallbackHandler(address handler) public authorized {
        internalSetFallbackHandler(handler);
        emit ChangedFallbackHandler(handler);
    }

    /// @notice FallbackManager.internalSetFallbackHandler
    function internalSetFallbackHandler(address handler) internal {
        bytes32 slot = FALLBACK_HANDLER_STORAGE_SLOT;
        assembly {
            sstore(slot, handler)
        }
    }

    //
    ////// READ FUNCTIONS //////
    //

    /// @notice GnosisSafe.checkNSignatures
    function checkNSignatures(bytes32 dataHash, bytes memory data, bytes memory signatures, uint256 requiredSignatures)
        public
        view
    {
        // Check that the provided signature data is not too short
        require(signatures.length >= requiredSignatures.mul(65), "GS020");
        // There cannot be an owner with address 0.
        address lastOwner = address(0);
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;
        for (i = 0; i < requiredSignatures; i++) {
            (v, r, s) = signatureSplit(signatures, i);
            if (v == 0) {
                // If v is 0 then it is a contract signature
                // When handling contract signatures the address of the contract is encoded into r
                currentOwner = address(uint160(uint256(r)));

                // Check that signature data pointer (s) is not pointing inside the static part of the signatures bytes
                // This check is not completely accurate, since it is possible that more signatures than the threshold are send.
                // Here we only check that the pointer is not pointing inside the part that is being processed
                require(uint256(s) >= requiredSignatures.mul(65), "GS021");

                // Check that signature data pointer (s) is in bounds (points to the length of data -> 32 bytes)
                require(uint256(s).add(32) <= signatures.length, "GS022");

                // Check if the contract signature is in bounds: start of data is s + 32 and end is start + signature length
                uint256 contractSignatureLen;
                assembly {
                    contractSignatureLen := mload(add(add(signatures, s), 0x20))
                }
                require(uint256(s).add(32).add(contractSignatureLen) <= signatures.length, "GS023");

                // Check signature
                bytes memory contractSignature;
                assembly {
                    // The signature data for contract signatures is appended to the concatenated signatures and the offset is stored in s
                    contractSignature := add(add(signatures, s), 0x20)
                }
                require(
                    ISignatureValidator(currentOwner).isValidSignature(data, contractSignature) == EIP1271_MAGIC_VALUE,
                    "GS024"
                );
            } else if (v == 1) {
                // If v is 1 then it is an approved hash
                // When handling approved hashes the address of the approver is encoded into r
                currentOwner = address(uint160(uint256(r)));
                // Hashes are automatically approved by the sender of the message or when they have been pre-approved via a separate transaction
                require(msg.sender == currentOwner || approvedHashes[currentOwner][dataHash] != 0, "GS025");
            } else if (v > 30) {
                // If v > 30 then default va (27,28) has been adjusted for eth_sign flow
                // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
                currentOwner =
                    ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s);
            } else {
                // Default is the ecrecover flow with the provided data hash
                // Use ecrecover with the messageHash for EOA signatures
                currentOwner = ecrecover(dataHash, v, r, s);
            }
            require(
                currentOwner > lastOwner && owners[currentOwner] != address(0) && currentOwner != SENTINEL_OWNERS,
                "GS026"
            );
            lastOwner = currentOwner;
        }
    }

    /// @notice GnosisSafe.checkSignatures
    function checkSignatures(bytes32 dataHash, bytes memory data, bytes memory signatures) public view {
        // Load threshold to avoid multiple storage loads
        uint256 _threshold = threshold;
        // Check that a threshold is set
        require(_threshold > 0, "GS001");
        checkNSignatures(dataHash, data, signatures, _threshold);
    }

    /// @notice GnosisSafe.encodeTransactionData
    function encodeTransactionData(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) public view returns (bytes memory) {
        bytes32 safeTxHash = keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                to,
                value,
                keccak256(data),
                operation,
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                _nonce
            )
        );
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), safeTxHash);
    }

    /// @notice GnosisSafe.getTransactionHash
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) public view returns (bytes32) {
        return keccak256(
            encodeTransactionData(
                to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce
            )
        );
    }

    /// @notice ModuleManager.isModuleEnabled
    function isModuleEnabled(address module) public view returns (bool) {
        return SENTINEL_MODULES != module && modules[module] != address(0);
    }

    /// @notice ModuleManager.getModulesPaginated
    function getModulesPaginated(address start, uint256 pageSize)
        external
        view
        returns (address[] memory array, address next)
    {
        // Init array with max page size
        array = new address[](pageSize);

        // Populate return array
        uint256 moduleCount = 0;
        address currentModule = modules[start];
        while (currentModule != address(0x0) && currentModule != SENTINEL_MODULES && moduleCount < pageSize) {
            array[moduleCount] = currentModule;
            currentModule = modules[currentModule];
            moduleCount++;
        }
        next = currentModule;
        // Set correct size of returned array
        // solhint-disable-next-line no-inline-assembly
        assembly {
            mstore(array, moduleCount)
        }
    }

    /// @notice StorageAccessible.getStorageAt
    function getStorageAt(uint256 offset, uint256 length) public view returns (bytes memory) {
        bytes memory result = new bytes(length * 32);
        for (uint256 index = 0; index < length; index++) {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                let word := sload(add(offset, index))
                mstore(add(add(result, 0x20), mul(index, 0x20)), word)
            }
        }
        return result;
    }

    /// @notice GnosisSafe.requiredTxGas
    function requiredTxGas(address to, uint256 value, bytes calldata data, Operation operation)
        external
        returns (uint256)
    {
        uint256 startGas = gasleft();
        // We don't provide an error message here, as we use it to return the estimate
        require(execute(to, value, data, operation, gasleft()));
        uint256 requiredGas = startGas - gasleft();
        // Convert response to string and return via error message
        revert(string(abi.encodePacked(requiredGas)));
    }

    /// @notice StorageAccessible.simulateAndRevert
    function simulateAndRevert(address targetContract, bytes memory calldataPayload) external {
        assembly {
            let success := delegatecall(gas(), targetContract, add(calldataPayload, 0x20), mload(calldataPayload), 0, 0)

            mstore(0x00, success)
            mstore(0x20, returndatasize())
            returndatacopy(0x40, 0, returndatasize())
            revert(0, add(returndatasize(), 0x40))
        }
    }

    /// @notice OwnerManager.getThreshold
    function getThreshold() public view returns (uint256) {
        return threshold;
    }

    /// @notice OwnerManager.isOwner
    function isOwner(address owner) public view returns (bool) {
        return owner != SENTINEL_OWNERS && owners[owner] != address(0);
    }

    /// @notice OwnerManager.getOwners
    function getOwners() public view returns (address[] memory) {
        address[] memory array = new address[](ownerCount);

        // populate return array
        uint256 index = 0;
        address currentOwner = owners[SENTINEL_OWNERS];
        while (currentOwner != SENTINEL_OWNERS) {
            array[index] = currentOwner;
            currentOwner = owners[currentOwner];
            index++;
        }
        return array;
    }

    /// @notice GuardManager.getGuard
    function getGuard() internal view returns (address guard) {
        bytes32 slot = GUARD_STORAGE_SLOT;
        assembly {
            guard := sload(slot)
        }
    }

    /// @notice GnosisSafe.getChainId
    function getChainId() public view returns (uint256) {
        uint256 id;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            id := chainid()
        }
        return id;
    }

    /// @notice GnosisSafe.domainSeparator
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, getChainId(), this));
    }

    /// @notice SignatureDecoded.signatureSplit
    function signatureSplit(bytes memory signatures, uint256 pos)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        // The signature format is a compact form of:
        //   {bytes32 r}{bytes32 s}{uint8 v}
        // Compact means, uint8 is not padded to 32 bytes.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            v := and(mload(add(signatures, add(signaturePos, 0x41))), 0xff)
        }
    }

    /// @notice SelfAuthorized.requireSelfCall
    function requireSelfCall() private view {
        require(msg.sender == address(this), "GS031");
    }

    /// @notice SelfAuthorized.authorized
    modifier authorized() {
        requireSelfCall();
        _;
    }
}

/// @notice this contract is deployed with every safe deployed from the Safe UI
contract CompatibilityFallbackHandler {
    /// @notice CompatibilityFallbackHandler.isValidSignature / EIP1271.isValidSignature
    function isValidSignature(bytes calldata _data, bytes calldata _signature) public view returns (bytes4) {
        // Caller should be a Safe
        FlatSafe safe = FlatSafe(payable(msg.sender));
        bytes32 messageHash = getMessageHashForSafe(safe, _data);
        if (_signature.length == 0) {
            require(safe.signedMessages(messageHash) != 0, "Hash not approved");
        } else {
            safe.checkSignatures(messageHash, _data, _signature);
        }
        return EIP1271_MAGIC_VALUE;
    }

    /// @notice CompatibilityFallbackHandler.getMessageHash
    function getMessageHash(bytes memory message) public view returns (bytes32) {
        return getMessageHashForSafe(FlatSafe(payable(msg.sender)), message);
    }

    /// @notice CompatibilityFallbackHandler.getMessageHashForSafe
    function getMessageHashForSafe(FlatSafe safe, bytes memory message) public view returns (bytes32) {
        bytes32 safeMessageHash = keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(message)));
        return keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), safe.domainSeparator(), safeMessageHash));
    }

    /// @notice CompatibilityFallbackHandler.isValidSignature (OLD EIP-1271)
    function isValidSignature(bytes32 _dataHash, bytes calldata _signature) external view returns (bytes4) {
        ISignatureValidator validator = ISignatureValidator(msg.sender);
        bytes4 value = validator.isValidSignature(abi.encode(_dataHash), _signature);
        return (value == EIP1271_MAGIC_VALUE) ? UPDATED_MAGIC_VALUE : bytes4(0);
    }

    /// @notice CompatibilityFallbackHandler.getModules (GnosisSafe 1.1.1)
    function getModules() external view returns (address[] memory) {
        FlatSafe safe = FlatSafe(payable(msg.sender));
        (address[] memory array,) = safe.getModulesPaginated(SENTINEL_MODULES, 10);
        return array;
    }

    /// @notice CompatibilityFallbackHandler.simulate
    function simulate(address targetContract, bytes calldata calldataPayload)
        external
        returns (bytes memory response)
    {
        targetContract;
        calldataPayload;

        assembly {
            let internalCalldata := mload(0x40)
            // Store `simulateAndRevert.selector`.
            // String representation is used to force right padding
            mstore(internalCalldata, "\xb4\xfa\xba\x09")
            // Abuse the fact that both this and the internal methods have the
            // same signature, and differ only in symbol name (and therefore,
            // selector) and copy calldata directly. This saves us approximately
            // 250 bytes of code and 300 gas at runtime over the
            // `abi.encodeWithSelector` builtin.
            calldatacopy(add(internalCalldata, 0x04), 0x04, sub(calldatasize(), 0x04))

            // `pop` is required here by the compiler, as top level expressions
            // can't have return values in inline assembly. `call` typically
            // returns a 0 or 1 value indicated whether or not it reverted, but
            // since we know it will always revert, we can safely ignore it.
            pop(
                call(
                    gas(),
                    caller(),
                    0,
                    internalCalldata,
                    calldatasize(),
                    // The `simulateAndRevert` call always reverts, and
                    // instead encodes whether or not it was successful in the return
                    // data. The first 32-byte word of the return data contains the
                    // `success` value, so write it to memory address 0x00 (which is
                    // reserved Solidity scratch space and OK to use).
                    0x00,
                    0x20
                )
            )

            // Allocate and copy the response bytes, making sure to increment
            // the free memory pointer accordingly (in case this method is
            // called as an internal function). The remaining `returndata[0x20:]`
            // contains the ABI encoded response bytes, so we can just write it
            // as is to memory.
            let responseSize := sub(returndatasize(), 0x20)
            response := mload(0x40)
            mstore(0x40, add(response, responseSize))
            returndatacopy(response, 0x20, responseSize)

            if iszero(mload(0x00)) { revert(add(response, 0x20), mload(response)) }
        }
    }

    /// @notice DefaultCallbackHandler token receive functions
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return 0xf23a6e61;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return 0xbc197c81;
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return 0x150b7a02;
    }

    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external pure {
        // We implement this for completeness, doesn't really have any value
    }

    /// ERC-165 support
    function supportsInterface(bytes4 interfaceId) external view virtual returns (bool) {
        return interfaceId == type(ERC1155TokenReceiver).interfaceId
            || interfaceId == type(ERC721TokenReceiver).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
