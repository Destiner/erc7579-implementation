// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { DecodeLib } from "../utils/Decode.sol";
import { IExecution } from "../interfaces/IMSA.sol";

/**
 * |---------------------------------------------|
 * | SELECTOR | EXEC_MODE | CONTEXT | CALLDATA   |
 * |---------------------------------------------|
 * | 8        | 8         | 30      | n-bytes    |
 * |---------------------------------------------|
 *
 * SELECTOR: 8 bits
 * Selector is used to determine how the data should be decoded.
 * It can be either single, batch or delegatecall. In the future different calls could be added. i.e. staticcall
 * Selector can be used by a validation module to determine how to decode <bytes data>.
 *
 * EXEC_MODE: 8 bits
 * Exec mode is used to determine how the account should handle the execution.
 * Validator Modules do not have to interpret this value.
 * It can indicate if the execution should revert on failure or continue execution.
 * FEEDBACK REQUEST: is it actually a good idea to make this an emum? it might be better
 * to use a bytes4 value, to avoid "collisions" of different behavior ideas of different account vendors in the futures
 *
 * CONTEXT: 30 bits
 * Context is used to pass data to the execution phase.
 * It can be used to decode additional context data that the smart account may interpret to change the execution behavior.
 *
 * CALLDATA: n bytes
 * single, delegatecall or batch exec encoded as bytes
 */

/**
 * this enum informs how the data should be decoded.
 * It defines if the execution is single/batched/delegatecall
 * this enum is in scope for validation modules to be able to decode the data
 */
enum SELECTOR {
    NONE,
    SINGLE,
    BATCH,
    DELEGATECALL
}

/**
 * this enum informs how the execution should be handled in the execution phase.
 * it should be out of scope for most validation modules
 */
enum EXEC_MODE {
    NONE,
    EXEC,
    TRY_EXEC
}

library ModeLib {
    function decode(bytes32 mode)
        internal
        pure
        returns (SELECTOR _selector, EXEC_MODE _mode, bytes30 _context)
    {
        assembly {
            _selector := shr(248, mode)
            _mode := shr(224, mode)
            _context := shr(192, mode)
        }
    }

    function encode(
        SELECTOR selector,
        EXEC_MODE mode,
        bytes30 context
    )
        internal
        pure
        returns (bytes32)
    {
        return bytes32(uint256(selector) << 248 | uint256(mode) << 224 | uint256(uint240(context)));
    }

    function encodeBatch(
        EXEC_MODE _mode,
        bytes30 context,
        IExecution.Execution[] calldata executions
    )
        internal
        pure
        returns (bytes32 mode, bytes memory data)
    {
        SELECTOR selector = SELECTOR.BATCH;
        mode = encode(selector, _mode, context);
        data = abi.encode(executions);
    }

    function encodeSingle(
        EXEC_MODE _mode,
        bytes30 context,
        address target,
        uint256 value,
        bytes calldata callData
    )
        internal
        pure
        returns (bytes32 mode, bytes memory data)
    {
        SELECTOR selector = SELECTOR.SINGLE;
        mode = encode(selector, _mode, context);
        data = abi.encode(target, value, callData);
    }
}

abstract contract ModeExecution {
    using ModeLib for bytes32;
    using DecodeLib for bytes;

    function executeMode(bytes32 _mode, bytes calldata data) external payable {
        // handle batch
        (SELECTOR selector, EXEC_MODE mode, bytes30 context) = _mode.decode();

        // (optional) decode stuff from context
        if (selector == SELECTOR.BATCH) {
            IExecution.Execution[] calldata executions = data.decodeBatch();
            if (mode == EXEC_MODE.EXEC) {
                _execute(executions);
            } else if (mode == EXEC_MODE.TRY_EXEC) {
                _tryExecute(executions);
            }
        } else if (selector == SELECTOR.SINGLE) {
            (address target, uint256 value, bytes calldata callData) = data.decodeSingle();
            if (mode == EXEC_MODE.EXEC) {
                _execute(target, value, callData);
            } else if (mode == EXEC_MODE.TRY_EXEC) {
                _tryExecute(target, value, callData);
            }
        }
    }

    function supportsMode(SELECTOR selector, EXEC_MODE mode) external view virtual returns (bool) {
        if (mode == EXEC_MODE.EXEC) {
            return selector == SELECTOR.SINGLE || selector == SELECTOR.BATCH;
        } else if (mode == EXEC_MODE.TRY_EXEC) {
            return selector == SELECTOR.SINGLE || selector == SELECTOR.BATCH;
        } else {
            return false;
        }
    }

    function _execute(
        address target,
        uint256 value,
        bytes calldata callData
    )
        internal
        virtual
        returns (bytes[] memory result);

    function _execute(IExecution.Execution[] calldata executions)
        internal
        virtual
        returns (bytes[] memory result);

    function _tryExecute(
        address target,
        uint256 value,
        bytes calldata callData
    )
        internal
        virtual
        returns (bytes[] memory result);

    function _tryExecute(IExecution.Execution[] calldata executions)
        internal
        virtual
        returns (bytes[] memory result);
}
