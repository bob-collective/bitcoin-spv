pragma solidity ^0.8.4;

import {BTCUtils} from "./BTCUtils.sol";
import {BytesLib} from "./BytesLib.sol";

library SegWitUtils {
    using BTCUtils for bytes;
    using BytesLib for bytes;

    bytes6 public constant WITNESS_MAGIC_BYTES = hex"6a24aa21a9ed";
    uint256 public constant COINBASE_WITNESS_PK_SCRIPT_LENGTH = 38;
    bytes1 public constant TAPROOT_ANNEX_PREFIX = 0x50;

    function isWitnessCommitment(
        bytes memory pkScript
    ) internal pure returns (bool) {
        return
            pkScript.length >= COINBASE_WITNESS_PK_SCRIPT_LENGTH &&
            bytes6(pkScript.slice32(0)) == WITNESS_MAGIC_BYTES;
    }

    // https://github.com/btcsuite/btcd/blob/80f5a0ffdf363cfff27d550f9e38aa262667a7f1/blockchain/merkle.go#L192
    function extractWitnessCommitment(
        bytes memory _vout
    ) internal pure returns (bytes32) {
        uint256 _varIntDataLen;
        uint256 _nOuts;

        (_varIntDataLen, _nOuts) = _vout.parseVarInt();
        require(
            _varIntDataLen != BTCUtils.ERR_BAD_ARG,
            "Read overrun during VarInt parsing"
        );

        uint256 _len = 0;
        uint256 _offset = 1 + _varIntDataLen;

        for (uint256 _i = 0; _i < _nOuts; _i++) {
            _len = _vout.determineOutputLengthAt(_offset);
            require(_len != BTCUtils.ERR_BAD_ARG, "Bad VarInt in scriptPubkey");
            bytes memory _output = _vout.slice(_offset, _len);
            if (_output[8] == hex"26") {
                // skip 8-byte value
                bytes memory _pkScript = _output.slice(
                    9,
                    COINBASE_WITNESS_PK_SCRIPT_LENGTH
                );
                if (isWitnessCommitment(_pkScript)) {
                    return
                        bytes32(
                            _pkScript.slice(
                                WITNESS_MAGIC_BYTES.length,
                                COINBASE_WITNESS_PK_SCRIPT_LENGTH -
                                    WITNESS_MAGIC_BYTES.length
                            )
                        );
                }
            }
            _offset += _len;
        }

        return hex"";
    }

    /// @notice          Determines the length of a witness from its elements,
    ///                  starting at the specified position
    /// @param _witness  The byte array containing the witness
    /// @param _at       The position of the witness in the array
    /// @return          The length of the witness in bytes
    function determineWitnessLengthAt(
        bytes memory _witness,
        uint256 _at
    ) internal pure returns (uint256) {
        uint256 _varIntDataLen;
        uint256 _nWit;

        (_varIntDataLen, _nWit) = _witness.parseVarIntAt(_at);
        require(
            _varIntDataLen != BTCUtils.ERR_BAD_ARG,
            "Read overrun during VarInt parsing"
        );

        uint256 _len = 0;
        uint256 _offset = 1 + _varIntDataLen;

        for (uint256 _i = 0; _i < _nWit; _i++) {
            (_varIntDataLen, _len) = _witness.parseVarIntAt(_at + _offset);
            require(_len != BTCUtils.ERR_BAD_ARG, "Bad VarInt in witness");
            _offset = _offset + 1 + _varIntDataLen + _len;
        }

        return _offset;
    }

    /// @notice                Extracts the nth witness from the witness vector (0-indexed)
    /// @dev                   Iterates over the witness vector. If you need to extract several, write a custom function
    /// @param _witnessVector  The witness as a tightly-packed byte array
    /// @param _index          The 0-indexed location of the witness to extract
    /// @return                The witness vector as a byte array
    function extractWitnessAtIndex(
        bytes memory _witnessVector,
        uint256 _index
    ) internal pure returns (bytes memory) {
        uint256 _len = 0;
        uint256 _offset = 0;

        // NOTE: there is no VarInt preceeding the witness vector
        // if you want to know the number of elements check the input
        for (uint256 _i = 0; _i < _index; _i++) {
            _len = determineWitnessLengthAt(_witnessVector, _offset);
            require(_len != BTCUtils.ERR_BAD_ARG, "Bad VarInt in witness");
            _offset = _offset + _len;
        }

        _len = determineWitnessLengthAt(_witnessVector, _offset);
        require(_len != BTCUtils.ERR_BAD_ARG, "Bad VarInt in scriptSig");
        return _witnessVector.slice(_offset, _len);
    }

    // https://github.com/rust-bitcoin/rust-bitcoin/blob/8aa5501827a0dd5b27abf304a5f9bdefb07a2cc6/bitcoin/src/blockdata/witness.rs#L386-L406
    function extractTapscript(
        bytes memory _witness
    ) internal pure returns (bytes memory) {
        uint256 _varIntDataLen;
        uint256 _nWit;

        (_varIntDataLen, _nWit) = _witness.parseVarInt();
        require(
            _varIntDataLen != BTCUtils.ERR_BAD_ARG,
            "Read overrun during VarInt parsing"
        );

        uint256[] memory _offsets = new uint256[](_nWit);

        uint256 _len = 0;
        uint256 _offset = 1 + _varIntDataLen;

        for (uint256 _i = 0; _i < _nWit; _i++) {
            _offsets[_i] = _offset;
            (_varIntDataLen, _len) = _witness.parseVarIntAt(_offset);
            require(_len != BTCUtils.ERR_BAD_ARG, "Bad VarInt in witness");
            _offset = _offset + 1 + _varIntDataLen + _len;
        }

        uint256 scriptPosFromLast = 2;
        if (
            _nWit >= 2 && _witness[_offsets[_nWit - 1]] == TAPROOT_ANNEX_PREFIX
        ) {
            scriptPosFromLast = 3;
        }

        _offset = _offsets[_nWit - scriptPosFromLast];
        (, _len) = _witness.parseVarIntAt(_offset);
        require(_len != BTCUtils.ERR_BAD_ARG, "Bad VarInt in witness");

        return _witness.slice(_offset, _len);
    }
}
