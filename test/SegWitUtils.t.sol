// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import {SegWitUtils} from "../src/SegWitUtils.sol";

import {Test, console2} from "forge-std/Test.sol";

contract SegWitUtilsTest is Test {
    using SegWitUtils for bytes;

    function test_IsWitnessTxOut() public {
        bytes memory pkScript = hex"6a24aa21a9edaf8dcb9588f94a3adb462e80f1306d96ef6ffad72160b33cd5e90045d81e0d77";
        assert(pkScript.isWitnessCommitment());
    }

    function test_ExtractWitnessCommitmentFromTxOut() public {
        bytes memory outputVector =
            hex"020593cb260000000016001435f6de260c9f3bdee47524c473a6016c0c055cb90000000000000000266a24aa21a9edaf8dcb9588f94a3adb462e80f1306d96ef6ffad72160b33cd5e90045d81e0d77";
        bytes32 witnessCommitment = outputVector.extractWitnessCommitment();
        bytes32 coinbaseWitnessCommitment = hex"af8dcb9588f94a3adb462e80f1306d96ef6ffad72160b33cd5e90045d81e0d77";
        assertEq(coinbaseWitnessCommitment, witnessCommitment);
    }

    // 120c1b297faedd14568b7f02cc15725864d0ec2a9d6a42af764c03827ccc1c72
    function test_ExtractWitnessAtIndex() public {
        bytes memory witnessVector =
            hex"0247304402203c643747293b2f1e3f42253e8307147fa46086f065bdaddb7540c0862e7133c2022031e9cc284d643ae1c0fc139dad929136edc7bb3454512f11a0cbc4117240e604012103608b21667ba574f0177cd505c7b33c657b0fdb62ebb913fdd537a5358a22c6ec0247304402203cbccb97dc9eac21436325d551960ae41a55f00edcb0a39e1099ecf8ab3cbf9f02200f04f061eb50de21ea0ef98ad6ba913c3ee43306f9e2d2ce57576a6beaa2e8c0012103d2296e51b33a43425c5c905afee8997a5fbfdaa8c10add4e56ea8bc5ceea2fcf";
        assertEq(
            keccak256(witnessVector.extractWitnessAtIndex(0)),
            0x42d6cb8ef768d22410c78498a0370193b833b87da6985435f6ba299fa84f9ab7
        );
        assertEq(
            keccak256(witnessVector.extractWitnessAtIndex(1)),
            0xf43ff1046b987727b344b2646dc121f22e6b5b6e71b5c528c377cbbb093ce687
        );
    }

    function test_ExtractTapscript() public {
        bytes memory witnessVector =
            hex"03406c00eb3c4d35fedd257051333b4ca81d1a25a37a9af4891f1fec2869edd56b14180eafbda8851d63138a724c9b15384bc5f0536de658bd294d426a36212e6f08a5209e2849b90a2353691fccedd467215c88eec89a5d0dcf468e6cf37abed344d746ac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d38004c5e7b200a20202270223a20226272632d3230222c0a2020226f70223a20226465706c6f79222c0a2020227469636b223a20226f726469222c0a2020226d6178223a20223231303030303030222c0a2020226c696d223a202231303030220a7d6821c19e2849b90a2353691fccedd467215c88eec89a5d0dcf468e6cf37abed344d746";

        assertEq(
            keccak256(witnessVector.extractWitnessAtIndex(0).extractTapscript()),
            0xf4573d2a3472df97b6a2d9ecb0dab17eef1bebb903ecad628de8e96b0cc7ab30
        );
    }
}
