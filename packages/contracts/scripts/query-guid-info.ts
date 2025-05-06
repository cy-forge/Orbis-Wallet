import "dotenv/config";
import { hash, num, uint256 } from "starknet";
import { manager } from "../lib";

const lastBlock = await manager.getBlock("latest");
const guidToFind = "0x078e6eccfb97cea1b4ca2e0735d0db7cd9e33a316378391e58e7f3ed107062c2";
const keyFilter = [num.toHex(hash.starknetKeccak("SignerLinked")), guidToFind];

// Just gotta find any event matching this.
// It should be (almost) impossible for 2 guids to collide.
const MAX_STEP = 100_000;
const block_number = Math.max(lastBlock.block_number - MAX_STEP, 0);
const eventsList = await manager.getEvents({
  // address: myContractAddress, // If you have the address of the contract, you can fill it in
  from_block: { block_number },
  // to_block: { block_number: lastBlock.block_number }, // Defaults to latest
  keys: [keyFilter],
  chunk_size: 1000,
});
// If not found check from lastBlock - MAX_STEP to lastBlock - (2 * MAX_STEP) and so on.

const lastEvent = eventsList.events[eventsList.events.length - 1];
console.log(dataToSignature(lastEvent.data));

function dataToSignature(data: string[]) {
  const type = data[0];
  if (type == "0x0") {
    return { name: "StarknetSigner", pubkey: data[1] };
  } else if (type == "0x1") {
    return { name: "Secp256k1Signer", pubkey_hash: data[1] };
  } else if (type == "0x2") {
    const pubkey = uint256.uint256ToBN({
      low: data[1],
      high: data[2],
    });
    return { name: "Secp256r1Signer", pubkey };
  } else if (type == "0x3") {
    return { name: "Eip191Signer", eth_address: data[1] };
  } else if (type == "0x4") {
    const rp_id_hash = uint256.uint256ToBN({
      low: data[2],
      high: data[3],
    });
    return { name: "WebauthnSigner", origin: data[1], rp_id_hash, pubkey: data[4] };
  } else {
    throw new Error("Unrecognized signer type");
  }
}
