import "core-js/stable";
import "regenerator-runtime/runtime";
import { waitForAppScreen, zemu, genericTx } from '../test.fixture';
import { ethers } from "ethers";

// StakeDAO Palace
const NETWORK = "ethereum";
const contractAddr = "0x221738f73fa4bfca91918e77d112b87d918c751f";
const xSDT_TO_DEPOSIT = '100259000000000000000'; // 100.259
const BASE_SCREENS_S = (1 + 1 + 1 + 1 + 3 + 1 + 1); // STAKEDAO + STRATEGY + WANT + AMOUNT +  STRATEGY ADDRESS (3) + GAS_FEES + ACCEPT
const BASE_SCREENS_X = (1 + 1 + 1 + 1 + 1 + 1 + 1); // STAKEDAO + STRATEGY + WANT + AMOUNT +  STRATEGY ADDRESS (3) + GAS_FEES + ACCEPT

test('[Nano S] Stake xSDT into the Palace', zemu("nanos", async (sim, eth) => {
  const contract = new ethers.Contract(contractAddr, ['function stake(uint256)']);
  const {data} = await contract.populateTransaction.stake(xSDT_TO_DEPOSIT);
  let unsignedTx = genericTx;
  unsignedTx.to = contractAddr;
  unsignedTx.data = data;

  const serializedTx = ethers.utils.serializeTransaction(unsignedTx).slice(2);
  const tx = eth.signTransaction("44'/60'/0'/0", serializedTx);

  await waitForAppScreen(sim);
  await sim.navigateAndCompareSnapshots('.', 'nanos_palace_stake', [BASE_SCREENS_S, 0]);
  await tx;
}, NETWORK));

test('[Nano X] Stake xSDT into the Palace', zemu("nanox", async (sim, eth) => {
  const contract = new ethers.Contract(contractAddr, ['function stake(uint256)']);
  const {data} = await contract.populateTransaction.stake(xSDT_TO_DEPOSIT);
  let unsignedTx = genericTx;
  unsignedTx.to = contractAddr;
  unsignedTx.data = data;

  const serializedTx = ethers.utils.serializeTransaction(unsignedTx).slice(2);
  const tx = eth.signTransaction("44'/60'/0'/0", serializedTx);

  await waitForAppScreen(sim);
  await sim.navigateAndCompareSnapshots('.', 'nanox_palace_stake', [BASE_SCREENS_X, 0]);
  await tx;
}, NETWORK));
