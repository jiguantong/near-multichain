import { Web3 } from "web3"
import { keccak256, toUtf8Bytes, ethers, concat, AbiCoder, recoverAddress, hexlify, toBeHex } from "ethers"
import { bytesToHex } from '@ethereumjs/util';
import { FeeMarketEIP1559Transaction } from '@ethereumjs/tx';
import { deriveChildPublicKey, najPublicKeyStrToUncompressedHexPoint, uncompressedHexPointToEvmAddress } from '../services/kdf';
import { Common } from '@ethereumjs/common'
import { Contract, JsonRpcProvider } from "ethers";
import { parseNearAmount } from "near-api-js/lib/utils/format";

export class Ethereum {
  constructor(chain_rpc, chain_id) {
    this.web3 = new Web3(chain_rpc);
    this.provider = new JsonRpcProvider(chain_rpc);
    this.chain_id = chain_id;
    this.queryGasPrice();
  }

  async deriveAddress(accountId, derivation_path) {
    const publicKey = await deriveChildPublicKey(najPublicKeyStrToUncompressedHexPoint(), accountId, derivation_path);
    const address = await uncompressedHexPointToEvmAddress(publicKey);
    return { publicKey: Buffer.from(publicKey, 'hex'), address };
  }

  async queryGasPrice() {
    const maxFeePerGas = await this.web3.eth.getGasPrice();
    const maxPriorityFeePerGas = await this.web3.eth.getMaxPriorityFeePerGas();
    return { maxFeePerGas, maxPriorityFeePerGas };
  }

  async getBalance(accountId) {
    const balance = await this.web3.eth.getBalance(accountId);
    return this.web3.utils.fromWei(balance, "ether");
  }

  async getContractViewFunction(receiver, abi, methodName, args = []) {
    const contract = new Contract(receiver, abi, this.provider);

    return await contract[methodName](...args);
  }

  createTransactionData(receiver, abi, methodName, args = []) {
    const contract = new Contract(receiver, abi);

    return contract.interface.encodeFunctionData(methodName, args);
  }

  async createPayload(sender, receiver, amount, data) {
    const common = new Common({ chain: this.chain_id });

    // Get the nonce & gas price
    const nonce = await this.web3.eth.getTransactionCount(sender);
    const { maxFeePerGas, maxPriorityFeePerGas } = await this.queryGasPrice();

    // Construct transaction
    const transactionData = {
      nonce,
      gasLimit: 50_000,
      maxFeePerGas,
      maxPriorityFeePerGas,
      to: receiver,
      data: data,
      value: BigInt(this.web3.utils.toWei(amount, "ether")),
      chain: this.chain_id,
    };

    // Create a transaction
    const transaction = FeeMarketEIP1559Transaction.fromTxData(transactionData, { common });
    const payload = transaction.getHashedMessageToSign();

    // Store in sessionStorage for later
    sessionStorage.setItem('transaction', transaction.serialize());

    return { transaction, payload };
  }

  createEip712Payload(domain, types, message) {
    const domainSeparator = this.getDomainSeparator(domain);
    console.log("> ### Domain Separator:", domainSeparator);
    const structHash = this.getStructHash(message);
    console.log("> ### structHash:", structHash);
    console.log("> ### aggregator: :", hexlify(toUtf8Bytes(message.aggregator)));
    const digest = keccak256(
      concat(["0x1901", domainSeparator, structHash])
    );
    console.log("> ### Digest:", digest);
    const toSignMessage = ethers.getBytes(digest);
    console.log("> ### To sign message:", toSignMessage);
    return { digest, toSignMessage };
  }

  getStructHash(data) {
    // { name: "aggregator", type: "string" },
    // { name: "reportersFee", type: "uint256" },
    // { name: "publishFee", type: "uint256" },
    // { name: "rewardAddress", type: "address" },
    // { name: "version", type: "uint256" },
    const typeHash = keccak256(
      toUtf8Bytes(
        "AggregatorConfig(string aggregator,address rewardAddress,uint256 reportersFee,uint256 publishFee,uint256 version)"
      )
    );

    console.log("> ### struct type Hash", typeHash);

    const structHash = new AbiCoder().encode(
      ["bytes32", "bytes32", "address", "uint256", "uint256", "uint256"],
      [
        typeHash,
        keccak256(toUtf8Bytes(data.aggregator)),
        data.rewardAddress,
        data.reportersFee,
        data.publishFee,
        data.version
      ]
    );

    return keccak256(structHash);
  }

  getDomainSeparator(domain) {
    const typeHash = keccak256(
      toUtf8Bytes(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
      )
    );
    console.log("### getDomainSeparator typeHash", typeHash);

    const domainHash = new AbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [
        typeHash,
        keccak256(toUtf8Bytes(domain.name)),
        keccak256(toUtf8Bytes(domain.version)),
        domain.chainId,
        domain.verifyingContract
      ]
    );

    console.log("### getDomainSeparator domainHash", domainHash);

    return keccak256(domainHash);
  }

  verifySignature(digest, r, s, v) {
    const recoveredAddress = recoverAddress(digest, { r, s, v });
    console.log("### signature: ", concat([r, s, toBeHex(v, 1)]));
    console.log("### Recovered Address", recoveredAddress);
    return recoveredAddress;
  }

  async requestSignatureToMPC(wallet, contractId, path, ethPayload) {
    // Ask the MPC to sign the payload
    sessionStorage.setItem('derivation', path);

    const payload = Array.from(ethPayload);
    const { big_r, s, recovery_id } = await wallet.callMethod({ contractId, method: 'sign', args: { request: { payload, path, key_version: 0 } }, gas: '250000000000000', deposit: parseNearAmount('0.25') });
    return { big_r, s, recovery_id };
  }

  async reconstructSignature(big_r, S, recovery_id, transaction) {
    // reconstruct the signature
    const r = Buffer.from(big_r.affine_point.substring(2), 'hex');
    const s = Buffer.from(S.scalar, 'hex');
    const v = recovery_id;

    const signature = transaction.addSignature(v, r, s);

    if (signature.getValidationErrors().length > 0) throw new Error("Transaction validation errors");
    if (!signature.verifySignature()) throw new Error("Signature is not valid");
    return signature;
  }

  async reconstructSignatureFromLocalSession(big_r, s, recovery_id, sender) {
    const serialized = Uint8Array.from(JSON.parse(`[${sessionStorage.getItem('transaction')}]`));
    const transaction = FeeMarketEIP1559Transaction.fromSerializedTx(serialized);
    console.log("transaction", transaction)
    return this.reconstructSignature(big_r, s, recovery_id, transaction, sender);
  }

  // This code can be used to actually relay the transaction to the Ethereum network
  async relayTransaction(signedTransaction) {
    const serializedTx = bytesToHex(signedTransaction.serialize());
    const relayed = await this.web3.eth.sendSignedTransaction(serializedTx);
    return relayed.transactionHash
  }
}