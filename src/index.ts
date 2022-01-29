import { Wallet, Common, Amount, Trust } from "lib";
import wallets from "./wallets.json";
import { isEqual } from 'lodash'
import { pbkdf2Sync } from "crypto";

const Wallets = wallets.map((wallet) => Wallet.serialize(wallet));

class Prover extends Common {
  secretWallet: Wallet;

  constructor(secretWallet: Wallet, ledger: Wallet[]) {
    super(ledger);
    this.secretWallet = secretWallet;
  }

  revealAmount(): Amount {
    return {
      min: this.secretWallet.balance - 15,
      max: this.secretWallet.balance,
    };
  }
  
  solvingProof(
    samples: {
      message: string;
      signature: string;
      key: string
    }[]
  ): string | undefined {

    const decryptedSamples = samples.map((block) => {
      const answer = this.secretWallet.trust.privateDecrypt(block.message)
      const hash = Trust.hash(`${block.key}.${block.message}.${answer}`, block.key)
      return {
        key: block.key,
        message: block.message,
        matching: hash === block.signature,
        signature: block.signature,
        answer,
      }
    });

    const secret = decryptedSamples.find(d => d.matching)?.answer

    if(!secret) return "No secret found"

    const amount = this.revealAmount();

    const psignatures = this.buildProofOfBalance(amount, secret).map(s => s.signature);

    const dsignatures = decryptedSamples.map(s => s.signature)

    const valid = isEqual(psignatures, dsignatures)

    if(!valid) return "Samples not valid"

    return secret as string;
  }
}

class Verifier extends Common {
  constructor(ledger: Wallet[]) {
    super(ledger);
  }

}
function test(fail?: boolean) {
  // Only the prover knowns their secretWallet.
  const proversSecretWallet = Wallets[3];
  
  // Prover will create a proof that the verifier can use to verify that the prover has a certain amount without revealing their wallet.
  const prover = new Prover(proversSecretWallet, Wallets);
  
  // Verifier will ask prover if they have a certain amount without the prover revealing their wallet address.
  const verifier = new Verifier(Wallets);
  
  // Prover declares the balance range they are ready to reveal. 
  // This could also be set by the verifier
  const amountToProve = prover.revealAmount();
  
  // // Verifier will generate a secret value that only people with the same balance can decode.
  // const secret = verifier.generateSecret();
  const secret = verifier.generateSecret("123abc")
  
  // Verifier builds a proof that will contain every wallet that has the same balance range
  // Note that the sample size should be large enough so Prover can't easily be identified.
  const samplesProof = verifier.buildProofOfBalance(amountToProve, secret, fail ? "Replaced secret" : "");
  
  // Prover will solve or answer verifier by providing the secret value
  // Note that Prover will also verify that every sample actually have a valid "question". 
  // That means that every message that gets encrypted should also gets hashed with their respective public key and secret value.
  // This will allow the prover to verify that the content has not been manipulated.
  const secretFromProver = prover.solvingProof(samplesProof);
  
  // We check if Prover returns the same secret as verifier generated
  const valid = secretFromProver === secret
  
  console.log("[Prover]:", secretFromProver, "\n");
  console.log("[Verifier]:", secret, "\n");
  console.log("[Valid]:", valid)
  console.log()
  
  if(valid) {
    console.log("[Prover] has atleast", amountToProve.max, "coins in their wallet.")
  } else {
    console.log("Proof failed")
  }
  console.log()
}


console.log("------FAIL------\n")
test(true)
console.log("----------------\n")
console.log()
console.log("-----SUCCEED----\n")
test(false)
console.log("----------------\n")

