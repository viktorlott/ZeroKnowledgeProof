import { Wallet, Common, Amount, Trust } from "lib";
import wallets from "./wallets.json";
import { isEqual } from 'lodash'

const Wallets = wallets.map((wallet) => Wallet.serialize(wallet));

type Sample = {
  message: string;
  signature: string;
  key: string
}

class Prover extends Common {
  secretWallet: Wallet;

  constructor(secretWallet: Wallet, ledger: Wallet[]) {
    super(ledger);
    this.secretWallet = secretWallet;

    console.log("[Prover] balance:", this.secretWallet.balance, "\n")
  }

  revealAmount(): Amount {
    return {
      min: this.secretWallet.balance - 15,
      max: this.secretWallet.balance,
    };
  }
  
  solvingProof(
    samples: Sample[]
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

// For this proof, both parties must have a record of all the wallets. 
// Each wallet has a balance, a public key and an address.
// Both parties can specify the amount range that is getting proven, as long as they are the same.
// With this, both parties will use this infomation to gather all wallets matching the amount range specified.
// Lets say that both of them gathered 10 wallets matching the specification, Verifier can then use each wallets public key
// and encrypt a secret that only people with that amount in their wallets can decrypt. To make sure that the Verifier hasn't
// manipulated any of the encrypted secrets, a hash signature is produced with the secret, public key and the encrypted secret 
// so that the Prover can detect if any manipulation  has been performed to the data. 
// After Prover has verified the validity of the data--they will send back the secret to the Verifier. 
// If Verifiers initial secret matches Provers secret, 
// the Verifier can trust that the Prover has the amount they are claiming to have.

function test(fail?: boolean) {
  // Only the prover knowns their secretWallet.
  const proversSecretWallet = Wallets[Math.floor(Math.random() * Wallets.length)];
  
  // Prover will create a proof that the verifier can use to verify that the prover has a certain amount without revealing their wallet.
  const prover = new Prover(proversSecretWallet, Wallets);
  
  // Verifier will ask prover if they have a certain amount without the prover revealing their wallet address.
  const verifier = new Verifier(Wallets);
  
  // Prover declares the balance range they are ready to reveal. 
  // This could also be set by the verifier
  const amountToProve = prover.revealAmount();
  
  // // Verifier will generate a secret value that only people with the same balance can decode.
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
    console.log("[Proof]: failed")
  }
  console.log()
}

// We are proving that we can detect if verifier has manipulated our Proof
console.log("------FAIL------\n")
test(true)
console.log("----------------\n")

console.log()

// Here we show that the Prover can actually prove that they have a cetain wallet balance without the Verifier identifying the wallet.
console.log("-----SUCCEED----\n")
test(false)
console.log("----------------\n")

