# Zero Knowledge Proof

## Let user prove that they have a certain amount of crypto coins without revealing the wallet address


#### Will add a indepth guide later.

```typescript
// Only the prover knowns their secret wallet.
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
```