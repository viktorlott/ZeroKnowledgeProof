# Interactive Zero Knowledge Proof

## Lets user prove that they have a certain amount of crypto coins without revealing their wallet address


<br/>

This project is meant for learning purposes only. I though this was super cool, so i decided to try making it. 
There is some stuff i still want to add, for example, a changes for the Prover to provide a secret that the verifier then 
uses with their secret. This will help the Prover stay more annonymous because the Verifier can't pre-generate Proofs that they
then can use to identify the Prover.
<br/>
If there is a weakness with my implementation, please make an issue.


```typescript
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