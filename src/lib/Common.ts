import { Wallet } from "./Wallet";
import { Trust } from "./Trust";
import { pbkdf2Sync, generateKeyPairSync } from "crypto";

type Amount = {
  min: number;
  max: number;
};

const proofLog = (
  amount: { min: number; max: number },
  secret: string,
  length: number
) =>
  console.log("Wallets with", amount, "coins - found", length, "\n");

class Common {
  wallets: Wallet[];

  constructor(wallets: Wallet[]) {
    this.wallets = wallets;
  }

  generateSecret(secret: string) {
    // Took me time to figure this out..
    const klength = 128
    // RSA always use padding for en/de-cryption, that means that we always get unique encryptions with same input.
    // To bypass this we need to generate a secret with the exact key size
    // This is called Textbook RSA and i considered a weakness, though there are ways of securing it
    const passphrase = pbkdf2Sync(secret, 'salt', 100, klength, 'sha512').toString("base64");

    return passphrase
  }

  // It's good to maybe set a min samples length so that prover can't get easily verified.
  getAllWalletsWithBalance(amount: Amount, minSamples: number) {
    const wallets = this.wallets.filter(
      (wallet) => wallet.balance >= amount.min && wallet.balance <= amount.max
    );

    return wallets;
  }

  buildProofOfBalance(amount: Amount, secret: string, fake?: string) {
    const matchingWallets = this.getAllWalletsWithBalance(amount, 3);

    proofLog(amount, secret, matchingWallets.length);

    return matchingWallets.map((wallet, i) => {
      let s = secret

      if(fake && i === 5) {
        s = this.generateSecret("123")
        console.log(fake,"-",s)
      }


      const message = wallet.trust.publicEncrypt(s, wallet.trust.publicKey)
      const signature = wallet.trust.hash(`${wallet.trust.publicKey}.${message}.${secret}`)

      return {
        key: wallet.trust.publicKey,
        message,
        signature
      }
  });;
  }
}

export { Common, Amount };
