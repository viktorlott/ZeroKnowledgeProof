import { Trust } from "./Trust";

class Wallet {
  trust!: Trust;
  address: string;
  balance: number;

  constructor(name: string, balance: number, secret: string) {
    this.trust = new Trust(secret);
    this.address = name;
    this.balance = balance;
    console.log("Wallet:", this.address, "-", "created");
  }

  deserialize() {
    return {
      trust: this.trust.getAll(),
      address: this.address,
      balance: this.balance,
    };
  }

  static serialize(wallet: {
    trust: { passphrase: string; privateKey: string; publicKey: string };
    address: string;
    balance: number;
  }) {
    const w = Object.create(this.prototype) as Wallet;
    return Object.assign(w, {
      address: wallet.address,
      balance: wallet.balance,
      trust: Trust.from(wallet.trust),
    });
  }
}

export { Wallet };
