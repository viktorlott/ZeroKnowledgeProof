import fs from "fs";
import path from "path";
import minifaker from "minifaker";
import { Wallet } from 'lib'
import { pbkdf2Sync } from 'crypto'

const walletsPath = path.resolve(__dirname, "..", "wallets.json")

const Wallets = minifaker.array(
  200,
  () =>
    new Wallet(
      minifaker.bitcoinAddress(),
      minifaker.number({ min: 1, max: 100 }),
      pbkdf2Sync(minifaker.password({ minLength: 5, maxLength: 5 }), 'salt', 100, 128, 'sha512').toString("base64")
    )
);

fs.writeFileSync(walletsPath, Buffer.from(JSON.stringify(Wallets.map(wallet => wallet.deserialize()))))

export { Wallets }
