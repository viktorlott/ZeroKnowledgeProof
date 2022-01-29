import {
  generateKeyPairSync,
  privateDecrypt,
  publicEncrypt,
  verify,
  sign,
  RSAKeyPairOptions,
  KeyPairSyncResult,
  constants,
  createHmac
} from "crypto";

function generateKeyPairSettings(
  passphrase: string
): RSAKeyPairOptions<"pem", "pem"> {
  return {
    modulusLength: 1024,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase: passphrase,

    },
  };
}

function generateKeyPair(
  passphrase: string
): KeyPairSyncResult<string, string> {
  return generateKeyPairSync("rsa", generateKeyPairSettings(passphrase));
}

const SHA256 = "SHA256";
// We are using RSA with no padding, this i considered insecure.
// But we need this to ensure that every time we encrypt X, we will get Y back.
// RSA with padding will make every encryption output different with the same data. X -> Y, X -> P etc etc.
const PADDING = constants.RSA_NO_PADDING

class Trust {
  private passphrase: string;
  private privateKey: string;
  public publicKey: string;

  constructor(passphrase: string) {
    const { privateKey, publicKey } = generateKeyPair(passphrase);
    this.passphrase = passphrase;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  static generateKeyPair(passphrase: string) {
    return generateKeyPair(passphrase);
  }

  static from(trust: {
    passphrase: string;
    privateKey: string;
    publicKey: string;
  }): Trust {
    const t = Object.create(this.prototype) as Trust;
    return Object.assign(t, trust);
  }

  static sign(data: string, publicKey: string) {
    return sign(SHA256, Buffer.from(data), publicKey).toString("base64");
  }

  static hash(data: string, key: string) {
    return createHmac('sha256', key).update(data).digest('hex');
  }

  verify(data: string, signature: string) {
    return verify(
      SHA256,
      Buffer.from(data, "base64"),
      this.publicKey,
      Buffer.from(signature, "base64")
    )
  }

  sign(data: string) {
    return sign(SHA256, Buffer.from(data), { key: this.privateKey, passphrase: this.passphrase }).toString("base64");
  }

  hash(data: string, key?: string) {
    return createHmac('sha256', key || this.publicKey).update(data).digest('hex');
  }

  publicEncrypt(message: string, publicKey?: string) {
    const data = Buffer.from(message, "base64")
    // Note that we are using no padding here.
    return publicEncrypt({
       key: publicKey || this.publicKey,
       padding: PADDING
    }, 
    data).toString(
      "base64"
    );
  }

  privateDecrypt(encrypted: string, privateKey?: string) {
    try {
      // Note that we are using no padding here.
      return privateDecrypt(
        {
          key: privateKey || this.privateKey.toString(),
          passphrase: this.passphrase,
          padding: PADDING
        },
        Buffer.from(encrypted, "base64")
      ).toString("base64");
    } catch (err) {
      return "";
    }
  }

  getAll() {
    return {
      privateKey: this.privateKey,
      publicKey: this.publicKey,
      passphrase: this.passphrase,
    };
  }
}

export { Trust };
