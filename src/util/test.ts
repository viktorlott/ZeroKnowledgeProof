import {
  generateKeyPairSync,
  privateDecrypt,
  publicEncrypt,
  verify,
  sign,
  RSAKeyPairOptions,
  KeyPairSyncResult,
  constants,
  createHmac,
  randomBytes,
  pbkdf2Sync
  //   RsaPrivateKey,
  //   publicDecrypt,
  //   privateEncrypt,
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


const passphrase = pbkdf2Sync("test", 'salt', 100, 128, 'sha512').toString("base64")
const passphrase2 = pbkdf2Sync("tset", 'salt', 100, 128, 'sha512').toString("base64")
const message = pbkdf2Sync(passphrase, 'salt', 100, 128, 'sha512').toString("base64");
const SHA256 = "SHA256";

console.log(message)
const { privateKey, publicKey } = generateKeyPair(passphrase);

function testing() {
  const encrypted = publicEncrypt(
    {
      key: publicKey,
      padding: constants.RSA_NO_PADDING
    },
    Buffer.from(message, "base64")
  ).toString("base64");

  console.log(encrypted, "hello", "\n")

  const decrypted = privateDecrypt(
    {
      key: privateKey.toString(),
      passphrase: passphrase,
      padding: constants.RSA_NO_PADDING,
    },
    Buffer.from(encrypted, "base64")
  ).toString("utf8");
}


testing()
testing()
testing()
testing()