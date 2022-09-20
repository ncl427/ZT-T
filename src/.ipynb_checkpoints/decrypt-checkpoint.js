module.exports = {decrypt};  // entry for node

const EthCrypto = require('eth-crypto');


async function decrypt(message, privKey) {
    const encryptedObject = EthCrypto.cipher.parse(message);
    const decrypted = await EthCrypto.encryptWithPublicKey(
        privKey, // privateKey
        encryptedObject // message
    );

    console.log(decrypted);
    return decrypted;
}
