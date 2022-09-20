module.exports = {decrypt};  // entry for node

const EthCrypto = require('eth-crypto');


async function decrypt(message, privKey) {
    const encryptedObject = EthCrypto.cipher.parse(message);
    //console.log(encryptedObject)
    const decrypted = await EthCrypto.decryptWithPrivateKey(
        privKey, // privateKey
        encryptedObject // message
    );

    console.log(decrypted);
    return decrypted;
}
