module.exports = {encrypt};  // entry for node

const EthCrypto = require('eth-crypto');


async function encrypt(message, pupKey) {
    const encrypted = await EthCrypto.encryptWithPublicKey(
        pupKey, // publicKey
        message // message
    );

    //console.log(encrypted);

    const str = EthCrypto.cipher.stringify(encrypted);
    console.log(str);
    return str;
}
