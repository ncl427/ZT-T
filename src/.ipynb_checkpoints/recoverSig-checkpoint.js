module.exports = {recoverPubKey};  // entry for node

const EthCrypto = require('eth-crypto');

function recoverPubKey(signature, message) {
    const signer = EthCrypto.recoverPublicKey(
        signature, // signature
        EthCrypto.hash.keccak256(message) // message hash
    );
    console.log(signer);
    return signer;
}