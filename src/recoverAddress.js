module.exports = {recoverAddress};  // entry for node

const EthCrypto = require('eth-crypto');

function recoverAddress(signature, message) {
    const signer = EthCrypto.recover(
        signature, // signature
        EthCrypto.hash.keccak256(message) // message hash
    );
    console.log(signer);
    return signer;
}