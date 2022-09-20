module.exports = {signMessage};  // entry for node
const EthCrypto = require('eth-crypto');


  function signMessage(message,privKey) {
    const messageHash = EthCrypto.hash.keccak256(message);
    const signature = EthCrypto.sign(
        privKey, // privateKey
        messageHash // hash of message
    );
    console.log(signature)
    return signature;
  }
