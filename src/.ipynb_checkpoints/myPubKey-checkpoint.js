  module.exports = {myPubKey};  // entry for node
  
  const EthCrypto = require('eth-crypto');
  
  function myPubKey(privKey) {
      
  
      const publicKey = EthCrypto.publicKeyByPrivateKey(privKey);
      console.log(publicKey);
      return publicKey;
      
  }