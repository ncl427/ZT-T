module.exports = {vrs};  // entry for node

const EthCrypto = require('eth-crypto');


async function vrs(signature) {
    const vrs = EthCrypto.vrs.fromString(signature);

    console.log(vrs);
    return vrs;
}
