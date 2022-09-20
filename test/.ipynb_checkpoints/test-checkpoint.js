Web3 = require('web3')

const web3 = new Web3()

var account = web3.eth.accounts.create()

var json = web3.eth.accounts.encrypt(account.privateKey, 'ziticlient')

