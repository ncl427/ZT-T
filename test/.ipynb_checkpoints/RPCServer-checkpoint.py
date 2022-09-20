#!/usr/bin/env python
# coding: utf-8

# In[3]:


#!pip install flask


# In[1]:


from web3 import Web3, HTTPProvider, EthereumTesterProvider
from web3.middleware import geth_poa_middleware
from flask import request
from os.path import exists
from requests.auth import HTTPBasicAuth
from eth_account.messages import encode_defunct

import json
import requests

permissionedAddress = "0x56da4f2C76bbb7B56da0b287fC9d525872638145"
nftOTT = "0xDeF8050496E0A0b757cf1dFb4a34e55BA9663992"
abi = json.loads('[ { "inputs": [ { "internalType": "contract AccountIngress", "name": "_ingressContract", "type": "address" }, { "internalType": "contract AccountStorage", "name": "_storage", "type": "address" } ], "stateMutability": "nonpayable", "type": "constructor" }, { "anonymous": false, "inputs": [ { "indexed": false, "internalType": "bool", "name": "accountAdded", "type": "bool" }, { "indexed": false, "internalType": "address", "name": "accountAddress", "type": "address" } ], "name": "AccountAdded", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": false, "internalType": "bool", "name": "accountRemoved", "type": "bool" }, { "indexed": false, "internalType": "address", "name": "accountAddress", "type": "address" } ], "name": "AccountRemoved", "type": "event" }, { "inputs": [ { "internalType": "address", "name": "account", "type": "address" } ], "name": "addAccount", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address[]", "name": "accounts", "type": "address[]" } ], "name": "addAccounts", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [], "name": "enterReadOnly", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [], "name": "exitReadOnly", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "account", "type": "address" } ], "name": "removeAccount", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "_account", "type": "address" } ], "name": "accountPermitted", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "getAccounts", "outputs": [ { "internalType": "address[]", "name": "", "type": "address[]" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "index", "type": "uint256" } ], "name": "getByIndex", "outputs": [ { "internalType": "address", "name": "account", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "getContractVersion", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "getSize", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "isReadOnly", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "sender", "type": "address" }, { "internalType": "address", "name": "", "type": "address" }, { "internalType": "uint256", "name": "", "type": "uint256" }, { "internalType": "uint256", "name": "", "type": "uint256" }, { "internalType": "uint256", "name": "", "type": "uint256" }, { "internalType": "bytes", "name": "", "type": "bytes" } ], "name": "transactionAllowed", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }]')
abiNFT= json.loads('[ { "inputs": [], "stateMutability": "nonpayable", "type": "constructor" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "address", "name": "owner", "type": "address" }, { "indexed": true, "internalType": "address", "name": "approved", "type": "address" }, { "indexed": true, "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "Approval", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "address", "name": "owner", "type": "address" }, { "indexed": true, "internalType": "address", "name": "operator", "type": "address" }, { "indexed": false, "internalType": "bool", "name": "approved", "type": "bool" } ], "name": "ApprovalForAll", "type": "event" }, { "inputs": [ { "internalType": "address", "name": "to", "type": "address" }, { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "approve", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "burn", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "_to", "type": "address" }, { "internalType": "uint256", "name": "_tokenId", "type": "uint256" }, { "internalType": "string", "name": "tokenURI_", "type": "string" } ], "name": "mint", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "address", "name": "previousOwner", "type": "address" }, { "indexed": true, "internalType": "address", "name": "newOwner", "type": "address" } ], "name": "OwnershipTransferred", "type": "event" }, { "inputs": [], "name": "renounceOwnership", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "from", "type": "address" }, { "internalType": "address", "name": "to", "type": "address" }, { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "safeTransferFrom", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "from", "type": "address" }, { "internalType": "address", "name": "to", "type": "address" }, { "internalType": "uint256", "name": "tokenId", "type": "uint256" }, { "internalType": "bytes", "name": "_data", "type": "bytes" } ], "name": "safeTransferFrom", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "operator", "type": "address" }, { "internalType": "bool", "name": "approved", "type": "bool" } ], "name": "setApprovalForAll", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "string", "name": "baseURI_", "type": "string" } ], "name": "setBaseURI", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "address", "name": "from", "type": "address" }, { "indexed": true, "internalType": "address", "name": "to", "type": "address" }, { "indexed": true, "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "Transfer", "type": "event" }, { "inputs": [ { "internalType": "address", "name": "from", "type": "address" }, { "internalType": "address", "name": "to", "type": "address" }, { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "transferFrom", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "newOwner", "type": "address" } ], "name": "transferOwnership", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "owner", "type": "address" } ], "name": "balanceOf", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "getApproved", "outputs": [ { "internalType": "address", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "owner", "type": "address" }, { "internalType": "address", "name": "operator", "type": "address" } ], "name": "isApprovedForAll", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "name", "outputs": [ { "internalType": "string", "name": "", "type": "string" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "owner", "outputs": [ { "internalType": "address", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "ownerOf", "outputs": [ { "internalType": "address", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "bytes4", "name": "interfaceId", "type": "bytes4" } ], "name": "supportsInterface", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "symbol", "outputs": [ { "internalType": "string", "name": "", "type": "string" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "index", "type": "uint256" } ], "name": "tokenByIndex", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "owner", "type": "address" }, { "internalType": "uint256", "name": "index", "type": "uint256" } ], "name": "tokenOfOwnerByIndex", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "tokenURI", "outputs": [ { "internalType": "string", "name": "", "type": "string" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "totalSupply", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" } ]')
obj = {
    "username": "admin",
    "password": "admin"
}
authURL = "https://orchestrator.ncl.lab:1280/edge/management/v1/authenticate?method=password"


# In[2]:


def safePasswordInput( my_encKey, num_retries = 3 ):
    for attempt_no in range(num_retries):
        try:
            passw = str(input())
            dec_key = w3.eth.account.decrypt(my_encKey, passw)
            return dec_key
        except ValueError as error:
            if attempt_no < (num_retries - 1):
                print("Error: Invalid password")
            else:
                raise error


# In[3]:


def getBlockKey(file_exists):
    if not file_exists:
        my_account = w3.eth.account.create("ZeroTrustNetworkZT")
        print("Please provide a password for encryptyion of Blockchain Keys:")
        passw = str(input())
        my_encAcc= w3.eth.account.encrypt(my_account.privateKey, passw)
        print(my_encAcc)
        with open('encyptedKeyIBN.json', 'w') as json_file:
            json.dump(my_encAcc, json_file)
        return my_account
    else:
        with open('encyptedKeyIBN.json') as my_key:
            my_encKey = json.load(my_key)
        print(my_encKey)
        #print(type(my_encKey))
        print("Enter your password for decryption:")
        #passw = str(input())
        try:
            dec_key =safePasswordInput(my_encKey)  
            my_account = w3.eth.account.privateKeyToAccount(dec_key)
            return my_account
        except ValueError as error:
            print("Too many wrong passwords!!", error)
            raise error


# In[4]:


def createIdentityObj(address):
    identobj = {
        "appData": None,
        "defaultHostingCost": 0,
        "enrollment": {
            "ott": True
            },
        "isAdmin": False,
        "name": address,
        "roleAttributes": None,
        "serviceHostingCosts": {},
        "serviceHostingPrecedences": {},
        "tags": None,
        "type": "User"
    }
    return identobj


# In[5]:


def createOTT(objId, authResponse ):
    jsonResponse = json.loads(authResponse.text)

        
    createIdentity = requests.post(
    "https://orchestrator.ncl.lab:1280/edge/management/v1/identities",
    verify=False,
    headers={"zt-session": jsonResponse['data']['token']},
    json = objId

    )
    print(createIdentity)

    if createIdentity.status_code == 201:
        jsonIdentResponse = json.loads(createIdentity.text)
        print(jsonIdentResponse)
        identity = jsonIdentResponse['data']['id']
    else:
        raise Exception(createIdentity.text)

    
    identityInfo = requests.get(
    f"https://orchestrator.ncl.lab:1280/edge/management/v1/identities/{identity}",
    verify=False,
    headers={"zt-session": jsonResponse['data']['token']}
        )
    identityResponse = json.loads(identityInfo.text)
    ott = identityResponse['data']['enrollment']['ott']['jwt']
    return ott


# In[6]:


def mintOTTNFT(ott, address):
    totalSupply = nftOTT_instance.functions.totalSupply().call() #Get the status of the account
    check_sum = w3.toChecksumAddress(my_account._address)
    print("Totalsupply", totalSupply, address, ott)
    tokenId = totalSupply+1
    print(tokenId)
    nftOTT_instance.functions.penis(address).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": w3.eth.get_transaction_count(check_sum),"chainId": 2022}) #build RAW transaction supported by BESU



    #tx = nftOTT_instance.functions.mint(address,tokenId,ott).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": w3.eth.get_transaction_count(check_sum),"chainId": 2022}) #build RAW transaction supported by BESU
    #tx = nftOTT_instance.functions.renounceOwnership().buildTransaction() #build RAW transaction supported by BESU
    #print(tx)
    #del tx['maxPriorityFeePerGas']
 
  


# In[7]:


def signsendTransaction(trx, my_account):
       signed_txn = w3.eth.account.sign_transaction(trx, my_account.privateKey) #Sign transaction using our own private key
       print(signed_txn.rawTransaction)
       txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU
       tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash.hex())
# In[8]:


def getOTT(address):
    authResponse = requests.post(authURL, json=obj, verify=False,)
    print(authResponse.text)
    identobj =createIdentityObj(address)
    ott = createOTT(identobj, authResponse)
    print(ott)
    return ott

    


# In[ ]:


from flask import Flask
app = Flask(__name__)
@app.route('/test/', methods=['GET', 'POST'])
def welcome():
    return "IBN Zero Trust!"

@app.route('/enroll/', methods=['POST'])
def enroll():
    message = encode_defunct(text="verified")  #placeholder for signature verification
    try:
        signedMessage = request.data
        print(signedMessage)
        # handle your JSON_sent here
        # Pass JSON_received to the frontend
        #signedMessageJSON = json.dump(signedMessage)
        address = w3.eth.account.recover_message(message, signature=signedMessage)
        print(address)
        check_sum = w3.toChecksumAddress(my_account._address)
        balance = w3.eth.get_balance(check_sum)
        print(balance)
        #print(w3.eth.get_transaction_count(check_sum))
        isPerm = contract_instance.functions.accountPermitted(address).call() #Get the status of the account
        if isPerm:
            try:
                ott = str(getOTT(address))
                print("TEEEEEEEEEEEEEEEEEEEEEST")
                mintOTTNFT(ott, address)
                return "The account " + address + " is enrolled, here is your OTT: " + ott
            except (RuntimeError, TypeError, NameError, ValueError, KeyError, Exception) as error:
                response = json.loads(str(error))
                return "ERROR: " + response["error"]["cause"]["reason"]
        else:
            tx = contract_instance.functions.addAccount(address).buildTransaction({'from': check_sum,
                                                                               "gasPrice": w3.eth.gas_price,
                                                                               'nonce': w3.eth.get_transaction_count(check_sum),
                                                                               "chainId": 2022}) #build RAW transaction supported by BESU
            #del tx['maxPriorityFeePerGas']
            print(tx)
            signsendTransaction(tx, my_account)
#            signed_txn = w3.eth.account.sign_transaction(tx, my_account.privateKey) #Sign transaction using our own private key
#            print(signed_txn.rawTransaction)
#            try:
#                txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU
#                tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash.hex())
#                return "enrolled!" + str(tx_receipt)
#            except (RuntimeError, TypeError, NameError, ValueError) as error:
#                if type(error) ==ValueError:
#                    return "Your must wait for transaction to finish"
#                else:
#                    return json.loads(str(error))
    except Exception as e:
        print("Bad JSON Format from the request " + str(e))
        return str(e)


if __name__ == '__main__':
    w3 = Web3(HTTPProvider('http://172.18.102.169:9545')) #If access to our Local lockchain
    w3.middleware_onion.inject(geth_poa_middleware, layer=0) #For compatibility with POA consensus chains
    contract_instance = w3.eth.contract(address = permissionedAddress, abi = abi) #Creates a contract instance for the permissions
    nftOTT_instance = w3.eth.contract(address = nftOTT, abi = abiNFT) #Creates a contract instance for the OTT-NFT
    print(dir(nftOTT_instance.functions.mint))
    print(dir(contract_instance.functions))
    
    
    accounts = contract_instance.functions.getAccounts().call() #Get the accounts that are permissioned


    file_exists = exists("encyptedKeyIBN.json")
    try:
        my_account = getBlockKey(file_exists)
        print(my_account.address)
        app.run(host='0.0.0.0', port=105)
    except:
        print("Cannot run the RPC server, verify your Ethereum Account")


# In[ ]:





# In[ ]:





# In[ ]:




