# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %%
#!pip install flask
#!pip install random-password-generator


# %%
from web3 import Web3, HTTPProvider, EthereumTesterProvider
from web3.middleware import geth_poa_middleware
from flask import request
from os.path import exists
from requests.auth import HTTPBasicAuth
from eth_account.messages import encode_defunct
from flask import Flask
from config.definitions import ROOT_DIR_LINUX
from email.message import EmailMessage
from password_generator import PasswordGenerator



import os
import json
import requests
import smtplib
import ssl
import subprocess
import re

### FOR OUR BESU CHAIN ####
##Uncomment if neeeded###

permissionedAddress = "0xc6AE6461B8b3c2C98e10E21fA8aD0ea15aF6F582"
nftOTT = "0xAf47c9D246fEF48C6AAc885353A86Cf06B8Ec4E5"
employeeRepo= "0x862052D18e7B8f5261E2601b94bE2197f58A86Ae"
###
web3Prov = "http://172.18.102.169:9545"
authURL = "https://orchestrator.ncl.lab:1280/edge/management/v1/authenticate?method=password"
apiURL = "https://orchestrator.ncl.lab:1280/edge/management/v1/"
chainId = 2022

### FOR MY LOCAL TEST ###
### Uncomment if needed###
#web3Prov = "http://172.23.192.1:8545"
#authURL = "https://localhost:1280/edge/management/v1/authenticate?method=password"
#apiURL = "https://localhost:1280/edge/management/v1/"
#chainId = 1337
###
#permissionedAddress = "0x9B4844756255c8898862B3b2A2E9e056d8269eAd"
#nftOTT = "0x6d700596EA273E209Daefe5AAD491Dc1e125155C"
#employeeRepo= "0xb233ba6eA44a27Fa9948a93BB6FAc4b48AB6d173"
###

unlockEmail = ""
abiFolder = os.path.join(ROOT_DIR_LINUX, 'ABI')
keyFolder = os.path.join(ROOT_DIR_LINUX, 'Keys')
srcFolder = os.path.join(ROOT_DIR_LINUX, 'src')
##idFolder =  os.path.join(ROOT_DIR_LINUX, 'identity') ##Could be used later for API authentication

pwo = PasswordGenerator()
#print(os.chdir('ABI'))

with open(abiFolder+"/"+"accountRules.json") as file:
    abi = json.load(file)

with open(abiFolder+"/"+"ottNFT.json") as file:
    abiNFT = json.load(file)
    
with open(abiFolder+"/"+"repoList.json") as file:
    abiEmpRep = json.load(file)
            
#abi = json.loads('[ { "inputs": [ { "internalType": "contract AccountIngress", "name": "_ingressContract", "type": "address" }, { "internalType": "contract AccountStorage", "name": "_storage", "type": "address" } ], "stateMutability": "nonpayable", "type": "constructor" }, { "anonymous": false, "inputs": [ { "indexed": false, "internalType": "bool", "name": "accountAdded", "type": "bool" }, { "indexed": false, "internalType": "address", "name": "accountAddress", "type": "address" } ], "name": "AccountAdded", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": false, "internalType": "bool", "name": "accountRemoved", "type": "bool" }, { "indexed": false, "internalType": "address", "name": "accountAddress", "type": "address" } ], "name": "AccountRemoved", "type": "event" }, { "inputs": [ { "internalType": "address", "name": "account", "type": "address" } ], "name": "addAccount", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address[]", "name": "accounts", "type": "address[]" } ], "name": "addAccounts", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [], "name": "enterReadOnly", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [], "name": "exitReadOnly", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "account", "type": "address" } ], "name": "removeAccount", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "_account", "type": "address" } ], "name": "accountPermitted", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "getAccounts", "outputs": [ { "internalType": "address[]", "name": "", "type": "address[]" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "index", "type": "uint256" } ], "name": "getByIndex", "outputs": [ { "internalType": "address", "name": "account", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "getContractVersion", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "getSize", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "isReadOnly", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "sender", "type": "address" }, { "internalType": "address", "name": "", "type": "address" }, { "internalType": "uint256", "name": "", "type": "uint256" }, { "internalType": "uint256", "name": "", "type": "uint256" }, { "internalType": "uint256", "name": "", "type": "uint256" }, { "internalType": "bytes", "name": "", "type": "bytes" } ], "name": "transactionAllowed", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }]')
#abiNFT= json.loads('[ { "inputs": [], "stateMutability": "nonpayable", "type": "constructor" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "address", "name": "owner", "type": "address" }, { "indexed": true, "internalType": "address", "name": "approved", "type": "address" }, { "indexed": true, "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "Approval", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "address", "name": "owner", "type": "address" }, { "indexed": true, "internalType": "address", "name": "operator", "type": "address" }, { "indexed": false, "internalType": "bool", "name": "approved", "type": "bool" } ], "name": "ApprovalForAll", "type": "event" }, { "inputs": [ { "internalType": "address", "name": "to", "type": "address" }, { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "approve", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "burn", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "_to", "type": "address" }, { "internalType": "uint256", "name": "_tokenId", "type": "uint256" }, { "internalType": "string", "name": "tokenURI_", "type": "string" } ], "name": "mint", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "address", "name": "previousOwner", "type": "address" }, { "indexed": true, "internalType": "address", "name": "newOwner", "type": "address" } ], "name": "OwnershipTransferred", "type": "event" }, { "inputs": [], "name": "renounceOwnership", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "from", "type": "address" }, { "internalType": "address", "name": "to", "type": "address" }, { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "safeTransferFrom", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "from", "type": "address" }, { "internalType": "address", "name": "to", "type": "address" }, { "internalType": "uint256", "name": "tokenId", "type": "uint256" }, { "internalType": "bytes", "name": "_data", "type": "bytes" } ], "name": "safeTransferFrom", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "operator", "type": "address" }, { "internalType": "bool", "name": "approved", "type": "bool" } ], "name": "setApprovalForAll", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "string", "name": "baseURI_", "type": "string" } ], "name": "setBaseURI", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "anonymous": false, "inputs": [ { "indexed": true, "internalType": "address", "name": "from", "type": "address" }, { "indexed": true, "internalType": "address", "name": "to", "type": "address" }, { "indexed": true, "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "Transfer", "type": "event" }, { "inputs": [ { "internalType": "address", "name": "from", "type": "address" }, { "internalType": "address", "name": "to", "type": "address" }, { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "transferFrom", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "newOwner", "type": "address" } ], "name": "transferOwnership", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "owner", "type": "address" } ], "name": "balanceOf", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "getApproved", "outputs": [ { "internalType": "address", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "owner", "type": "address" }, { "internalType": "address", "name": "operator", "type": "address" } ], "name": "isApprovedForAll", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "name", "outputs": [ { "internalType": "string", "name": "", "type": "string" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "owner", "outputs": [ { "internalType": "address", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "ownerOf", "outputs": [ { "internalType": "address", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "bytes4", "name": "interfaceId", "type": "bytes4" } ], "name": "supportsInterface", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "symbol", "outputs": [ { "internalType": "string", "name": "", "type": "string" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "index", "type": "uint256" } ], "name": "tokenByIndex", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "address", "name": "owner", "type": "address" }, { "internalType": "uint256", "name": "index", "type": "uint256" } ], "name": "tokenOfOwnerByIndex", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "tokenId", "type": "uint256" } ], "name": "tokenURI", "outputs": [ { "internalType": "string", "name": "", "type": "string" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "totalSupply", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" } ]')
obj = {
    "username": "admin",
    "password": "admin"
}



# %%
def safePasswordInput( my_encKey, num_retries = 3 ):
    for attempt_no in range(num_retries):
        try:
            passw = str(input())
            unlockEmail = passw
            dec_key = w3.eth.account.decrypt(my_encKey, passw)
            return dec_key
        except ValueError as error:
            if attempt_no < (num_retries - 1):
                print("Error: Invalid password")
            else:
                raise error


# %%
def getBlockKey(file_exists):
    if not file_exists:
        my_account = w3.eth.account.create("ZeroTrustNetworkZT")
        print("Please provide a password for encryptyion of Blockchain Keys:")
        passw = str(input())
        my_encAcc= w3.eth.account.encrypt(my_account.privateKey, passw)
        #print(my_encAcc)
        with open(keyFolder+"/"+"encyptedKeyIBN.json", 'w') as json_file:
            json.dump(my_encAcc, json_file)
        return my_account
    else:
        with open(keyFolder+"/"+"encyptedKeyIBN.json") as my_key:
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


# %%
def createIdentityObj(address, endpointType):
    identobj = {
        "appData": None,
        "defaultHostingCost": 0,
        "enrollment": {
            "ott": True
            },
        "isAdmin": False,
        "name": address,
        "blockId": address,
        "roleAttributes": None,
        "serviceHostingCosts": {},
        "serviceHostingPrecedences": {},
        "tags": None,
        "type": endpointType
    }
    return identobj


# %%
def createOTT(objId, authResponse ):
    jsonResponse = json.loads(authResponse.text)

        
    createIdentity = requests.post(
    f"{apiURL}identities",
    verify=False,
    headers={"zt-session": jsonResponse['data']['token']},
    json = objId

    )
    #print(createIdentity)

    if createIdentity.status_code == 201:
        jsonIdentResponse = json.loads(createIdentity.text)
        print(jsonIdentResponse)
        identity = jsonIdentResponse['data']['id']
    else:
        raise Exception(createIdentity.text)

    
    identityInfo = requests.get(
    f"{apiURL}identities/{identity}",
    verify=False,
    headers={"zt-session": jsonResponse['data']['token']}
        )
    identityResponse = json.loads(identityInfo.text)
    ott = identityResponse['data']['enrollment']['ott']['jwt']
    return ott


# %%



# %%
def signsendTransaction(trx, my_account):
       signed_txn = w3.eth.account.sign_transaction(trx, my_account.privateKey) #Sign transaction using our own private key
       #print(signed_txn.rawTransaction)
       try:
           txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU
           tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash.hex())
           return "Transaction Succesful" + str(tx_receipt)
       except (RuntimeError, TypeError, NameError, ValueError) as error:
           if type(error) ==ValueError:
               return "Your must wait for transaction to finish"
           else:
               return json.loads(str(error))


# %%
def getOTT(address, endpointType):
    authResponse = requests.post(authURL, json=obj, verify=False,)
    #print(authResponse.text)
    identobj =createIdentityObj(address, endpointType)
    ott = createOTT(identobj, authResponse)
    #print(ott)
    return ott

    


# %%
def emailMFA(email, secret):

    # mypass =  w3.eth.account.decrypt(myencPass, passw) #Decrypts the email password, to not reveal it.
    msg = EmailMessage() 
    sender = "nclztibn@gmail.com"
    passWd = "cytbdpweoplpsogk" #not secure, change later
    msg['From'] = sender    # Your e-mail address
    msg['To'] = email
    msg['Subject'] = "MFA from ZT&T"
    msg.set_content(secret)
    
    
    with smtplib.SMTP_SSL("smtp.gmail.com", port=465, context=ctx) as server:
        server.login(sender, passWd)
        server.send_message(msg)
        server.quit()


       
        
    


# %%
def encryptMessage(message, publicKey):
    cmd = """node -e 'require(\"./encrypt.js\").encrypt(\"{}\",\"{}\")'"""
    #cmd = 'node -e \"require(\'./encrypt.js\').encrypt(\'{}\',\'{}\')\"' #If fail, check quotes
    #pattern = r'\\n(.*)\\n'
    pattern = r'b\'(.*)\\n'
    
 
    #privKey = w3.toHex(privKey)
    output = subprocess.check_output(cmd.format(message, publicKey), shell=True)
    print(output)

    
    
    #signed_message = w3.eth.sign(privKey,text=message)
    print(cmd.format(message,publicKey))
    print(str(output))

    substring = re.search(pattern, str(output)).group(1)
    print(substring)
    return substring
    


# %%
def signMessage(message, privKey):
    singlequote ="'"
    doublequote = '"'
    cmd = """node -e 'require(\"./signMe.js\").signMessage(\"{}\",\"{}\")'"""
    #cmd = 'node -e \"require(\'./signMe.js\').signMessage(\'{}\',\'{}\')\"' #If fail, check quotes
    #pattern = r'\\n(.*)\\n'
    pattern = r'b\'(.*)\\n'
 
    privKey = w3.toHex(privKey)
    output = subprocess.check_output(cmd.format(message, privKey), shell=True)
    
    
    #signed_message = w3.eth.sign(privKey,text=message)
    print(cmd.format(message,privKey))
    print(str(output))
    substring = re.search(pattern, str(output)).group(1)
    print(substring)
    return substring


# %%
def getPubKeyfromSig(signedmessage, message):
    cmd = """node -e 'require(\"./recoverSig.js\").recoverPubKey(\"{}\",\"{}\")'"""
    #cmd = 'node -e \"require(\'./recoverSig.js\').recoverPubKey(\'{}\',\'{}\')\"' #If fail, check quotes 
    #pattern = r'\\n(.*)\\n'
    pattern = r'b\'(.*)\\n'

    output = subprocess.check_output(cmd.format(signedmessage, message), shell=True)
    print(cmd.format(signedmessage,message))
    print(output)
    substring = re.search(pattern, str(output)).group(1)
    print(substring)
    return substring


# %%
def decryptMessage(message, privKey):
    cmd = """node -e 'require(\"./decrypt.js\").decrypt(\"{}\",\"{}\")'"""
    #cmd = 'node -e \"require(\'./decrypt.js\').decrypt(\'{}\',\'{}\')\"' #If fail, check quotes
    #pattern = r'\\n(.*)\\n'
    pattern = r'b\'(.*)\\n'
    
 
    privKey = w3.toHex(privKey)
    output = subprocess.check_output(cmd.format(message, privKey), shell=True)
    print(output)

    
    
    #signed_message = w3.eth.sign(privKey,text=message)
    print(cmd.format(message,privKey))
    substring = re.search(pattern, str(output)).group(1)
    print(substring)
    return substring


# %%
def recordPassword(empId, pssWd):
    check_sum = w3.toChecksumAddress(my_account._address)
    trans = verify_instance.functions.updatePass(empId, pssWd).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": nonce,"chainId": chainId}) #build RAW transaction supported by BESU
    updateNonce()
    signed_txn = w3.eth.account.sign_transaction(trans, my_account.privateKey) #Sign transaction using our own private key
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU
    #tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash.hex())  #Gets a receipt from the Blockchain
    #return tx_receipt
    


# %%
def recordAddress(empId, address):
    check_sum = w3.toChecksumAddress(my_account._address)
    trans = verify_instance.functions.updateAddress(empId, address).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": nonce,"chainId": chainId}) #build RAW transaction supported by BESU
    updateNonce()
    signed_txn = w3.eth.account.sign_transaction(trans, my_account.privateKey) #Sign transaction using our own private key
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU
    #tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash.hex())  #Gets a receipt from the Blockchain
    #return tx_receipt


# %%
def addPermission(address):
    check_sum = w3.toChecksumAddress(my_account._address)
    tx = contract_instance.functions.addAccount(address).buildTransaction({'from': check_sum,
                                                                               "gasPrice": w3.eth.gas_price,
                                                                               'nonce': nonce,
                                                                               "chainId": chainId}) #build RAW transaction supported by BESU
    #del tx['maxPriorityFeePerGas']
    print(tx)
    updateNonce()
    #signsendTransaction(tx, my_account)
    signed_txn = w3.eth.account.sign_transaction(tx, my_account.privateKey) #Sign transaction using our own private key
    print(signed_txn.rawTransaction)
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU
    #tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash.hex())
    


# %%
def mintOTTNFT(address, endpointType):
    check_sum = w3.toChecksumAddress(my_account._address)
    ott = str(getOTT(address, endpointType))  
    #mintOTTNFT(ott, address)
    totalSupply = nftOTT_instance.functions.totalSupply().call() #Get the total amount of tokens created
    check_sum = w3.toChecksumAddress(my_account._address)
    print("Totalsupply", totalSupply, address, ott)
    tokenId = totalSupply+1
    print(tokenId)
    trans = nftOTT_instance.functions.mint(address,tokenId,ott).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": nonce,"chainId": chainId}) #build RAW transaction supported by BESU
    updateNonce()
    signed_txn = w3.eth.account.sign_transaction(trans, my_account.privateKey) #Sign transaction using our own private key
    print(signed_txn.rawTransaction)
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU

 


# %%
def updateAccount(address, accountHash, enrollment, idType):
    check_sum = w3.toChecksumAddress(my_account._address)
    tx = contract_instance.functions.updateAccount(address, accountHash, enrollment, idType).buildTransaction({'from': check_sum,
                                                                               "gasPrice": w3.eth.gas_price,
                                                                               'nonce': nonce,
                                                                               "chainId": chainId}) #build RAW transaction supported by BESU
    #del tx['maxPriorityFeePerGas']
    print(tx)
    updateNonce()
    #signsendTransaction(tx, my_account)
    signed_txn = w3.eth.account.sign_transaction(tx, my_account.privateKey) #Sign transaction using our own private key
    print(signed_txn.rawTransaction)
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU
    #tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash.hex())
    


# %%
def updateNonce():
    global nonce
    nonce = nonce + 1
    print("Nonce", nonce)


# %%
def verifyMFA(signedMessage, address):
    resultMFA = verify_instance.functions.verifyMFA(signedMessage, address).call({'from': "0xc9e93b4E813c6818975ea166B0CfEc001454aD0B"}) #Get the status of the account
    print(resultMFA)
    return resultMFA

    
    


# %%
### NEED TO change to a better version.... Save the ID somewhere (Get it from the createOTT part)###
def getIdentityInfoN(identity):
    authResponse = requests.post(authURL, json=obj, verify=False,)
    jsonResponse = json.loads(authResponse.text)
    #print(authResponse.text)

    identityInfo = requests.get(
    f"{apiURL}identities?filter=(name contains \"{identity}\")",
    verify=False,
    headers={"zt-session": jsonResponse['data']['token']}
        )
    identityResponse = json.loads(identityInfo.text)
    if len(identityResponse) != 0:
        authenticators = identityResponse["data"][0]['authenticators']
        responseObj = {
            "id": identityResponse["data"][0]["id"],
            "name": identityResponse["data"][0]["name"],
            "createdAt": identityResponse["data"][0]["createdAt"],
            "updatedAt": identityResponse["data"][0]["updatedAt"],
            "auth": authenticators        
        }
        return responseObj
    else:
        return ''   ##Check a better way to return


# %%
app = Flask(__name__)
@app.route('/test/', methods=['GET', 'POST'])
def welcome():
    return "IBN Zero Trust!"

def burnOTT(address, tokenId):
    tokensOwned = nftOTT_instance.functions.balanceOf(address).call() #Get the status of the account
    check_sum = w3.toChecksumAddress(my_account._address)
    print("Tokens Owned", tokensOwned)
    trans = nftOTT_instance.functions.burn(tokenId).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": nonce,"chainId": chainId}) #build RAW transaction supported by BESU
    updateNonce()
    signed_txn = w3.eth.account.sign_transaction(trans, my_account.privateKey) #Sign transaction using our own private key
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU
    #tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash.hex())  #Gets a receipt from the Blockchain
    #return tx_receipt

def isPerm(address):
    result = contract_instance.functions.accountPermitted(address).call() #Get the status of the account
    return result

@app.route('/giveMePub/', methods=['GET'])
def giveMePub():
    result = signMessage(my_account.address, my_account.privateKey) #Get the status of the account
    resultObj = {
        "signature": result,
        "message": my_account.address
    }
    return resultObj

@app.route('/verifyEnrolled/', methods=['GET'])
def verifyEnrolled():
    args = request.args
    identity = args.get('name')
    tokenId = args.get('tokenId')
    type = args.get('type')
    
    ##burns the used token
    burnOTT(identity, int(tokenId))
    ##
    identityObject = getIdentityInfoN(identity)
    auth =identityObject["auth"]
    identityJSON = json.dumps(identityObject)
    print("JSON :", auth)
    if len(auth) == 0:
        return "False"
    else:
        result = contract_instance.functions.getFullByAddress(identity).call() #Get the status of the account
        isEnrolled = result[1]
        if isEnrolled:
            return "True"
        else:
            idHash = Web3.keccak(text=identityJSON)    #Hashes the Identity for storing in the blockchain
            updateAccount(identity, str(idHash), True, type)        #Updates the status of the identity
            return "True"
            
        
        
        
@app.route('/verify/', methods=['POST'])
def verify():
    stringData = request.data
    print(stringData.decode("utf-8") )
    decryptedData = decryptMessage(stringData.decode("utf-8"), my_account.privateKey)
    
    
    jsonData = json.loads(Web3.toText(hexstr=decryptedData))
    empId = jsonData["Id"]
    email = jsonData["email"]
    signature = jsonData["signature"]
    message  = jsonData["message"]
    
    empResult = verify_instance.functions.getRepoIdFromEmployeeId(int(empId)).call() #Get the status of the account
    emailResult = verify_instance.functions.getRepoIdFromEmail(email).call() #Get the status of the account
    if empResult == 0 or emailResult == 0:
        return "404"
    else:
        pubKey = getPubKeyfromSig(signature, message)
        print(pubKey)
        uniquePassw = pwo.generate()
        encryptedMessage =  encryptMessage(str(uniquePassw), pubKey)  # We encrypt the message with a random password
        recordPassword(empResult, str(uniquePassw)) #Records address and password information in the verification repo for MFA
        recordAddress(empResult, message) #Records address and password information in the verification repo for MFA
        emailMFA(email, encryptedMessage)
        return "201"
    return result

@app.route('/createIdentity/', methods=['POST'])
def createIdentity():
    try:
        requestJSON = request.json
        print(requestJSON)
        # handle your JSON_sent here
        # Pass JSON_received to the frontend
        #requestJSON = json.loads(requestJSON)
        address = requestJSON["address"]
        signature = requestJSON["signature"]
        endpointType = requestJSON["type"]
        print(address, signature)
        resultMFA = verifyMFA(signature, address)
        if resultMFA:
            #print(balance)
            #print(w3.eth.get_transaction_count(check_sum))
            perm = isPerm(address) #Get the status of the account
            if not perm:
                    addPermission(address)
                    perm = True
            if perm:
                    print("TEEEEEEEEEEEEEEEEEEEEEST")
                    mintOTTNFT(address, endpointType)
                    return "The account " + address + "has created a valid ID is , here is your OTT: "
         
    except Exception as e:
        print("An error ocurred: " + str(e))
        return str(e)
    
@app.route('/createEnrollment/', methods=['POST'])
def createEnrollment():
    try:
        requestJSON = request.json
        print(requestJSON)
        # handle your JSON_sent here
        # Pass JSON_received to the frontend
        #requestJSON = json.loads(requestJSON)
        address = requestJSON["address"]
        endpointType = requestJSON["type"]
        print(address)
        perm = isPerm(address) #Get the status of the account
        if not perm:
            e = "An error ocurred: " + "Address not permissioned"
            return str(e)
        if perm:
            print("TEEEEEEEEEEEEEEEEEEEEEST")
            mintOTTNFT(address, endpointType)
            return "The account " + address + "has created a valid ID is , here is your OTT: "
         
    except Exception as e:
        print("An error ocurred: " + str(e))
        return str(e)

    
if __name__ == '__main__':
    w3 = Web3(HTTPProvider(web3Prov)) #If access to our Local lockchain
    ctx = ssl.create_default_context() #secure ssl context for email
    
    w3.middleware_onion.inject(geth_poa_middleware, layer=0) #For compatibility with POA consensus chains
    nonce = 0 #Need to find a better way for nonce tracking
    contract_instance = w3.eth.contract(address = permissionedAddress, abi = abi) #Creates a contract instance for the permissions
    nftOTT_instance = w3.eth.contract(address = nftOTT, abi = abiNFT) #Creates a contract instance for the OTT-NFT
    verify_instance = w3.eth.contract(address = employeeRepo, abi = abiEmpRep) #Creates a contract instance for the employee Repo 
    #print(dir(nftOTT_instance.functions.mint))
    #print(dir(contract_instance.functions))

    
    
    accounts = contract_instance.functions.getAccounts().call() #Get the accounts that are permissioned


    file_exists = exists(keyFolder+"/"+"encyptedKeyIBN.json")
    try:
        my_account = getBlockKey(file_exists)
        check_sum = w3.toChecksumAddress(my_account._address)
        nonce = w3.eth.get_transaction_count(check_sum)
        print(my_account.address)
        #print(my_account.privateKey.hex())
        app.run(host='0.0.0.0', port=3003)
    except:
        print("Cannot run the RPC server, verify your Ethereum Account")


# %%



# %%



# %%



# %%



# %%



# %%



