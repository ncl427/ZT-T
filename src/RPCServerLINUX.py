# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %%
#!pip install flask
#!pip install random-password-generator
#!pip install python-dotenv


# %%
from calendar import calendar
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
from collections import namedtuple
from datetime import datetime


from dotenv import load_dotenv
from os import getenv

import os
import json
import requests
import smtplib
import ssl
import subprocess
import re
import time
import calendar
import jwt


### FOR OUR BESU CHAIN ####
##Uncomment if neeeded###
load_dotenv()

permissionedAddress = os.getenv('IDENTITYCONTRACT')
nftOTT = os.getenv('OTTADDRESS') #Address of the NFT contract
sessionNFT = os.getenv('SESSIONTOKENADDRESS') #Address of the session token contract
policyRules = os.getenv('POLICYCONTRACT') #Address of the policy contract
employeeRepo= os.getenv('MFAREPO')
###
web3Prov = os.getenv('WEB3PROVIDER')
#authURL = "https://orchestrator.ncl.lab:1280/edge/management/v1/authenticate?method=password"
apiURL = os.getenv('ZITIRPC')
#chainId = os.getenv('CHAINID')
chainId = 2022

ibnAddress = os.getenv('IBNADDRESS')
emailUser = os.getenv('EMAILUSER')
emailPwd = os.getenv('EMAILPWD')

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

with open(abiFolder+"/"+"sessionNFT.json") as file:
    abiSessionNFT = json.load(file)

with open(abiFolder+"/"+"policyRules.json") as file:
    abiPolicy = json.load(file)          
obj = {
    "username": os.getenv('ZITIUSERNAME'),
    "password": os.getenv('ZITIPWD')
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
    authResponse = requests.post(f"{apiURL}authenticate?method=password", json=obj, verify=False,)
    #print(authResponse.text)
    identobj =createIdentityObj(address, endpointType)
    ott = createOTT(identobj, authResponse)
    #print(ott)
    return ott

    


# %%
def emailMFA(email, secret):

    # mypass =  w3.eth.account.decrypt(myencPass, passw) #Decrypts the email password, to not reveal it.
    msg = EmailMessage() 
    sender = emailUser
    passWd = emailPwd 
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
def getAddressfromSig(signedmessage, message):
    cmd = """node -e 'require(\"./recoverAddress.js\").recoverAddress(\"{}\",\"{}\")'"""
    #cmd = """node -e 'require(\"./recoverSig.js\").recoverPubKey(\"{},{}\")'"""
    #cmd = 'node -e \"require(\'./recoverAddress.js\').recoverAddress(\'{}\',\'{}\')\"' #If fail, check quotes 
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
def recordPubKey(empId, pubKey):
    check_sum = w3.toChecksumAddress(my_account._address)
    trans = verify_instance.functions.updatePubKey(empId, pubKey).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": nonce,"chainId": chainId}) #build RAW transaction supported by BESU
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
def mintOTTNFT(address, endpointType, signature):
    check_sum = w3.toChecksumAddress(my_account._address)
    ott = str(getOTT(address, endpointType))
    decodedOTT = jwt.decode(ott, options={"verify_signature": False})   #We need to cecrypt first
    expiration = str(decodedOTT["exp"])

    if signature == '':
        pubKeyAddress = getPubKeyByAddress(address)
    else:
        pubKeyAddress = getPubKeyfromSig(signature, address)
    encryptedOTT = encryptMessage(ott, pubKeyAddress)  # We encrypt the ott using the requested address pubKey
       #mintOTTNFT(ott, address)
    totalSupply = nftOTT_instance.functions.totalSupply().call() #Get the total amount of tokens created
    check_sum = w3.toChecksumAddress(my_account._address)
    print("Totalsupply", totalSupply, address, ott)
    tokenId = totalSupply+1
    print(tokenId)
    trans = nftOTT_instance.functions.mint(address,tokenId,expiration,encryptedOTT).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": nonce,"chainId": chainId}) #build RAW transaction supported by BESU
    updateNonce()
    signed_txn = w3.eth.account.sign_transaction(trans, my_account.privateKey) #Sign transaction using our own private key
    print(signed_txn.rawTransaction)
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU

# %%
def mintSessionNFT(address, endpointType, identityInfo):
    metadataList = []
    check_sum = w3.toChecksumAddress(my_account._address)
    roleList = identityInfo[3] #Array of roles per Identity
    
    thePolicies = getPolicies()  ##NEED TO QUERY THE TOTAL POLICIES
    print("HERE", roleList, thePolicies )
    metadataList = getActivePolicies(thePolicies, roleList, endpointType, address) ##MAP roleList with the Total policies.
    
   
    ####Create a session NFT per unique policy Id that has the role only if NO SESSION TOKEN EXIST
    if metadataList:
        for m in metadataList:
            metadata = json.dumps(m._asdict()) #Each item in the metadatalist as JSON string
            totalSupply = sessionToken_instance.functions.totalSupply().call() #Get the total amount of tokens created
            tokenExist = verifyExist(address, m)
            if not tokenExist:

                check_sum = w3.toChecksumAddress(my_account._address)
                print("Totalsupply", totalSupply, address)
                tokenId = totalSupply+1
                print(tokenId)
                trans = sessionToken_instance.functions.mint(address,tokenId,endpointType,metadata).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": nonce,"chainId": chainId}) #build RAW transaction supported by BESU
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
    check_sum = w3.toChecksumAddress(my_account._address)
    thisNonce = w3.eth.get_transaction_count(check_sum)
   
    
    print("Nonce is!!", thisNonce, nonce)

    if thisNonce > nonce:
        nonce = thisNonce
    else:
        nonce = nonce + 1
    print("Nonce", nonce)


# %%
def verifyMFA(signedMessage, address):
    resultMFA = verify_instance.functions.verifyMFA(signedMessage, address).call({'from': ibnAddress}) #Get the status of the account
    print(resultMFA)
    return resultMFA
# %%
def getPubKeyByAddress(address):
    resulPubKey = verify_instance.functions.getPubKeyByAddress(address).call({'from': ibnAddress}) #Get the pubKey of the account
    #print(resultMFA)
    return resulPubKey


# %% Queries the blockchain for all the current policies
def getPolicies():
    policies = policyRules_instance.functions.getAllPolicies().call() #Get all the policies
    if len(policies) == 0:
        return 0
    else:
        return policies


# %% Compare the list of assigned roles to a list of roles from each policy
# returns an intersection
def detect(list_a, list_b):
    result = set(list_a) & set(list_b)
    print(list(result))
    
    return result


# %% Function that gets the policies which relate to an assigned role
# TO DO - query the attribute of the active roles returned by the intersection.
def getActivePolicies(policies, roles, type, address):
    activePolicyList = []
    if policies:
        if type == "Provider":
            for p in policies:
                print("This Policy", p)
                if address == p[3]: 
                    expiration = 32496789304
                    activePolicyList.append(Policy(p[0],p[4],expiration)) 
            print("List of policies", activePolicyList)
            #result = json.dumps(activePolicyList[0]._asdict())##Important for the metadata
            #print("JSON", result)

        elif roles:
            for p in policies:
                print("This Policy", p)
                a = detect(roles,p[1])
                if a: 
                    role =list(a)
                    roleAttribute =  policyRules_instance.functions.getFullRoleById(role[0]).call()
                    expiration = timetoEXP(json.loads(roleAttribute[2][0]))
                    print("ROLE ATTRIBUTES", expiration)
                    activePolicyList.append(Policy(p[0],p[4],expiration)) 
                print("RESULT", a)
            print("List of policies", activePolicyList)
            #result = json.dumps(activePolicyList[0]._asdict())##Important for the metadata
            #print("JSON", result)

    return activePolicyList 
    
# %% Verify if token exists
def verifyExist(address, metadata):
    sessionTokens = sessionToken_instance.functions.getOwnedNfts(address).call()
    if len(sessionTokens) == 0:
        return False
    else:
        for s in sessionTokens:
            print("Session Token", s[0])
            tokenURI = sessionToken_instance.functions.tokenURI(s[0]).call()
            res = json.loads(tokenURI)
            print("TOKEN URI",tokenURI)
            print ("METADATA", metadata, metadata.policyId,res["policyId"])
            if int(metadata.policyId) == int(res["policyId"]):
                return True

    return False
# %% Creates UTC timestamp
def timetoEXP(timeinsecs):
    current_datetime = datetime.utcnow()
    current_timetuple = current_datetime.utctimetuple()
    current_timestamp = calendar.timegm(current_timetuple)
    print(current_timestamp)
    current_timestamp = int(current_timestamp) + int(timeinsecs["exp"])

    print(current_timestamp)
    return current_timestamp

# %% Verifies expiration time
def verifyEXP(timeinsecs):
    current_datetime = datetime.utcnow()
    current_timetuple = current_datetime.utctimetuple()
    current_timestamp = calendar.timegm(current_timetuple)
    print("THE TIME IS: ",current_timestamp, timeinsecs)
    if int(current_timestamp) > int(timeinsecs):
        return True
    else:
        return False

# %% Checks validity of session tokens, burn if invalid
def isTokenValid(tokenId, address):
    tokenURI = sessionToken_instance.functions.tokenURI(tokenId).call()
    owner = sessionToken_instance.functions.ownerOf(tokenId).call()
    
    res = json.loads(tokenURI)
    policyId = int(res["policyId"])
    policyExists = policyRules_instance.functions.policyExists(policyId).call()
    isExpired = verifyEXP(res["exp"])
    if isExpired or not policyExists:
        burnSessionToken(owner, int(tokenId))
        return f"Session Token {tokenId} of {owner} is expired and was burned"
    else:
        return f"Session Token {tokenId} of {address} is still valid"

# %% Checks validity of OTtokens, burn if invalid
def isOTTokenValid(ott, address):
    owner = nftOTT_instance.functions.ownerOf(ott[0]).call()
    isExpired = verifyEXP(ott[1])
    if isExpired:
        burnOTT(owner, ott[0])
        print(f"OTT {ott[0]} of {owner} is expired and was burned")
    else:
        print(f"OTT {ott[0]} of {address} is still valid")



# %%
### Obtains info of the identity in Ziti
def getIdentityInfoN(identity):
    authResponse = requests.post(f"{apiURL}authenticate?method=password", json=obj, verify=False,)
    jsonResponse = json.loads(authResponse.text)
    #print(authResponse.text)

    identityInfo = requests.get(
    f"{apiURL}identities/{identity}",
    verify=False,
    headers={"zt-session": jsonResponse['data']['token']}
        )
    identityResponse = json.loads(identityInfo.text)
    if len(identityResponse) != 0:
        authenticators = identityResponse["data"]['authenticators']
        fingerprint = identityResponse["data"]["authenticators"]["cert"]["fingerprint"]
        responseObj = {
            "id": identityResponse["data"]["id"],
            "name": identityResponse["data"]["name"],
            "createdAt": identityResponse["data"]["createdAt"],
            "updatedAt": identityResponse["data"]["updatedAt"],
            "auth": authenticators,
            "fing": fingerprint  
        }
        return responseObj ##We only require the certificate fingerprint
        ##return fingerprint
    else:
        return ''   ##Check a better way to return




# %% Burn used Enrollment tokens
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

# %% Burn expired Session tokens
def burnSessionToken(address, tokenId):
    tokensOwned = sessionToken_instance.functions.balanceOf(address).call() #Get the status of the account
    check_sum = w3.toChecksumAddress(my_account._address)
    print("Tokens Owned", tokensOwned)
    trans = sessionToken_instance.functions.burn(tokenId).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": nonce,"chainId": chainId}) #build RAW transaction supported by BESU
    updateNonce()
    signed_txn = w3.eth.account.sign_transaction(trans, my_account.privateKey) #Sign transaction using our own private key
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU
    #tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash.hex())  #Gets a receipt from the Blockchain
    #return tx_receipt

# %%
app = Flask(__name__)
@app.route('/test/', methods=['GET', 'POST'])
def welcome():
    return "IBN Zero Trust!"





def isPerm(address):
    result = contract_instance.functions.accountPermitted(address).call() #Get the status of the account
    return result

def isEnrolled(address):
    result = contract_instance.functions.getFullByAddress(address).call() #Get the status of the account
    return result

@app.route('/giveMePub/', methods=['GET'])
def giveMePub():
    result = signMessage(my_account.address, my_account.privateKey) #Get the status of the account
    resultObj = {
        "signature": result,
        "message": my_account.address
    }
    return resultObj

@app.route('/giveMeToken/', methods=['POST'])
def giveMeToken():
    try:
        requestJSON = request.json
        print(requestJSON)
        address = requestJSON["address"]
        signature = requestJSON["signature"]
        print(address)
        realAddress = getAddressfromSig(signature, address)
        perm = isPerm(realAddress) #Get the status of the account
        enrolled = isEnrolled(realAddress)
        if not perm and not enrolled[1]:
            e = "An error ocurred: " + "Address not permissioned"
            return str(e)
        if perm and enrolled[1]:
            print("TEEEEEEEEEEEEEEEEEEEEEST")
            mintSessionNFT(address, enrolled[2], enrolled)
            return "The account " + address + "has been issued a session token: "
         
    except Exception as e:
        print("An error ocurred: " + str(e))
        return str(e)

@app.route('/verifyToken/', methods=['POST'])
def verifyToken():
    res = ''
    try:
        requestJSON = request.json
        print(requestJSON)
        address = requestJSON["address"]
        tokenId = requestJSON["tokenId"]
        print(address)
        if tokenId == '':
            sessionTokens = sessionToken_instance.functions.getOwnedNfts(address).call()
            otTokens = nftOTT_instance.functions.getOwnedNfts(address).call()
            if len(sessionTokens) != 0:
                for s in sessionTokens:
                  print("Session Token", s[0])
                  res = isTokenValid(s[0], address)
            
            if len(otTokens) != 0:
                for o in otTokens:
                    print("OTToken", o[0])
                    isOTTokenValid(o, address)
            
            return str(res)

        else:
            res = isTokenValid(tokenId, address)
            return str(res)
         
    except Exception as e:
        print("An error has ocurred: " + str(e))
        return str(e)

@app.route('/verifyEnrolled/', methods=['GET'])
def verifyEnrolled():
    args = request.args
    identity = args.get('name')
    tokenId = args.get('tokenId')
    type = args.get('type')
    

    ##
    identityObject = getIdentityInfoN(identity)
    auth =identityObject["auth"]
    ##auth = identityObject
    identityJSON = json.dumps(identityObject)
    print("JSON :", auth)
    if len(auth) == 0:
        return "False"
    else:
        enrolled = isEnrolled(identity) 
        if enrolled[1]:
            ##burns the used token
            burnOTT(identity, int(tokenId))
            return "True"
        else:
            idHash = Web3.keccak(text=identityObject["fing"])    #Hashes the Identity for storing in the blockchain
            hexHash = idHash.hex()
            updateAccount(identity, hexHash, True, type)        #Updates the status of the identity
            ##burns the used token
            burnOTT(identity, int(tokenId))
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
        recordPubKey(empResult, pubKey) #Records address and pubKey information in the verification repo for encryption
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
                    mintOTTNFT(address, endpointType, '')
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
        signature = requestJSON["signature"]
        print(address)
        perm = isPerm(address) #Get the status of the account
        if not perm:
            e = "An error ocurred: " + "Address not permissioned"
            return str(e)
        if perm:
            print("TEEEEEEEEEEEEEEEEEEEEEST")
            mintOTTNFT(address, endpointType, signature)
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
    sessionToken_instance = w3.eth.contract(address = sessionNFT, abi = abiSessionNFT)
    policyRules_instance = w3.eth.contract(address = policyRules, abi = abiPolicy)
    verify_instance = w3.eth.contract(address = employeeRepo, abi = abiEmpRep) #Creates a contract instance for the employee Repo 
    Policy = namedtuple("Policy",["policyId","hash", "exp"]) #Named Tuple for a policy    #print(dir(nftOTT_instance.functions.mint))
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



