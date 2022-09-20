#!/usr/bin/env python
# coding: utf-8

# In[1]:


#!pip install web3
#!pip install eth-tester


# In[2]:


from web3 import Web3, HTTPProvider, EthereumTesterProvider
from web3.middleware import geth_poa_middleware
from os.path import exists
from eth_account.messages import encode_defunct
from config.definitions import ROOT_DIR

import json
import requests
import os
import asyncio

nftOTT = "0xAf47c9D246fEF48C6AAc885353A86Cf06B8Ec4E5" #Address of the NFT contract
operator ="0xc9e93b4E813c6818975ea166B0CfEc001454aD0B" #Address of IBN

abiFolder = os.path.join(ROOT_DIR, 'ABI')
with open(abiFolder+"/"+"ottNFT.json") as file:
    abiNFT = json.load(file)
rpcURL = "http://192.168.0.64:105/"


# In[ ]:





# In[3]:


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


# In[4]:


def setApproval(address):
    tokensOwned = nftOTT_instance.functions.balanceOf(my_account._address).call() #Get the status of the account
    check_sum = w3.toChecksumAddress(my_account._address)
    print("Tokens Owned", tokensOwned)
    trans = nftOTT_instance.functions.setApprovalForAll(address, True).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": w3.eth.get_transaction_count(check_sum),"chainId": 2022}) #build RAW transaction supported by BESU
    signed_txn = w3.eth.account.sign_transaction(trans, my_account.privateKey) #Sign transaction using our own private key
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU
    tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash.hex())  #Gets a receipt from the Blockchain
    return tx_receipt


# In[5]:


def getBlockKey(file_exists):
    if not file_exists:
        print("Please provide an entropy phrase for your secured Blockchain Keys:")
        entropy = str(input())
        my_account = w3.eth.account.create(entropy)
        print("Please provide a password for encryptyion of Blockchain Keys:")
        passw = str(input())
        my_encAcc= w3.eth.account.encrypt(my_account.privateKey, passw)
        print(my_encAcc)
        with open('encyptedKey.json', 'w') as json_file:
            json.dump(my_encAcc, json_file)
        return my_account
    else:
        with open('encyptedKey.json') as my_key:
            my_encKey = json.load(my_key)
        print(my_encKey)
        print(type(my_encKey))
        print("Enter your password for decryption:")
        #passw = str(input())
        try:
            dec_key =safePasswordInput(my_encKey)  
            my_account = w3.eth.account.privateKeyToAccount(dec_key)
            return my_account
        except ValueError as error:
            print("Too many wrong passwords!!", error)
            raise error


# In[6]:


def createIdentity():
    print("Input the MFA verification message that you received in your E-mail")
    msg = str(input())
    #msg = "verified"
    private_key = my_account.privateKey
    message = encode_defunct(text=msg)
    signed_message = w3.eth.account.sign_message(message, private_key=private_key)

    print(signed_message)

    createIdentity = requests.post(
    rpcURL+"/enroll/",
    verify=False,
    data = signed_message.signature
    )
    print(createIdentity.text)
    
    


# In[14]:


# define function to handle events and print to the console
def handle_event(event):
    print(Web3.toJSON(event))
    # and whatever


# asynchronous defined function to loop
# this loop sets up an event filter and is looking for new entires for the "PairCreated" event
# this loop runs on a poll interval
async def log_loop(event_filter, poll_interval):
    while True:
        for Transfer in event_filter.get_new_entries():
            print("TEST")
            handle_event(Transfer)
        await asyncio.sleep(poll_interval)


# In[15]:


def checkBalance():
    check_sum = w3.toChecksumAddress(my_account._address)
    balance = w3.eth.get_balance(check_sum)
    print(balance)

    


# In[21]:


def eventFilter():
    event_filter = nftOTT_instance.events.Transfer.createFilter(fromBlock='latest')
    print(event_filter)
    #block_filter = web3.eth.filter('latest')
    # tx_filter = web3.eth.filter('pending')
    loop = asyncio.get_event_loop()
    print("LOOP", loop)
    try:
        loop.run_until_complete(
            asyncio.gather(
                log_loop(event_filter, 2)))
                # log_loop(block_filter, 2),
                # log_loop(tx_filter, 2)))
    finally:
        # close loop to free up system resources
        loop.close()


# In[11]:


if __name__ == '__main__':
    w3 = Web3(HTTPProvider('http://172.18.102.169:9545')) #If access to our Local lockchain
    w3.isConnected()
    #w3 = Web3(EthereumTesterProvider()) #If no internet connectivity
    w3.middleware_onion.inject(geth_poa_middleware, layer=0) #For compatibility with POA consensus chains
    print ("Latest Ethereum block number" , w3.eth.block_number)
    nftOTT_instance = w3.eth.contract(address = nftOTT, abi = abiNFT) #Creates a contract instance for the OTT-NFT
    
    file_exists = exists("encyptedKey.json")
    print(file_exists)
    try:
        my_account = getBlockKey(file_exists)
        try:
            print(my_account.address)
        except NameError as error:
            print("There is no Ethereum account!!", error)
        latest_block = w3.eth.get_block('latest')
        print(latest_block)
    except:
        print("Verify your Ethereum Account")


# In[17]:


checkBalance() #Checks balance of current account


# In[22]:


eventFilter()


# In[ ]:



createIdentity() #Creates a new Identity


# In[62]:


receipt = setApproval(operator)  #Approves the use of the NFT to the IBN blockchain account
print("Approved", receipt)


# In[ ]:




