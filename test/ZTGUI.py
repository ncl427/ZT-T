#!/usr/bin/env python
# coding: utf-8

# In[2]:


# In[1]:


from web3 import Web3, HTTPProvider, EthereumTesterProvider
from web3.middleware import geth_poa_middleware
from os.path import exists
from eth_account.messages import encode_defunct
from config.definitions import ROOT_DIR
from threading import Thread

import json
import requests
import os
import asyncio
import time
import subprocess
import PySimpleGUI as sg



nftOTT = "0xAf47c9D246fEF48C6AAc885353A86Cf06B8Ec4E5" #Address of the NFT contract
operator ="0xc9e93b4E813c6818975ea166B0CfEc001454aD0B" #Address of IBN
myOTT = None

abiFolder = os.path.join(ROOT_DIR, 'ABI')
with open(abiFolder+"/"+"ottNFT.json") as file:
    abiNFT = json.load(file)
rpcURL = "http://localhost:105/"


# In[ ]:





# In[2]:


def safePasswordInput( my_encKey, passw, num_retries):
    for attempt_no in range(num_retries):
        try:
            dec_key = w3.eth.account.decrypt(my_encKey, str(passw))
            return dec_key
        except ValueError as error:
            if attempt_no  == 0:
                print("Error: Invalid password")
            else:
                raise error


# In[3]:


def setApproval(address):
    tokensOwned = nftOTT_instance.functions.balanceOf(my_account._address).call() #Get the status of the account
    check_sum = w3.toChecksumAddress(my_account._address)
    print("Tokens Owned", tokensOwned)
    trans = nftOTT_instance.functions.setApprovalForAll(address, True).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": w3.eth.get_transaction_count(check_sum),"chainId": 2022}) #build RAW transaction supported by BESU
    signed_txn = w3.eth.account.sign_transaction(trans, my_account.privateKey) #Sign transaction using our own private key
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU
    tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash.hex())  #Gets a receipt from the Blockchain
    return tx_receipt


# In[4]:


def createEthAcc(entropy):
    my_account = w3.eth.account.create(entropy)
    return my_account


# In[5]:


def encryptWithPass(passw):
    my_encAcc= w3.eth.account.encrypt(my_account.privateKey, passw)
    #print(my_encAcc)
    with open('encyptedKey.json', 'w') as json_file:
        json.dump(my_encAcc, json_file)
    


# In[6]:


def decryptWithPass(passw, num_retries):
    with open('encyptedKey.json') as my_key:
            my_encKey = json.load(my_key)
    print(my_encKey)

    try:
        dec_key =safePasswordInput(my_encKey, passw, num_retries)  
        my_account = w3.eth.account.privateKeyToAccount(dec_key)
        return my_account
    except ValueError as error:
        raise error

    


# In[7]:


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
    #print(createIdentity.text)
    


# In[8]:


def checkBalance():
    check_sum = w3.toChecksumAddress(my_account._address)
    balance = w3.eth.get_balance(check_sum)
    print(balance)


# In[9]:


# define function to handle events and print to the console
def handle_event(event):
    eventS = Web3.toJSON(event)
    eventJSON = json.loads(eventS)
    print(eventJSON)
    tokenId = eventJSON["args"]["tokenId"]
    return tokenId
    # and whatever


# asynchronous defined function to loop
# this loop sets up an event filter and is looking for new entires for the "PairCreated" event
# this loop runs on a poll interval
#async def log_loop(event_filter, poll_interval):
def log_loop(event_filter, poll_interval):
    while True:
        for Transfer in event_filter.get_new_entries():
            #print("TEST")
            tokenId = handle_event(Transfer)
            global myOTT
            myOTT=tokenId
            print(tokenId)
        time.sleep(poll_interval)
        #await asyncio.sleep(poll_interval)
        
def eventFilter():
    event_filter = nftOTT_instance.events.Transfer.createFilter(fromBlock='latest', argument_filters={'to': my_account.address})
    print(event_filter)
    worker = Thread(target=log_loop, args=(event_filter, 2), daemon=True)
    worker.start()
    #block_filter = web3.eth.filter('latest')
    # tx_filter = web3.eth.filter('pending')
    #loop = asyncio.get_event_loop()
    #print("LOOP", loop)
    #try:
       # loop.run_until_complete(
          #  asyncio.gather(
            #    log_loop(event_filter, 2)))
                # log_loop(block_filter, 2),
                # log_loop(tx_filter, 2)))
    #finally:
        # close loop to free up system resources
      #  loop.close()


# In[10]:


def enroll(tokenId):
    tokenURI = nftOTT_instance.functions.tokenURI(tokenId).call() #Get the OTT information
    with open('ott.jwt', 'w') as f:
        f.write(tokenURI)
    output = subprocess.run(["ziti.exe", "edge", "enroll", "-j", "ott.jwt", "-o", "myId.json"], capture_output=True, text=True, check=True)
    print(output)
    


# In[16]:


if __name__ == '__main__':
    w3 = Web3(HTTPProvider('http://172.18.102.169:9545')) #If access to our Local lockchain
    w3.isConnected()
    #w3 = Web3(EthereumTesterProvider()) #If no internet connectivity
    w3.middleware_onion.inject(geth_poa_middleware, layer=0) #For compatibility with POA consensus chains
    print ("Latest Ethereum block number" , w3.eth.block_number)
    nftOTT_instance = w3.eth.contract(address = nftOTT, abi = abiNFT) #Creates a contract instance for the OTT-NFT
    
    file_exists = exists("encyptedKey.json")
    num_retries = 3
    sg.theme('BluePurple')

    decrypt = [[sg.Text('Enter your password for decryption:', key='-TXT-')],
              [sg.Text('Wrond password, try again!! Remaining attempts:', key='-TXT2-', visible=False,  text_color='red'), sg.Text(key='-WRONG-', visible=False) ],
              [sg.Input(key='-IN-', password_char='*')]]
    
    info    = [[sg.Text('Your Account number is:', key='-TXT1-',visible=True), sg.Text(key='-ACC-', visible=True)]]
    
    info2   = [[sg.Text('Your Account number is:', key='-TXT1-',visible=True), sg.Text(key='-ACC-', visible=True)]]
    
    error   = [[sg.Text('Too many mistakes', text_color='red')],
              [sg.Text('Verify your Ethereum Account', text_color='red')]]
    
    entropy = [[sg.Text('Please provide an entropy phrase for your secured Blockchain Keys:')],
              [sg.Input(key='-IN-')],
              [sg.Button('OK', key='-OK-')]]
    
    encrypt = [[sg.Text('Please provide a password for encryptyion of Blockchain Keys:')],
              [sg.Input(key='-IN2-')],
              [sg.Button('OK',  key='-OK2-')]]
    
    layout1 = [[sg.Text('Latest Ethereum block number:'), sg.Text(w3.eth.block_number, key='-BLOCK-')],
              [sg.Column(decrypt, key='-COL1-'), sg.Column(info, visible=False, key='-COL2-'), sg.Column(error, visible=False, key='-COL3-')],
              [sg.Button('Enter',  key='-ENTER-')]]
      

       
    
    layout2 = [[sg.Text('Latest Ethereum block number:'), sg.Text(w3.eth.block_number, key='-BLOCK-')],
              [sg.Column(entropy, key='-COL1-'), sg.Column(encrypt, visible=False, key='-COL2-'), sg.Column(info2, visible=False, key='-COL3-')],
              [sg.Button('Exit')]]
    
    
    if file_exists:
        layout = layout1
    else:
        layout = layout2
        
    print(layout)
    window = sg.Window('ZTClient', layout)
    

    while True:  # Event Loop
        event, values = window.read(timeout=1000)
        
        window['-BLOCK-'].update(w3.eth.block_number)
        print(event, values)
        print(file_exists)
        if event == sg.WIN_CLOSED or event == 'Exit':
            break
        if event == '-ENTER-':
            try:
                my_account = decryptWithPass(values['-IN-'], num_retries)
            # Update the "output" text element to be the value of "input" element
                print(my_account.address)
                window['-ACC-'].update(my_account.address)
                window['-COL1-'].update(visible=False)
                window['-ENTER-'].update(visible=False)
                window['-COL2-'].update(visible=True)

            except:
                num_retries = num_retries -1
                if num_retries == 0:
                    print("Verify your Ethereum Account", num_retries)
                    window['-COL1-'].update(visible=False)
                    window['-COL3-'].update(visible=True)
                    window['-ENTER-'].update(visible=False)

                else:
                    window['-TXT2-'].update(visible=True)
                    window['-WRONG-'].update(num_retries, visible=True)
                    print("Verify your Ethereum Account", num_retries)
                    
        if event == '-OK-':
            try:
                my_account = createEthAcc(values['-IN-'])
                window['-ACC-'].update(my_account.address)
                window['-COL1-'].update(visible=False)
                window['-COL2-'].update(visible=True)               
            except:
                print("error ocurred")
                
                
            
    window.close()

            
        #my_account = getBlockKey(file_exists)
        #    try:
        #        print(my_account.address)
        #    except NameError as error:
        #        print("There is no Ethereum account!!", error)
        #    latest_block = w3.eth.get_block('latest')
        #    print(latest_block)
        #except:
        #    print("Verify your Ethereum Account")


# In[ ]:





# In[ ]:





# In[ ]:




