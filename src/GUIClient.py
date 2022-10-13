#!/usr/bin/env python
# coding: utf-8

# In[1]:


#!python -m pip install PySimpleGUI
#!pip install pyjwt
#!pip install openziti
#!pip install pywin32



# In[ ]:





# In[2]:


from web3 import Web3, HTTPProvider, EthereumTesterProvider
from web3.middleware import geth_poa_middleware
from os.path import exists
from eth_account.messages import encode_defunct
from config.definitions import ROOT_DIR
from threading import Thread

from dotenv import load_dotenv
from os import getenv


import json
import requests
import os
import asyncio
import time
import subprocess
import PySimpleGUI as sg
import re
import jwt
import win32serviceutil
import psutil



### FOR OUR BESU CHAIN ####
##Uncomment if neeeded###
load_dotenv()
nftOTT = os.getenv('OTTADDRESS') #Address of the NFT contract
sessionNFT = os.getenv('SESSIONTOKENADDRESS') #Address of the session token contract

permissionedAddress = os.getenv('IDENTITYCONTRACT')

web3Prov = os.getenv('WEB3PROVIDER')
rpcURL = os.getenv('IBNBACKEND')

ibnAddress = os.getenv('IBNADDRESS')
zitiTunnel = os.getenv('EDGETUNNEL')

### FOR MY LOCAL TEST ###
### Uncomment if needed###
#web3Prov = "http://172.23.192.1:8545"
###


#nftOTT = "0x6d700596EA273E209Daefe5AAD491Dc1e125155C" #Address of the NFT contract
#permissionedAddress = "0x9B4844756255c8898862B3b2A2E9e056d8269eAd"

###
myOTT = 0
decodedOTT = None
myEmail = None
isEnrolled = False

abiFolder = os.path.join(ROOT_DIR, 'ABI')
keyFolder = os.path.join(ROOT_DIR, 'Keys')
srcFolder = os.path.join(ROOT_DIR, 'src')
idFolder =  os.path.join(ROOT_DIR, 'identity')

print(ROOT_DIR)

with open(abiFolder+"/"+"ottNFT.json") as file:
    abiNFT = json.load(file)
    
with open(abiFolder+"/"+"accountRules.json") as file:
    abi = json.load(file)

with open(abiFolder+"/"+"sessionNFT.json") as file:
    abiSessionNFT = json.load(file)
    
##os.environ["ZITI_IDENTITIES"] = idFolder+"/"+"myId.json"
os.environ["ZITI_IDENTITIES"] = ""
from openziti import enroll as ztenroll ##Environment variable is acting weird.


# In[ ]:





# In[3]:


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


# %%Sets approval of OTT NFTs

def setApproval(address):
    tokensOwned = nftOTT_instance.functions.balanceOf(my_account._address).call() #Get the status of the account
    check_sum = w3.toChecksumAddress(my_account._address)
    print("Tokens Owned", tokensOwned)
    trans = nftOTT_instance.functions.setApprovalForAll(address, True).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": w3.eth.get_transaction_count(check_sum),"chainId": 2022}) #build RAW transaction supported by BESU
    signed_txn = w3.eth.account.sign_transaction(trans, my_account.privateKey) #Sign transaction using our own private key
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU
    tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash.hex())  #Gets a receipt from the Blockchain
    return tx_receipt

# %%Sets approval of Session NFTs

def setSessionApproval(address):
    tokensOwned = sessionToken_instance.functions.balanceOf(my_account._address).call() #Get the status of the account
    check_sum = w3.toChecksumAddress(my_account._address)
    print("Tokens Owned", tokensOwned)
    trans = sessionToken_instance.functions.setApprovalForAll(address, True).buildTransaction({"from": check_sum,"gasPrice": w3.eth.gas_price,"nonce": w3.eth.get_transaction_count(check_sum),"chainId": 2022}) #build RAW transaction supported by BESU
    signed_txn = w3.eth.account.sign_transaction(trans, my_account.privateKey) #Sign transaction using our own private key
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction) #Send transaction to BESU
    #tx_receipt = w3.eth.wait_for_transaction_receipt(txn_hash.hex())  #Gets a receipt from the Blockchain
    #return tx_receipt


# In[5]:


def createEthAcc(entropy):
    my_account = w3.eth.account.create(entropy)
    return my_account


# In[6]:


def encryptWithPass(passw):
    my_encAcc= w3.eth.account.encrypt(my_account.privateKey, passw)
    #print(my_encAcc)
    with open(keyFolder+"/"+"encyptedKey.json", 'w') as json_file:
        json.dump(my_encAcc, json_file)
    


# In[7]:


def decryptWithPass(passw, num_retries):
    with open(keyFolder+"/"+"encyptedKey.json") as my_key:
            my_encKey = json.load(my_key)
    print(my_encKey)

    try:
        dec_key =safePasswordInput(my_encKey, passw, num_retries)  
        my_account = w3.eth.account.privateKeyToAccount(dec_key)
        print("MI CUENTA", w3.toHex(my_account.privateKey)) ###Just for debug, dangerous as it reveals teh private keys
        return my_account
    except ValueError as error:
        raise error

    


# In[8]:


def createIdentity(secretMessage):
    ##print("Input the MFA verification message that you received in your E-mail")
    ##msg = str(input())
    #msg = "verified"
    private_key = my_account.privateKey
    #message = encode_defunct(text=msg)
    #signed_message = w3.eth.account.sign_message(message, private_key=private_key)
    signedMessage = signMessage(secretMessage, private_key) #Sign message to ensure proper identity
    jsonobj = {
        "signature": signedMessage,
        "address": my_account.address,
        "type": "User"
    }


    print(jsonobj)

    createIdentity = requests.post(
    rpcURL+"/createIdentity/",
    verify=False,
    json = jsonobj
    )
    print(createIdentity.text)
    


# In[9]:


def checkBalance():
    check_sum = w3.toChecksumAddress(my_account._address)
    balance = w3.eth.get_balance(check_sum)
    print(balance)


# In[10]:


# define function to handle events and print to the console
def handle_event(event):
    eventS = Web3.toJSON(event)
    eventJSON = json.loads(eventS)
    print(eventJSON)
    tokenId = eventJSON["args"]["tokenId"]
    return tokenId
    # and whatever


# asynchronous defined function to loop
# this loop sets up an event filter and is looking for new entires for the "Transfer" event
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


# In[11]:


def enroll(tokenId):
    if tokenId != 0:
        tokenURI = decryptOTT(tokenId) #Get the OTT information
        with open(r"C:\Windows\System32\config\systemprofile\AppData\Roaming\NetFoundry\myId.json", 'wb') as id_file:
            id_json = ztenroll(tokenURI)
            id_file.write(bytes(id_json, 'utf-8'))
        print("ENROLLMENT SUCCESS")
        notifyEnrollment(tokenId)
    


# In[12]:


def getmyOTT(address):
    myTokens = nftOTT_instance.functions.getOwnedNfts(address).call({'from': ibnAddress}) #Get the owned NFTs from an account
    if len(myTokens) == 0:
        return 0
    else:
        tokenId = myTokens[0][0]
        return tokenId
    


# In[13]:


### Function for decoding the JWT token ###
def decodeOTT(tokenId):
    if tokenId == 0:
        global myOTT
        myOTT = getmyOTT(my_account.address)
    print(myOTT)
    if myOTT == 0:
        return 0
    else:
        tokenURI = decryptOTT(myOTT) #Get the OTT information
        decodedOTT = jwt.decode(tokenURI, options={"verify_signature": False})   #We need to cecrypt first
        print(decodedOTT)
        return decodedOTT["exp"]


# In[14]:

def decryptOTT(tokenId):
    encryptedtokenURI = nftOTT_instance.functions.tokenURI(tokenId).call() #Get the OTT information
    tokenURI = decryptMessage(encryptedtokenURI, my_account.privateKey)
    return tokenURI

def isPerm(address):
    result = contract_instance.functions.accountPermitted(address).call() #Get the status of the account
    return result    


# In[15]:


def verifyUser(empId, email, pubKeyIBN):
    global myEmail
    signedMessage = signMessage(my_account.address, my_account.privateKey) #Sign message to not expose the public address and to ensure proper identity
    myEmail = email
    jsonobj = {
        "Id": empId,
        "email": email,
        "signature": signedMessage,
        "message": my_account.address
    }
    #jsonString = json.dumps(jsonobj)
    #print(type(jsonString))
    messageEncoded = w3.toHex(text=json.dumps(jsonobj))
    print(messageEncoded)
    encryptedMessage = encryptMessage(messageEncoded, pubKeyIBN) #To not disclose personal info to the network
    verification = requests.post(
    rpcURL+"/verify/",
    verify=False,
    data = encryptedMessage

    )
    print(verification.text)
    return verification.text
    
    


# In[16]:


def signMessage(message, privKey):
    singlequote ="'"
    doublequote = '"'
    cmd = 'node -e \"require(\'./signMe.js\').signMessage(\'{}\',\'{}\')\"' #If fail, check quotes
    pattern = r'\\n(.*)\\n'
    
 
    privKey = w3.toHex(privKey)
    output = subprocess.check_output(cmd.format(message, privKey), shell=True)
    
    
    #signed_message = w3.eth.sign(privKey,text=message)
    print(cmd.format(message,privKey))
    print(str(output))
    substring = re.search(pattern, str(output)).group(1)
    print(substring)
    return substring


# In[17]:


def encryptMessage(message, publicKey):
    #cmd = """node -e 'require(\"./encrypt.js\").encrypt(\"{},{}\")'"""
    cmd = 'node -e \"require(\'./encrypt.js\').encrypt(\'{}\',\'{}\')\"' #If fail, check quotes
    pattern = r'\\n(.*)\\n'
    
 
    #privKey = w3.toHex(privKey)
    output = subprocess.check_output(cmd.format(message, publicKey), shell=True)
    #print(output)

    
    
    #signed_message = w3.eth.sign(privKey,text=message)
    print(cmd.format(message,publicKey))
    substring = re.search(pattern, str(output)).group(1)
    print(substring)
    return substring


# In[18]:


def getPubKeyfromSig(signedmessage, message):
    #cmd = """node -e 'require(\"./recoverSig.js\").recoverPubKey(\"{},{}\")'"""
    cmd = 'node -e \"require(\'./recoverSig.js\').recoverPubKey(\'{}\',\'{}\')\"' #If fail, check quotes 
    pattern = r'\\n(.*)\\n'

    output = subprocess.check_output(cmd.format(signedmessage, message), shell=True)
    print(cmd.format(signedmessage,message))
    #print(output)
    substring = re.search(pattern, str(output)).group(1)
    print(substring)
    return substring


# In[19]:


#For identifying the IBN PublicKey
def getIBNPubKey():
    response = requests.get(
    rpcURL+"/giveMePub/",
    verify=False
    )
    print(response.text)
    respJSON = json.loads(response.text)
    pubKeyIBN = getPubKeyfromSig(respJSON["signature"], respJSON["message"] )
    
    
    return pubKeyIBN


# In[20]:


#For verification check of Enrollment to IBN
def notifyEnrollment(tokenId):
    response = requests.get(
    rpcURL+"/verifyEnrolled?name=" +my_account.address+"&tokenId=" +str(tokenId)+"&type=" +str("Client"),
    verify=False
    )
    print(response.text)


# In[21]:


#For creating identity and enrollment in Ziti when address was permissioned by Admin
def createEnrollment(address):
    signedMessage = signMessage(my_account.address, my_account.privateKey) #Sign message to not expose the public address and to ensure proper identity

    jsonobj = {
    "address": address,
    "type": "User",
    "signature": signedMessage
     }
    print(jsonobj)

    createIdentity = requests.post(
    rpcURL+"/createEnrollment/",
    verify=False,
    json = jsonobj
    )
    print(createIdentity.text)
    return createIdentity.text
    
    


# In[22]:


def decryptMessage(message, privKey):
    #cmd = """node -e 'require(\"./encrypt.js\").encrypt(\"{},{}\")'"""
    cmd = 'node -e \"require(\'./decrypt.js\').decrypt(\'{}\',\'{}\')\"' #If fail, check quotes
    pattern = r'\\n(.*)\\n'
    
 
    privKey = w3.toHex(privKey)
    #print(privKey)
    output = subprocess.check_output(cmd.format(message, privKey), shell=True)
    #print(output)

    
    
    #signed_message = w3.eth.sign(privKey,text=message)
    print(cmd.format(message,privKey))
    substring = re.search(pattern, str(output)).group(1)
    print(substring)
    return substring


# In[23]:


def countdown(timetoExp):
    if timetoExp > int(time.time()):
        timeDiff = timetoExp - int(time.time())
        return timeDiff
    else:
        return 0


# In[24]:


def checkEnrolled(address):
    result = contract_instance.functions.getFullByAddress(address).call() #Get the status of the account
    global isEnrolled
    isEnrolled = result[1]
    print("GETFULL", isEnrolled)
    myenroll = result[1]
    return myenroll



# %% For providing a token when connection starts
def giveMeToken():

    signedMessage = signMessage(my_account.address, my_account.privateKey) #Sign message to not expose the public address and to ensure proper identity

    jsonobj = {
    "address": my_account.address,
    "signature": signedMessage
     }

    response = requests.post(
    rpcURL+"/giveMeToken/",
    verify=False,
    json = jsonobj
    )
    print(response.text)

# %% For verifying token when connection starts

def verifyToken():
    
    jsonobj = {
    "address": my_account.address,
    "tokenId": ''
     }

    response = requests.post(
    rpcURL+"/verifyToken/",
    verify=False,
    json = jsonobj
    )
    print(response.text)



    


# In[25]:


def restartRouter():
    serviceName = "ziti"
    win32serviceutil.RestartService(serviceName)
    


# In[26]:


def startRouter():
    serviceName = "ziti"
    win32serviceutil.StartService(serviceName)


# In[27]:


def stopRouter():
    serviceName = "ziti"
    win32serviceutil.StopService(serviceName)


# In[28]:


def routerStatus():
    serviceName = "ziti"
    status = win32serviceutil.QueryServiceStatus(serviceName)
    
    service = None
    try:
        service = psutil.win_service_get(serviceName)
        service = service.as_dict()
        if service:
            print("Service found: ", service)
        else:
            print("Service not found")

        if service and service['status'] == 'running':
            print("Service is running")
            return 1
        if service and service['status'] == 'stop_pending':
            print("Service is stopping")
            return 2

        else: 
            print("Service is not running")
            print("ROUTER IS", status)
            return 3

    except Exception as ex:
        # raise psutil.NoSuchProcess if no service with such name exists
        print(str(ex))



# In[29]:


def collapse(layout, key, visible):
    """
    Helper function that creates a Column that can be later made hidden, thus appearing "collapsed"
    :param layout: The layout for the section
    :param key: Key used to make this seciton visible / invisible
    :return: A pinned column that can be placed directly into your layout
    :rtype: sg.pin
    """
    return sg.pin(sg.Column(layout, key=key, visible = visible))


# In[30]:


def connecButtons():
    if isEnrolled:
            if routerStatus() == 1:
                window['-ISCONNECTED-'].update("Connected", text_color='green')
                window['-SEC1-'].update(visible=False) #Pinned Column for button format
                window['-SEC2-'].update(visible=True) #Pinned Column for button format
                
            else:
                window['-ISCONNECTED-'].update("Not Connected", text_color='red')
                window['-SEC2-'].update(visible=False) #Pinned Column for button format
                window['-SEC1-'].update(visible=True) #Pinned Column for button format

    


# In[31]:




if __name__ == '__main__':
    w3 = Web3(HTTPProvider(web3Prov)) #If access to our Local lockchain
    w3.isConnected()
    #w3 = Web3(EthereumTesterProvider()) #If no internet connectivity
    w3.middleware_onion.inject(geth_poa_middleware, layer=0) #For compatibility with POA consensus chains
    print ("Latest Ethereum block number" , w3.eth.block_number)
    contract_instance = w3.eth.contract(address = permissionedAddress, abi = abi) #Creates a contract instance for the permissions
    nftOTT_instance = w3.eth.contract(address = nftOTT, abi = abiNFT) #Creates a contract instance for the OTT-NFT
    sessionToken_instance = w3.eth.contract(address = sessionNFT, abi = abiSessionNFT)

    
    file_exists = exists(keyFolder+"/"+"encyptedKey.json")
    num_retries = 3
    keyExist = True
    firstrun = True
    
    if file_exists:
        keyExist = True
      #  firstrun = False
    elif firstrun:
        keyExist = False
      #  firstrun = False
    sg.theme('BluePurple')

    decrypt = [[sg.Text('Enter your password for decryption:', key='-TXT-')],
              [sg.Text('Wrond password, try again!! Remaining attempts:', key='-TXT2-', visible=False,  text_color='red'), sg.Text(key='-WRONG-', visible=False) ],
              [sg.Input(key='-IN-', password_char='*')],
              [sg.Button('Enter',  key='-ENTER-') ]]
    
    connect = [[sg.Button('CONNECT', key='-CONNECT-', visible = True)]]
    
    discon  = [[sg.Button('DISCONNECT', key='-DISCONNECT-', visible = True)]]
    
    info    = [[sg.Text('Your Account number is:', key='-TXT1-',visible=True), sg.Text(key='-ACC-', visible=True)],
              [sg.Text('Account Status:')],
              [sg.Text(key='-ISPERM-')],
              [sg.Text(key='-ISENROLLED-')],
              [sg.Text(key='-ISCONNECTED-')],
              [sg.Text('Your enroll token expires in:', key='-TOKEN-'), sg.Text(key='-EXPIRE-')],
              [sg.Button('ENROll', key='-ENROLL-', visible = False)],
              [collapse(connect, '-SEC1-', False)],
              [collapse(discon, '-SEC2-', False)]]
    
    
    error   = [[sg.Text('Too many mistakes', text_color='red')],
              [sg.Text('Verify your Ethereum Account', text_color='red')]]
    
    entropy = [[sg.Text('Please provide an entropy phrase for your secured Blockchain Keys:')],
              [sg.Input(key='-IN2-', password_char='*')],
              [sg.Button('OK', key='-OK-')]]
    
    encrypt = [[sg.Text('Please provide a password for encryptyion of Blockchain Keys:')],
              [sg.Input(key='-IN3-', password_char='*')],
              [sg.Button('SUBMIT',  key='-OK2-')]]
    
    mfa = [[sg.Text('Please input the secret message that was sent to this email:'), sg.Text(myEmail, key='-MFA-')],
              [sg.Input(key='-INDEC-')],
              [sg.Button('SUBMIT',  key='-OK3-')]]
    
    verify = [[sg.Text('Please provide your Employee ID:')],
              [sg.Input(key='-IDIN-')],
              [sg.Text('Please provide your E-Mail:')],
              [sg.Input(key='-EMAILIN-')],
              [sg.Button('SUBMIT',  key='-SUBMIT-')]]
    
    layout = [[sg.Text('Latest Ethereum block number:'), sg.Text(w3.eth.block_number, key='-BLOCK-')],
              [sg.Column(decrypt, visible=keyExist, key='-COL1-'), sg.Column(info, visible=False, key='-COL2-'),
               sg.Column(error, visible=False, key='-COL3-'), sg.Column(entropy, visible=not keyExist, key='-COL4-'),
               sg.Column(encrypt, visible=False, key='-COL5-'), sg.Column(verify, visible=False, key='-COL6-'),
               sg.Column(mfa, visible=False, key='-COL7-')],
              [sg.Button('Exit')]]
      

    
    
        
    print(layout)
    window = sg.Window('ZTClient', layout)
    

    while True:  # Event Loop
        event, values = window.read()
        
        print("ENRROLADO", isEnrolled)
        #ziti-edge-router service status for the UI information only if Enrolled
        

        connecButtons() ###Used for connect/disconnect logic
            


        window['-BLOCK-'].update(w3.eth.block_number)
        print(event, values)
        print(int(time.time()))

        #print(file_exists)
        if event == sg.WIN_CLOSED or event == 'Exit':
            break
        if event == '-ENTER-':
            try:
                my_account = decryptWithPass(values['-IN-'], num_retries) #Tries to decrypt the account
                timetoExp = decodeOTT(myOTT) 

            # Update the "output" text element to be the value of "input" element
                print(my_account.address)
                window['-ACC-'].update(my_account.address) #Displays ethereum account address
                window['-COL1-'].update(visible=False)
                window['-ENTER-'].update(visible=False)

                if isPerm(my_account.address):
                    window['-COL2-'].update(visible=True)
                    count = countdown(timetoExp)
                    window['-EXPIRE-'].update(str(count) + ' seconds')
                    window['-ISPERM-'].update("Permissioned", text_color='green')
                    if not checkEnrolled(my_account.address): #Define a check for enrollment in Blockchain IMPORTANT
                        window['-ISENROLLED-'].update("Not Enrolled", text_color='red')
                        window['-ENROLL-'].update(visible=True)
                        connecButtons()
                    else:
                        window['-ISENROLLED-'].update("Enrolled", text_color='green')
                        window['-EXPIRE-'].update(visible=False)
                        window['-ENROLL-'].update(visible=False)
                        window['-TOKEN-'].update(visible=False)
                        connecButtons()
             
                else:
                    window['-COL6-'].update(visible=True)


            except Exception as e:
                num_retries = num_retries -1 #Counter for number of tries for decryption
                if num_retries == 0:
                    print("Verify your Ethereum Account", num_retries)
                    window['-COL1-'].update(visible=False)
                    window['-COL3-'].update(visible=True)
                    window['-ENTER-'].update(visible=False)

                else:
                    window['-TXT2-'].update(visible=True)
                    window['-WRONG-'].update(num_retries, visible=True)
                    print("Verify your Ethereum Account", num_retries)
                    print("An error ocurred: ", e)
                    
        if event == '-OK-':
            if values['-IN2-'] != '':
                try:
                    my_account = createEthAcc(values['-IN2-']) #If no ethereum account, creates one
                    window['-ACC-'].update(my_account.address)
                    window['-COL4-'].update(visible=False)
                    window['-COL5-'].update(visible=True)               
                except:
                    print("error ocurred")

        if event == '-OK2-':
            if values['-IN3-'] != '':
                try:
                    encryptWithPass(values['-IN3-']) #Encrypts created ethereum account
                    window['-COL5-'].update(visible=False)
                    if isPerm(my_account.address):
                        window['-COL2-'].update(visible=True)
                    else:
                        window['-COL6-'].update(visible=True)

                
                except:
                    print("error ocurred")
                    
        if event == '-SUBMIT-':
            if values['-IDIN-'] != '' and values['-EMAILIN-'] != '' :
                try:
                    pubKeyIBN = getIBNPubKey()
                    verification = verifyUser(values['-IDIN-'],values['-EMAILIN-'], pubKeyIBN) #If not permissioned, verifies user -> PUT IT IN THREAD
                    if verification == '201':
                        window['-MFA-'].update(values['-EMAILIN-'])
                        window['-COL6-'].update(visible=False)
                        window['-COL7-'].update(visible=True)
                        #window['-ACC-'].read() #Need to redraw the GUI again

                    else:
                        sg.popup("Wrong Info", "Try again")
                except Exception as e:
                    print("error ocurred", e)
                    
        if event == '-OK3-':
            if values['-INDEC-'] != '':
                try:
                    decryptedData = decryptMessage(values['-INDEC-'], my_account.privateKey)  #Decrypts MFA message
                    createIdentity(decryptedData)
                    eventFilter()                    
                    window['-COL7-'].update(visible=False)
                    window['-COL2-'].update(visible=True)
                    print("MYOTT: ", myOTT)
                    while myOTT == 0:
                        event, values = window.read(100)
                    timetoExp = decodeOTT(myOTT)
                    window['-ISPERM-'].update("Permissioned", text_color='green')
                    if not checkEnrolled(my_account.address): #Define a check for enrollment in Blockchain IMPORTANT
                        window['-ISENROLLED-'].update("Not Enrolled", text_color='red')
                        window['-ENROLL-'].update(visible=True)
                    else:
                        window['-ISENROLLED-'].update("Enrolled", text_color='green')
                    count = countdown(timetoExp)
                    window['-EXPIRE-'].update(str(count) + ' seconds')
                        
                        
   
                except Exception as e:
                    sg.popup("Wrong Info", "Try again")
                    print("error ocurred", e)
                

        if event == '-ENROLL-':
            myOTT = getmyOTT(my_account.address)
            setApproval(ibnAddress)
            setSessionApproval(ibnAddress)
            if (myOTT == 0 and isPerm(my_account.address)):
                createEnrollment(my_account.address)
                eventFilter()
                while myOTT == 0:
                    event, values = window.read(100)
                timetoExp = decodeOTT(myOTT)
                window['-ISPERM-'].update("Permissioned", text_color='green')
                if not checkEnrolled(my_account.address): #Define a check for enrollment in Blockchain IMPORTANT
                    window['-ISENROLLED-'].update("Not Enrolled", text_color='red')
                    window['-ENROLL-'].update(visible=True)
                else:
                    window['-ISENROLLED-'].update("Enrolled", text_color='green')
                count = countdown(timetoExp)
                window['-EXPIRE-'].update(str(count) + ' seconds')
            else:              
                try:
                    enroll(myOTT)
                    sg.popup("Enrollment sucessful!!!")
                    while not checkEnrolled(my_account.address): #Define a check for enrollment in Blockchain IMPORTANT
                        event, values = window.read(100)
                        window['-ISENROLLED-'].update("Not Enrolled", text_color='red')
                        window['-ENROLL-'].update(visible=False)
                        connecButtons()
                    window['-ISENROLLED-'].update("Enrolled", text_color='green')
                    window['-EXPIRE-'].update(visible=False)
                    window['-ENROLL-'].update(visible=False)
                    window['-TOKEN-'].update(visible=False)
                    connecButtons()
                except Exception as e:
                        sg.popup("An error ocurred")
                        print("error ocurred", e)
         
        #Start the ziti-edge-tunnel service and connects to the overlay
        if event == '-CONNECT-':
            
            if routerStatus() == 1:
                restartRouter()
            elif routerStatus() == 3 :
                startRouter()
            while routerStatus() != 1: #Checks if the service is up (it takes time to come up)
                event, values = window.read(100)
                window['-ISCONNECTED-'].update("Connecting...", text_color='blue')
            connecButtons()
            verifyToken()
            giveMeToken()
            
            window['-ISCONNECTED-'].update("Connected", text_color='green')
            
            
        #Stops the ziti-edge-tunnel service and disconnects from the overlay
        if event == '-DISCONNECT-':
            if routerStatus() == 1:
                stopRouter()
            while routerStatus() == 2: #Checks if the service is down
                event, values = window.read(100)
                window['-ISCONNECTED-'].update("Disconnecting...", text_color='red')
            connecButtons()
            window['-ISCONNECTED-'].update("Not Connected", text_color='red')
            
  
                


                
            
    window.close()

            




