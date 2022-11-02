#!/usr/bin/env python
# coding: utf-8

# In[1]:


import requests
from requests.auth import HTTPBasicAuth
import json
import warnings
import time
import datetime
import logging
warnings.filterwarnings('ignore')


# In[2]:


# create service on ziti
APIurl = "https://172.18.102.169:1280/edge/management/v1/"

# get Authentication Token
def GET_AUTH_TOKEN ():
    authURL = APIurl + "authenticate?method=password"
    cred = { "username": "admin", "password": "admin" }

    authResponse = requests.post(authURL, json=cred, verify =False)
    jsonResponse = json.loads(authResponse.text)
    authToken = jsonResponse['data']['token']
    
    return {'status': authResponse, 'authToken': authToken}


# In[3]:


def IDENTITY_UPDATE_API(identity_id, roles_ls):
    
    authInfo = GET_AUTH_TOKEN()
    sessResponse = requests.patch(
        APIurl + "identities/" + identity_id,
        verify = False,
        headers = {"zt-session": authInfo['authToken'], 'Content-Type': 'application/json'},
        json = {"encryptionRequired": True,
                'roleAttributes': roles_ls
               }
        )
    #print (sessResponse)
    result = str(sessResponse).split("[")[1][:3]
    #print (result, type(result))
    if (result == '200'):
        return json.loads(sessResponse.text)
    elif (result == '401'):
        authInfo = GET_AUTH_TOKEN()
        authToken = authInfo['authToken']
        return IDENTITY_UPDATE_API(identity_id, roles_ls)
    else:
        print ("IDENTITY UPDATE API error is: ", sessResponse)
        return -1
	

# In[4]:


import time
import json
import asyncio
from web3 import Web3
from threading import Thread
from web3.middleware import geth_poa_middleware


# In[5]:


w3 = Web3(Web3.HTTPProvider('http://172.18.102.169:9545/'))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
# w3.isConnected()

Identitycontract = '0xb17777a2F9f9B08aa6599623F362Ced84A9b14Ef'
truffleFile = json.load(open('AccountRules.json'))
abi = truffleFile['abi']
contract = w3.eth.contract(address=Identitycontract, abi=abi)

policyAddress = '0xB3Fc9617E051Ee61202fC29bC695Ff4504189234'
truffleFile2 = json.load(open('PolicyRules.json'))
abi2 = truffleFile2['abi']
roleContract = w3.eth.contract(address=policyAddress, abi=abi2)


# In[6]:


def handle_event(event):
    eventS = Web3.toJSON(event)
    eventJSON = json.loads(eventS)
    print(eventJSON)
    roleIds = eventJSON['args']['accountRoles']
    identity = eventJSON['args']['accountAddress']
    roleNames = []
    for rId in roleIds:
        roleNames.append(roleContract.functions.getFullRoleById(rId).call()[0])
    print ("---------\n", roleNames, identity, "---------\n")
    response = IDENTITY_UPDATE_API(identity, roleNames)
    if response !=1:
        print ("Identity updated with new role values")

def log_loop_handler(event_filter, event_name, poll_interval):
    print ('STARTED - log_loop_handler - ', event_name )
    while True:
        # print ('Waiting for event: ', event_name)
        for Event in event_filter.get_new_entries():
            print("Event Triggered: ", event_name)
            logging.info( json.loads( Web3.toJSON( Event ))['args'])
            handle_event(Event)
        time.sleep(poll_interval)
        
def filter_threading(event_filter, filter_name):
        worker = Thread(
            target=log_loop_handler,
            args=(event_filter, filter_name, 8),
            daemon=True)
        worker.start()


# In[7]:


if __name__ == "__main__":
    
    file = "/home/orchestrator/waleed/APIs_output/blockchian_events.log"
    logging.basicConfig(filename=file, level=logging.INFO)
    print (datetime.datetime.now())
    
    # service added filter
    test_filter = contract.events.AccountUpdatedRoles.createFilter(fromBlock='latest')
    filter_threading(test_filter, "Account Updated Roles")
