#!/usr/bin/env python
# coding: utf-8

# In[1]:


import time
import json
import asyncio
import calendar
from web3 import Web3
import requests
from threading import Thread
from datetime import datetime
import logging
from web3.middleware import geth_poa_middleware


# In[2]:


w3 = Web3(Web3.HTTPProvider('http://172.18.102.169:9545/'))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

sessionTokenAddress = "0xe2a15B7ac207cB4B6A4Aa7D8F0e474b2e84302e8"
truffleFile1 = json.load(open('sessionNFT.json'))
# abi1 = truffleFile1['abi']
sessionTokenContract = w3.eth.contract(address=sessionTokenAddress, abi=truffleFile1)

policyAddresss = "0xB3Fc9617E051Ee61202fC29bC695Ff4504189234"
truffleFile2 = json.load(open('PolicyRules.json'))
abi2 = truffleFile2['abi']
roleContract = w3.eth.contract(address=policyAddresss, abi=abi2)


# In[3]:


def TokenExpireAPI(tokenId, identityAddress):
    jsonobj = {
        "address": identityAddress,
        "tokenId": tokenId
        }

    response = requests.post(
                    "http://172.18.102.81:3003"+"/verifyToken/",
                    verify=False,
                    json = jsonobj
                    )
    print("API Response: ", response.text)

def tokenCounter (tokenId, identityAddress):
    eventResponse = json.loads(sessionTokenContract.functions.tokenURI(tokenId).call())
    exptimeStamp = eventResponse['exp']
    print ("Expiry Time: ", exptimeStamp)
    currentTimestamp = calendar.timegm(datetime.utcnow().utctimetuple())
    print("Current Time:", currentTimestamp)
    diff = exptimeStamp - currentTimestamp
    print ("Time Remaining: ", diff)

    # stopTime = diff-20
    while (diff > 0):
        diff = exptimeStamp - calendar.timegm(datetime.utcnow().utctimetuple())
        print ("Token Id: ",tokenId, " --- Time Remaining: " , diff)
        time.sleep(5)
    print ("Token expire. Token Id: ", tokenId)
    logging.warning ("TOKEM Expire. Token Id: " + str(tokenId) )
    TokenExpireAPI(tokenId, identityAddress)


# In[4]:


def handle_event(event):
    eventS = Web3.toJSON(event)
    eventJSON = json.loads(eventS)
    print(eventJSON)
    
    tokenId = eventJSON['args']['tokenId']
    identityAddress = eventJSON['args']['to']
    print ("Token Id: ", tokenId, identityAddress)
    
    counter_threading(tokenId, identityAddress)

def counter_threading(tokenId, identityAddress):
    worker = Thread(
        target=tokenCounter,
        args=(tokenId, identityAddress),
        daemon=True)
    worker.start()
    
def log_loop_handler(event_filter, event_name, poll_interval):
    print ('STARTED - log_loop_handler - ', event_name )
    while True:
        # print ('Waiting for event: ', event_name)
        for Event in event_filter.get_new_entries():
            print("Event Triggered: ", event_name)
            logging.info( json.loads( Web3.toJSON( Event ))['args'])
            if (json.loads( Web3.toJSON( Event ))['args']['to'] != '0x0000000000000000000000000000000000000000'):
                handle_event(Event)
        time.sleep(poll_interval)
        
def filter_threading(event_filter, filter_name):
        worker = Thread(
            target=log_loop_handler,
            args=(event_filter, filter_name, 10),
            daemon=True)
        worker.start()

if __name__ == "__main__":
    
    file = "/home/orchestrator/waleed/APIs_output/blockchian_events.log"
    logging.basicConfig(filename=file, level=logging.INFO)
    print (datetime.now())
    # service added filter
    test_filter = sessionTokenContract.events.Transfer.createFilter(fromBlock='latest')
    filter_threading(test_filter, "Transfer Event")
	