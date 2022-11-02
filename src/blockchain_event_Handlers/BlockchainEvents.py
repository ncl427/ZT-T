#!/usr/bin/env python
# coding: utf-8

# # Blockchain Event Handler

# In[1]:


import time
import json
import asyncio
import logging
from web3 import Web3
from threading import Thread
from web3.middleware import geth_poa_middleware


# In[2]:


w3 = Web3(Web3.HTTPProvider('http://172.18.102.169:9545/'))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

Identitycontract = '0xb17777a2F9f9B08aa6599623F362Ced84A9b14Ef'
truffleFile = json.load(open('AccountRules.json'))
abi = truffleFile['abi']
identitycontract = w3.eth.contract(address=Identitycontract, abi=abi)

policyAddress = '0xB3Fc9617E051Ee61202fC29bC695Ff4504189234'
truffleFile2 = json.load(open('PolicyRules.json'))
abi2 = truffleFile2['abi']
roleContract = w3.eth.contract(address=policyAddress, abi=abi2)


# In[4]:


#handler for service addition
def handle_event_add_service(event, authToken):
    eventS = Web3.toJSON(event)
    eventJSON = json.loads(eventS)
    print(eventJSON)
    service_id = str(eventJSON['args']['serviceId'])
    service_name = eventJSON['args']['serviceName']  
    address = eventJSON['args']['serviceConfig'][0].split(':')
    if len(address) == 2:
        serviceAddress = address[0]
        service_port = int(address[1])
    elif len(address) == 1:
        serviceAddress = address
        service_port = 8080
    else:
        print ("Address not added correctly. Default address and port used")
        serviceAddress = '0.0.0.0'
        service_port = 1000
    print (serviceAddress, service_port)
    
    config_id = SERVICE_CONFIG_ADD_API(service_name+".config", 'g7cIWbcGg', serviceAddress,
                                       service_port, authToken)
    response = SERVICE_ADD_API(service_name, service_id, [config_id], authToken)
    if (response != -1):
        rows = response["data"]['id']
        print ("Service Id: ", rows, "Config Id: ", config_id)

# handler for service deletion 
def handle_event_del_service(event, authToken):
    eventS = Web3.toJSON(event)
    eventJSON = json.loads(eventS)
    print(eventJSON)
    service_id = str(eventJSON['args']['serviceId'])
    print ("Service Id to be Deleted:",  service_id)
    response = SERVICE_DEL_API(service_id, authToken)


# handler for add service policy 
def handle_event_add_service_policy(event, authToken):
    eventS = Web3.toJSON(event)
    eventJSON = json.loads(eventS)
    print(eventJSON)    
    
    policyId = eventJSON['args']['policyId']
    policyRoleIds = eventJSON['args']['policyRoles'] # may be more than one
    serviceId = eventJSON['args']['policyService']
    serviceProviderId = eventJSON['args']['policyProvider']
    
# get service name using service id form blockchain
    policyRoleNames = []
    for rId in policyRoleIds:
        policyRoleNames.append(roleContract.functions.getFullRoleById(rId).call()[0])
    serviceName = roleContract.functions.getFullServiceById(serviceId).call()[0]
    service_policy_id   = str(policyId)        # from blockchain Event
    policy_name = serviceName                  # from blockchain API
    identity_roles = policyRoleNames           # from blockchain API
    service_ids = [str(serviceId)]             # from blockchain Event
    service_provider_id = [serviceProviderId]  # from blockchain Event

    # Add prefix '@' and '#' to roles
    for idx, iRole in enumerate(identity_roles):
        identity_roles[idx] = '#' + iRole
    for idx, service in enumerate(service_ids):
        service_ids[idx] = '@' + service
    for idx, provider in enumerate(service_provider_id):
        service_provider_id[idx] = '@' + provider

    response1 = SERVICE_POLICY_ADD_DIAL_API(
        service_policy_id + '_dial',
        policy_name + ".svc.dial",
        identity_roles,
        service_ids,
        authToken
    )
    if (response1 != -1):
        print ()
        rows = response1["data"]
        print (rows)

        response2 = SERVICE_POLICY_ADD_BIND_API(
            service_policy_id + '_bind',
            policy_name + ".svc.bind",
            service_provider_id,
            service_ids,
            authToken
        )
        if (response2 != -1):
            rows = response2["data"]
            print (rows)

def handle_event_del_service_policy(event, authToken):
    eventS = Web3.toJSON(event)
    eventJSON = json.loads(eventS)
    print(eventJSON)
    
    service_policy_id = str(eventJSON['args']['policyId'])
    response = SERVICE_POLICY_DEL_API(service_policy_id + '_dial', authToken)
    if (response != -1):
        print ('DAIL policy deleted sucessfully')
        response1 = SERVICE_POLICY_DEL_API(service_policy_id + '_bind', authToken)
        if (response1 != -1):
            print ('BIND policy deleted sucessfully')

def handle_event_del_account(event, authToken):
    eventS = Web3.toJSON(event)
    eventJSON = json.loads(eventS)
    print(eventJSON)
    
    if (eventJSON['args']['accountRemoved'] == True):
        print ( "Identity to be deleted: ",  eventJSON['args']['accountAddress'])
        response = IDENTITY_DELETE_API(eventJSON['args']['accountAddress'], authToken)
        if (response != -1):
            print ('Identity deleted sucessfully')

# general handler for all events
def log_loop_handler(event_filter, event_name, poll_interval):
    print ('STARTED - log_loop_handler - ', event_name )    
    while True:
        for Event in event_filter.get_new_entries():
            print("Event Triggered: ", event_name)
            logging.info( json.loads( Web3.toJSON( Event ))['args'])
            
            authInfo = GET_AUTH_TOKEN()
            authToken = authInfo['authToken']

            match event_name:
                case 'ServiceAdded':
                    handle_event_add_service(Event, authToken)
                case 'ServiceRemoved':
                    handle_event_del_service(Event, authToken)
                case 'PolicyAdded':
                    handle_event_add_service_policy(Event, authToken)
                case 'PolicyRemoved':
                    handle_event_del_service_policy(Event, authToken)
                case 'AccountRemoved':
                    handle_event_del_account(Event, authToken)
                case _:
                    print ('No valid event found')
        time.sleep(poll_interval)
        
def filter_threading(event_filter, filter_name):
        worker = Thread(
            target=log_loop_handler,
            args=(event_filter, filter_name, 12),
            daemon=True)
        worker.start()


# # Ziti API Calls

# In[5]:


import requests
from requests.auth import HTTPBasicAuth
import json
import warnings
warnings.filterwarnings('ignore')


# In[6]:


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


# ## ADD CALLS

# ### ADD SERVICE CALL

# In[7]:


# To add the config
def SERVICE_CONFIG_ADD_API(config_name, config_type_id, address, port, authToken):
    
    APIurl = "https://172.18.102.169:1280/edge/management/v1/configs"
    sessResponse = requests.post(
        APIurl,
        verify = False,
        headers = {"zt-session": authToken, 'Content-Type': 'application/json'},
        json = {
                "encryptionRequired": True,
                "configTypeId": config_type_id,
                "data": { 
                    "addresses": [address],
                    "portRanges": [
                        { "high":port, "low":port }
                        ],
                    "protocols": ["tcp"]
                    },
                "name": config_name
                }
        )
    result = str(sessResponse).split("[")[1][:3]
    if (result == '201'):
        return json.loads(sessResponse.text)["data"]["id"]
    else:
        print ("SERVICE CONFIG VERIFY API error is: ", sessResponse, "\n", sessResponse.text)
        return -1

# To add the service
def SERVICE_ADD_API(service_name, service_block_id, configs_list, authToken):
    
    APIurl = "https://172.18.102.169:1280/edge/management/v1/services"
    sessResponse = requests.post(
        APIurl,
        verify = False,
        headers = {"zt-session": authToken, 'Content-Type': 'application/json'},
        json = {"encryptionRequired": True, "name": service_name,
                'blockId': service_block_id, 'configs': configs_list}
        )
    result = str(sessResponse).split("[")[1][:3]
    if (result == '201'):
        return json.loads(sessResponse.text)
    elif (result == '401'):
        authInfo = GET_AUTH_TOKEN()
        authToken = authInfo['authToken']
        return SERVICE_ADD_API(service_name, service_block_id, configs_list, authToken)
    else:
        print ("ADD SERVICE API error is: ", sessResponse)
        return -1

# ### ADD SERVICE POLICY CALL

# In[8]:


def SERVICE_POLICY_ADD_DIAL_API(policy_id, policy_name, identity_roles, service_ids, authToken):
    
    APIurl = "https://172.18.102.169:1280/edge/management/v1/service-policies"
    sessResponse = requests.post(
        APIurl,
        verify = False,
        headers = {"zt-session": authToken, 'Content-Type': 'application/json'},
        json = {
            'blockId': policy_id,
            'name': policy_name,
            'semantic': "AnyOf",
            'type': "Dial",
            'identityRoles': identity_roles,
            'serviceRoles': service_ids
            }
        )
    result = str(sessResponse).split("[")[1][:3]
    if (result == '201'):
        return json.loads(sessResponse.text)
    elif (result == '401'):
        print ('session problem', sessResponse)
        return -1
    else:
        print ("SERVICE POLICY ADD DIAL API error is: ", sessResponse, "\n", sessResponse.text)
        return -1

def SERVICE_POLICY_ADD_BIND_API(policy_id, policy_name, identity_provider, service_name, authToken):
    
    APIurl = "https://172.18.102.169:1280/edge/management/v1/service-policies"
    sessResponse = requests.post(
        APIurl,
        verify = False,
        headers = {"zt-session": authToken, 'Content-Type': 'application/json'},
        json = {
            'blockId': policy_id,
            'name': policy_name,
            'semantic': "AnyOf",
            'type': "Bind",
            'identityRoles': identity_provider,
            'serviceRoles': service_name
            }
        )
    result = str(sessResponse).split("[")[1][:3]
    if (result == '201'):
        return json.loads(sessResponse.text)
    elif (result == '401'):
        print ('session problem', sessResponse)
        return -1
    else:
        print ("SERVICE POLICY ADD API error is: ", sessResponse.text)
        return -1


# ## DELETE CALLS

# ### DELETE SERVICE CALL

# In[9]:


# for service verification (Addition, Deletition of service and find config Id of provided service Id)
def FIND_CONFIG_ID_BY(service_id, authToken):
    # FALSE verify tag is used to find the service_config_id attached with provided service_id.
    
    APIurl = "https://172.18.102.169:1280/edge/management/v1/services/" + service_id
    sessResponse = requests.get(
        APIurl,
        verify = False,
        headers = {"zt-session": authToken}
        )
    print (sessResponse)
    result = str(sessResponse).split("[")[1][:3]
    if (result == '200'):
        return json.loads(sessResponse.text)
    else:
        print ("VERIFY SERVICE API error is: ", sessResponse)
        return -1

# to delete a serive config using service id
def SERVICE_CONFIG_DEL_API(service_config_id, authToken):
    
    APIurl = "https://172.18.102.169:1280/edge/management/v1/configs/" + service_config_id
    sessResponse = requests.delete(
        APIurl,
        verify = False,
        headers = {"zt-session": authToken},
        )
    result = str(sessResponse).split("[")[1][:3]
    if (result == '200'):
        print ("This service config is sucessfully deleted. The sevice config: ", service_config_id)
        return json.loads(sessResponse.text)
    else:
        print ("SERVICE CONFIG DEL API error is: ", sessResponse, sessResponse.text)
        return -1

# to delete a serive using service id
def SERVICE_DEL_API(service_id, authToken):
    # The attached service config id should be extracted before the deletion of service
    # There is no other way to find which config file is attached with service

    response = FIND_CONFIG_ID_BY(service_id, authToken)
    if  response != -1:
        service_config_id  = response['data']['configs'][0]
        print ("Service Config Id: ", service_config_id)
        
        if SERVICE_CONFIG_DEL_API(service_config_id, authToken) != -1:
            APIurl = "https://172.18.102.169:1280/edge/management/v1/services/" + service_id
            sessResponse = requests.delete(
                APIurl,
                verify = False,
                headers = {"zt-session": authToken},
                )
            result = str(sessResponse).split("[")[1][:3]
            if (result == '200'):
                print ('The service is sucessfully deleted. The service Id is: ', service_id)
                return json.loads(sessResponse.text)
            else:
                print ("SERVICE DEL API error is: ", sessResponse, sessResponse.text)
                return -1
        else:
            print ("SERVICE CONFIG DELETION ERROR")
            return -1
    else:
        print ("SERVICE VERIFY API ERROR")
        return -1


# ### DELETE SERVICE POLICY CALL

# In[10]:


# to delete a serive using service id
def SERVICE_POLICY_DEL_API(service_policy_id, authToken):
    
    APIurl = "https://172.18.102.169:1280/edge/management/v1/service-policies/" + service_policy_id
    sessResponse = requests.delete(
        APIurl,
        verify = False,
        headers = {"zt-session": authToken},
        )
    result = str(sessResponse).split("[")[1][:3]
    if (result == '200'):
        return json.loads(sessResponse.text)
    else:
        print ("API error is: ", sessResponse, sessResponse.text)
        return -1


# ### DELETE IDENTITY CALL

# In[11]:


def IDENTITY_DELETE_API(identity, authToken):
    
    APIurl = "https://172.18.102.169:1280/edge/management/v1/identities/" +  identity
    print ( APIurl )
    sessResponse = requests.delete(
        APIurl,
        verify = False,
        headers = {"zt-session": authToken},
        )
    result = str(sessResponse).split("[")[1][:3]
    if (result == '200'):
        return json.loads(sessResponse.text)
    else:
        print ("API error is: ", sessResponse, sessResponse.text)
        return -1

# ## MAIN FUNCTION

# In[12]:


if __name__ == "__main__":
    
    file = "/home/orchestrator/waleed/APIs_output/blockchian_events.log"
    logging.basicConfig(filename=file, level=logging.INFO)
    print (time.time())
    # service added filter
    service_add_event_filter = roleContract.events.ServiceAdded.createFilter(fromBlock='latest')
    filter_threading(service_add_event_filter, "ServiceAdded")

    # service removed filter
    service_remove_event_filter = roleContract.events.ServiceRemoved.createFilter(fromBlock='latest')
    filter_threading(service_remove_event_filter, 'ServiceRemoved')
    
    # service policy added filter
    policy_add_event_filter = roleContract.events.PolicyAdded.createFilter(fromBlock='latest')
    filter_threading(policy_add_event_filter, 'PolicyAdded')
    
    # # service policy deletion filter
    policy_remove_event_filter = roleContract.events.PolicyRemoved.createFilter(fromBlock='latest')
    filter_threading(policy_remove_event_filter, 'PolicyRemoved')
    
    identity_remove_event_filter = identitycontract.events.AccountRemoved.createFilter(fromBlock='latest')
    filter_threading(identity_remove_event_filter, 'AccountRemoved')
