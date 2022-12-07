# Read Me #

## RPC Server ##
It is the backend for the IBN operations that communicate with the blockchain and overlay network. It provides APIs to the ZTAgent for clients/providers to be able to interact with the Zero Trust Network.
The **RPCServerLINUX.py** should be run on a Linux PC and contains the latest version of the code for the IBN Backend. . The python file is an executable code. It is recomended to run a python enviroment such as Anaconda to run these files. 

## ZTA Agent##
The software for interaction with the Zero Trust Network. There are **Windows** and **Linux** versions of this Agent along **Client** and **Provider** versions (Apply different workflows). The python file is an executable code. It is recomended to run a python enviroment such as Anaconda to run these files.
This python code should be run on endpoints who whish to have access to a Zero Trust network.

## Blockchain Event Handlers ##
Background process for event filters and handlers that listen for blockchain events.

## Javascript code ##
Used by both ZTAgent and RPC Server as helper functionality for encryption and decryption.

(Cleaning up is required on this folder)


### If you have errors related to the Javascript functions ###
*secp256k1 unavailable, reverting to browser version*
Please run the noSECP256 versions of the python files.
