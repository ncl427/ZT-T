# ZT&T Backend servies and clients
 The IBN Backend Service and client code for the ZT&T

 ## Pre-requisites ##

### Anaconda Environments ###
Properly setup anaconda environments before running the code contained in /src folder. The environments contain the required dependencies for running the python code. The python environments are in the /conda_env/ folder of this repository.
- Import the **ZTAgent.yml** environment on the machines where you plan to run the ZTAgent software.
- Import the **IBN-Backend.yml** environment on the machine where you plan to run the IBN RPC Server.
- Import the **IBN_API.yml** environment on the machine whjere you plan to run the blockchain event handlers.

### Blockchain ###
Be sure to have an Ethereum private blockchain deployed and running, for more details please follow the [Hyperledger Besu guide](https://besu.hyperledger.org/en/stable/private-networks/tutorials/permissioning/onchain/) for deploying a permissioned Blockchain. **FOLLOW THE GUIDE UNTIL BEFORE STEP 11**. This requisite is a must, as the Smart Contracts are coded in Solidity and only compatible with an EVM (Ethereum Virtual Machine) type of Blockchain. The rest of the deployment details are included in the [Installation Manual instructions](InstallationManual-ZTAgent-IBNBackend-IBNGUI.pdf). **IBN MANAGER GUI SECTION**

### READ THE MANUALS FOR INSTALLATION AND RUNNING ###
- [ZTAgent and RPC Server Manual](InstallationManual-ZTAgent-IBNBackend-IBNGUI.pdf)
- [Installation Tools for Monitoring](InstallationManual-Tools.pdf)
