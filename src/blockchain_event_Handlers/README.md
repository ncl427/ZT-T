# Read Me #

## Main Function ##
The main function creates the thread for each filter.
The filter are "Service Added", "Service Removed", "Policy Added", "Policy Removed" and "Identity Removed"

## log loop handler ##
There is a event catcher that catches the events and calls the respective function based on event it catches

## event handler ##
There are event handler for each of these filter
These event handler extracts the information from the Intent and forwards the extracted infromation to Ziti APIs

## Ziti APIs ##
The Ziti APIs deployed the Intent information on the Ziti.

