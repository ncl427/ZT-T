### Read Me ###

## Main Function ##
configure the log file for logging
create a filter to detect transfer of an event

## log loop handler ##
There is a event catcher that catches the "Token Transfer" event and calls the "event handler" function

## event handler ##
Extracts the Intent information and create the counter based on expiry time.
when token expires it calls the IBN to remove the token
