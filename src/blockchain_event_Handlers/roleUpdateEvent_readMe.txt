### Read Me ###

## Main Function ##
configure the log file for logging
create a filter to detect "Role update" event

## log loop handler ##
There is a event catcher that catches the "update roles" event and calls the "event handler" function

## event handler ##
Extract the infromation from intent 
find the role names based on role ids
forwards the intent information to ziti

## ziti APIs ##
update the roles on ziti

