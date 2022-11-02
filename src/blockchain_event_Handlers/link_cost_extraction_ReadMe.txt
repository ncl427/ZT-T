## Read Me ##

## Session creation to read stream ##
create a session object using pyspark library 
Provide host and port to session object and activate read stream option

## filter and extract the metrics ##
filter the metrics from streaming data using mysql spark library

## update the ziti link cost according to metrics results
calculate new cost value based on collected metrics
call the ziti bash command to update the ziti link with the new cost value 
push new metric value to logs
