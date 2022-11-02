## Read Me ##

## Create required schemas ##
provide the schema in which structure the stream will be collected 

## Session creation to read stream ##
create a session object using pyspark library 
Provide host and port to session object and activate read stream option

## filter and extract the metrics ##
filter the "link" metrics from streaming data using mysql spark library

## send to prometheus pushgateway ##
send the "link" metrics to pushGateway for storing them
