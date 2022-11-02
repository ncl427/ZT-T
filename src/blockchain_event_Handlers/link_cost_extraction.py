#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import csv
import pyspark
from pyspark.sql import SparkSession
import pyspark.sql.functions as fun
import pandas as pd
from prometheus_client import CollectorRegistry, Gauge, pushadd_to_gateway, Counter
import json

import json
import subprocess
import logging
import time

spark = SparkSession.builder.appName('costTest').getOrCreate()

# Read text from socket
lines = spark     .readStream     .format("socket")     .option("host", "172.18.102.169")     .option("port", 44544)     .load()

# rows that contaoin link keyword
links = lines.filter(
    lines.value.contains("tx.bytesrate.m1_rate") & 
    lines.value.contains("link") &
    ~lines.value.contains("pool")
)

# slpit row one by one based on equallity sign (=) to seperate the col name and value
split_link_name_value = links.select(
    fun.split(links.value, '[\=]', 2).alias('metric')
)

# create two columns: first for metric full name and second for metric value
link_metric_name = split_link_name_value.select(
    split_link_name_value.metric.getItem(0).alias('linkMetricName'),
    split_link_name_value.metric.getItem(1).alias('metricValue')
)

# divide the metric name col into link name metric name
split_links_metric = link_metric_name.select(
    fun.split(link_metric_name.linkMetricName, '[\.]', 3).alias('linkMetricName'),
    link_metric_name.metricValue
)

# divide the metric name col into link name metric name amd drop word "link" adn attach link value
link_metric_value = split_links_metric.select(
    split_links_metric.linkMetricName.getItem(1).alias('linkName'),
    split_links_metric.linkMetricName.getItem(2).alias('metricName'),
    fun.round(link_metric_name.metricValue, 0). alias('metricValue')
)


def createLog(linkId, linkCost):
    file = "/home/orchestrator/waleed/APIs_output/test_cost.log"
    logging.basicConfig(filename=file, level=logging.INFO)
    logging.info("*Link ID: " + linkId + " *New Static Cost: " + str(linkCost))

def getStaticCost(row):
    
    cost = int(row.metricValue)
    if (row.metricValue != 0):
        bashCommand = '/home/orchestrator/.ziti/quickstart/orchestrator/ziti-bin/ziti-v0.26.2/ziti fabric update link ' + str(row.linkName) + ' --static-cost ' + str(cost)
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        if (error == None):
            createLog(row.linkName, row.metricValue)

query = link_metric_value.writeStream     .outputMode('update')     .format('console')     .option("truncate", "false")     .foreach(getStaticCost)     .start()
query.awaitTermination()

