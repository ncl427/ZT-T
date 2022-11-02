#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import csv
import pyspark
from pyspark.sql import SparkSession
import pyspark.sql.functions as fun
import pandas as pd
from prometheus_client import CollectorRegistry, Gauge, pushadd_to_gateway, Counter

spark = SparkSession.builder.appName('Test2').getOrCreate()

# Read text from socket
lines = spark     .readStream     .format("socket")     .option("host", "172.18.102.169")     .option("port", 11511)     .load()

# rows that contaoin link keyword
links = lines.filter(
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
    link_metric_name.metricValue
)

# create schems for string type columns
rows = link_metric_value.select(
    link_metric_value.linkName,
    fun.regexp_replace(link_metric_value.metricName, '[\.]', '_').alias('metricName'),
    link_metric_value.metricValue
)

# function to create prometheus metrics and send metrics to prometheus
def processRow(row):
    registryG = CollectorRegistry()
    Gauge(
        row.metricName, 'The description of metric', 
        registry=registryG
    ).set(row.metricValue),

    pushadd_to_gateway(
        '172.18.102.66:9091',
        job='zitiFabric',
        grouping_key={"instance": "link", "link_name": row.linkName},
        registry=registryG
    )

query = rows.writeStream     .outputMode('update')     .format('console')     .option("truncate", "false")     .foreach(processRow)     .start()
query.awaitTermination()






