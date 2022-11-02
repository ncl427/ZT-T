#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import csv
import pyspark
from pyspark.sql import SparkSession
import pyspark.sql.functions as fun
import pandas as pd
from prometheus_client import CollectorRegistry, Gauge, pushadd_to_gateway, Counter, Histogram
import json
from pyspark.sql.types import StructType, StructField, StringType
import prometheus_client

spark = SparkSession.builder.appName('Test1').getOrCreate()

schema1 = StructType([
    StructField("metric_type", StringType(), True),
    StructField("source_id", StringType(), True),
    StructField("metric", StringType(), True),
    StructField("metrics", StringType(), True),
])

schema2 = StructType([
    StructField("count", StringType(), True),
    StructField("m1_rate", StringType(), True),
    StructField("mean_rate", StringType(), True),
])

# Read text from socket
lines = spark     .readStream     .format("socket")     .option("host", "172.18.102.169")     .option("port", 33533)     .load()

# rows that contaoin link keyword
links = lines.filter(
    lines.value.contains("fabric") |
    lines.value.contains("ingress") |
    lines.value.contains("egress") 
)

# convert rows into dataframe based on mentioned schema 1
lines1 = links.select(
    fun.from_json(fun.col("value").cast("string"), schema1).alias("items")
)

# get all columns of dataframe
lines2 = lines1.select(
    fun.col("items.*")
)

# convert json col into dataframe using schema 2
lines3 = lines2.select(
    lines2.metric_type,
    lines2.source_id,
    lines2.metric,
    fun.from_json(fun.col("metrics").cast("string"), schema2).alias("metric_values_col")
)

# attach new cols with previous two columns
lines4 = lines3.select(
    lines3.metric_type,
    lines3.source_id,
    fun.split(lines3.metric, '[\.]', 3).getItem(0).alias('metricTag'),
    fun.regexp_replace(lines3.metric, '[\.]', '_').alias('metricName'),
    fun.col("metric_values_col.*")
)

# merge two cols and rename the 'count' col to 'm_count' to avoid possible keyword error 
lines5 = lines4.select(
    lines4.metric_type,
    fun.concat_ws('_', lines4.source_id, lines4.metricTag).alias('source_id'),
    lines4.metricName,
    fun.col('count').alias('m_count'),
    lines4.mean_rate,
    lines4.m1_rate
)

# function to create prometheus metrics and send metrics to prometheus
def processRow(row):
    registryG = CollectorRegistry()
    if (row.metric_type == 'meter'):
        Gauge(
            row.metricName + "_count", 'The description of count metric', 
            registry=registryG
        ).set(row.m_count),
        
        Gauge(
            row.metricName + "_mean_rate", 'The description of mean_rate metric', 
            registry=registryG
        ).set(row.mean_rate),
        
        Gauge(
            row.metricName + "_m1_rate", 'The description of m1_mean metric', 
            registry=registryG
        ).set(row.m1_rate),
    
        pushadd_to_gateway(
            '172.18.102.66:9091',
            job='zitiFabric',
#             grouping_key={"routerId": row.source_id, "metricName": row.metricName, "type":"gateway"},
            grouping_key={"gatewayId": row.source_id, "instance":"gateway"},
            registry=registryG
        )
    elif (row.metric_type == 'histogram'):
        Gauge(
            row.metricName + "_count", 'The description of count metric', 
            registry=registryG
        ).set(row.m_count),
        
        pushadd_to_gateway(
            '172.18.102.66:9091',
            job='zitiFabric',
#             grouping_key={"routerId": row.source_id, "metricName": row.metricName, "type":"gateway"},
            grouping_key={"gatewayId": row.source_id, "instance":"gateway"},
            registry=registryG
        )
#     .trigger(continuous='1 second') \
query = lines5.writeStream     .outputMode('update')     .format('console')     .option("truncate", "false")     .foreach(processRow)     .start()
query.awaitTermination()


