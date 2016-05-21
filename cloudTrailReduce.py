#!/usr/bin/env python
from __future__ import print_function

import json
import urllib
import boto3
import os
import gzip
import botocore

cloud_trail_reduce_bucket = 'dev-cloudtrailreduce-uaa' #this is *not* the target bucket for cloud trail log events!
s3resource = boto3.resource( 's3' )
s3client = boto3.client('s3')

def init_policy_template ( cloud_trail_reduce_bucket ):
	exists = True
	try:
		s3resource.Object(cloud_trail_reduce_bucket, 'iam.json').load()
	except botocore.exceptions.ClientError as e:
		if e.response['Error']['Code'] == "404":
			exists = False
		else:
			raise e
	if not exists:
		data = []
		with open('/tmp/iam.json', 'w') as outfile:
			json.dump(data, outfile)
		s3client.upload_file('/tmp/iam.json', cloud_trail_reduce_bucket, 'iam.json')

		
def load_policy_template ( cloud_trail_reduce_bucket ):
	try:
		object = s3resource.Object( cloud_trail_reduce_bucket, 'iam.json' ).download_file( '/tmp/iam.json' )
	except:
		raise Exception('Exception ocurred retrieving current iam.json from S3')
	with open( '/tmp/iam.json' ) as data_file:
		try:
			policy_template = json.load(data_file)
		except:
			raise Exception('Exception ocurred when parsing s3::%s/iam.json to JSON object' % cloud_trail_reduce_bucket )
	return policy_template
	
	
def get_trail_gzip(bucket, key):
	try:
		object = s3resource.Object( bucket, key ).download_file( '/tmp/in.gzip' )
	except:
		raise Exception('Exception ocurred retrieving CloudTrail object S3::%s/%s' % (bucket,key))

		
def extract_trail_gzip():
	try:
		with gzip.open( '/tmp/in.gzip', 'rb' ) as infile:
			with open( '/tmp/out.json', 'w' ) as outfile:
				for line in infile:
					outfile.write( line )
	except:
		raise Exception('Exception ocurred when extacting /tmp/in.gzip /tmp/out.json')

		
def load_trail_records():
	with open( '/tmp/out.json' ) as data_file:
		try:
			trail_json = json.load(data_file)
			records = trail_json['Records']
		except:
			raise Exception('Exception ocurred when parsing /tmp/out.json to JSON object')
	return records
	
	
def munge_record ( record ):
	try:
		event_name = record['eventName']
		event_source = record['eventSource']
		type = record['userIdentity']['type']
		arn = record['userIdentity']['arn']
		if 'root' in arn:
			iamId = 'root'
		else:
			iamId = str(arn).split('/')[1]
	except:
		raise Exception('Exception ocurred when munging record: %s' % ( record ))
	return {'iamId': iamId, 'type': type, 'events': [{'event_name': event_name, 'event_source': event_source}]}


def parse_policy_template ( policy_template, record ):
	match = False
	for existing_record in policy_template:
		if existing_record['iamId'] == record['iamId']:
		    match = True
		    for event in existing_record['events']:
		        if event == record['events'][0]:
		            return policy_template
	            else:
	                existing_record['events'].append(record['events'][0])
	if not match:
		policy_template.append(record)
	return policy_template


def post_policy_template ( policy_template, cloud_trail_reduce_bucket ):
    with open('/tmp/iamOut.json', 'w') as f:
        json.dump(policy_template, f, indent=4)
    s3client.upload_file('/tmp/iamOut.json', cloud_trail_reduce_bucket, 'iam.json')
    

def lambda_handler(event, context):
	init_policy_template ( cloud_trail_reduce_bucket )
	policy_template = load_policy_template ( cloud_trail_reduce_bucket )
	bucket = event['Records'][0]['s3']['bucket']['name']
	
	for record in event['Records']:
		key = urllib.unquote_plus(record['s3']['object']['key']).decode('utf8')
		get_trail_gzip(bucket, key)
		extract_trail_gzip()
		trail_records = load_trail_records()

		for record in trail_records:
			record = munge_record ( record )
			policy_template = parse_policy_template( policy_template, record )
	print ( policy_template )
	post_policy_template ( policy_template, cloud_trail_reduce_bucket )
