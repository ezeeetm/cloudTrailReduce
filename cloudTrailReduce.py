#!/usr/bin/env python
import boto3
import gzip
import os
import json
from pprint import pprint

bucket_name = 'dev-cloudtrail-uaa'
source_dir = "/home/ubuntu/cloudTrailIn/"
dest_dir = "/home/ubuntu/cloudTrailOut/"
results = {}
global global_results

s3 = boto3.resource( 's3' )
bucket = s3.Bucket( bucket_name )
for key in bucket.objects.all():
	concatKey = ( key.key ).replace( '/','' )
	src_name = '/home/ubuntu/cloudTrailIn/%s' % concatKey
	object = s3.Object( bucket_name, key.key ).download_file( src_name )
	base = os.path.basename( src_name )
	dest_name = os.path.join( dest_dir, base[:-3] )
	with gzip.open( src_name, 'rb' ) as infile:
		with open( dest_name, 'w' ) as outfile:
			for line in infile:
				outfile.write( line )			

	with open( dest_name ) as data_file:
		try:
			cloudTrailIngestionDate = ((dest_name.split('-')[4]).split('_')[1]).split('T')[0]
			data = json.load(data_file)
			records = data['Records']
			for record in records:
				event_name = record['eventName']
				event_source = record['eventSource']
				type = record['userIdentity']['type']
				arn = record['userIdentity']['arn']
				if 'root' in arn:
					iamId = 'root'
				else:
					iamId = str(arn).split('/')[1]
				record_parsed = {'type': type, 'events': [{'event_name': event_name, 'event_source': event_source}]}
				if iamId not in results:
					results[iamId] = record_parsed
					print ( '#########################added iamId: %s from %s' % ( iamId, cloudTrailIngestionDate ) )
					pprint ( record_parsed )
					pprint ( record ) # DEBUG
				else:
					match = False
					for event in results[iamId]['events']:
						if event == record_parsed['events']:
							match = True
							break
					if match:
						break
					else:
						results[iamId]['events'].append(record_parsed['events'][0])
						print( '#########################added EVENT to iamId: %s from %s' % ( iamId, cloudTrailIngestionDate ))
						pprint ( record_parsed['events'])
						pprint ( record ) # DEBUG
				global_results = results 
		except Exception, e:
			print(str(e))	
	try:
		os.chmod( src_name, 777 )
		os.remove( src_name )
		os.chmod( dest_name, 777 )
		os.remove( dest_name )
	except OSError:
		pass
		
with open('/home/ubuntu/results.json', 'w') as f:
    json.dump(global_results, f)
	
	
'''
#!/usr/bin/env python
import boto3
import gzip
import os
import json
from pprint import pprint

bucket_name = 'dev-cloudtrail-uaa'
source_dir = "/home/ubuntu/cloudTrailIn/"
dest_dir = "/home/ubuntu/cloudTrailOut/"
results = {}
global global_results

s3 = boto3.resource( 's3' )
bucket = s3.Bucket( bucket_name )
for key in bucket.objects.all():
	concatKey = ( key.key ).replace( '/','' )
	src_name = '/home/ubuntu/cloudTrailIn/%s' % concatKey
	object = s3.Object( bucket_name, key.key ).download_file( src_name )
	base = os.path.basename( src_name )
	dest_name = os.path.join( dest_dir, base[:-3] )
	with gzip.open( src_name, 'rb' ) as infile:
		with open( dest_name, 'w' ) as outfile:
			for line in infile:
				outfile.write( line )			

	with open( dest_name ) as data_file:
		try:
			cloudTrailIngestionDate = ((dest_name.split('-')[4]).split('_')[1]).split('T')[0]
			data = json.load(data_file)
			records = data['Records']
			for record in records:
				event_name = record['eventName']
				event_source = record['eventSource']
				type = record['userIdentity']['type']
				arn = record['userIdentity']['arn']
				if 'root' in arn:
					iamId = 'root'
				else:
					iamId = str(arn).split('/')[1]
				record_parsed = {'type': type, 'events': [{'event_name': event_name, 'event_source': event_source}]}
				if iamId not in results:
					results[iamId] = record_parsed
					print ( '#########################added iamId: %s from %s' % ( iamId, cloudTrailIngestionDate ) )
					pprint ( record_parsed )
					pprint ( record ) # DEBUG
				else:
					match = False
					for event in results[iamId]['events']:
						if event == record_parsed['events']:
							match = True
							break
					if match:
						break
					else:
						results[iamId]['events'].append(record_parsed['events'][0])
						print( '#########################added EVENT to iamId: %s from %s' % ( iamId, cloudTrailIngestionDate ))
						pprint ( record_parsed['events'])
						pprint ( record ) # DEBUG
				global_results = results 
		except Exception, e:
			print(str(e))	
	try:
		os.chmod( src_name, 777 )
		os.remove( src_name )
		os.chmod( dest_name, 777 )
		os.remove( dest_name )
	except OSError:
		pass
		
with open('/home/ubuntu/results.json', 'w') as f:
    json.dump(global_results, f)
'''
