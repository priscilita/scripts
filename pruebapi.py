import requests
import csv
myData = [['name', 'blacklist','country_code','classification']]
#params = {'apikey': 'c1a19808529d6a5b82b346a704ac1094488188b52fbe0b693a802d2fdc2d58ea', 'resource': '099963cf07ba7184ac0079947c2fe607'}
#response = requests.get(api, params=params)
#sha256=response.json()['sha256']
#print(sha256)
api = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
params = {'apikey': 'c1a19808529d6a5b82b346a704ac1094488188b52fbe0b693a802d2fdc2d58ea', 'ip': '68.62.245.148'}
response = requests.get(api, params=params)
#print(response.json())

	#[0]['date'],['resolutions'][1]['positives'])
#print(response.json()['detected_communicating_samples'])

#print(response.json()['verbose_msg'])
#print(response.json()['detected_downloaded_samples'])
#print(response.json()['detected_urls'])
print(response.json()['as_owner'])
print(response.json()['country'])
#lista_url=(response.json()['detected_urls'])

#if len(lista_url) > 0 :
#	for url in lista_url:
#		url_relacionada=url['url']
#		positivos=url['positives']
#		total=url['total']
#		scan_date=url['scan_date']
#		print(url_relacionada +' '+str(positivos) +' ' +str(total) +' '+scan_date)
print(response.json()['detected_downloaded_samples'])
#if len(lista_samples) > 0 :
#	for hashs in lista_samples:
#		date=hashs['date']
#		positivos=hashs['positives']
#		total=hashs['total']
#		sha256=hashs['sha256']
#		print(date +' '+str(positivos) +' ' +str(total) +' '+sha256)


