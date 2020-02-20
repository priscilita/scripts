import requests
import csv
myData = [['name', 'blacklist','country_code','classification','ip']]
#params = {'apikey': 'c1a19808529d6a5b82b346a704ac1094488188b52fbe0b693a802d2fdc2d58ea', 'resource': '099963cf07ba7184ac0079947c2fe607'}
#response = requests.get(api, params=params)
#sha256=response.json()['sha256']
#print(sha256)
ip = '68.62.245.148'

api = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
params = {'apikey': 'c1a19808529d6a5b82b346a704ac1094488188b52fbe0b693a802d2fdc2d58ea', 'ip': ip}
response = requests.get(api, params=params)
json_virustotal = response.json()
whois=json_virustotal['as_owner']
print(whois)

apim = 'https://api.maltiverse.com/ip/' + ip
		#auth_token='72d55285-4adb-4030-acd5-c4be234ab7f7'
response = requests.get(apim)

#	response = requests.get(apim)
json=response.json()

name = whois

if 'blacklist' in json:
	blacklist=(response.json()['blacklist'][0]['description'])
else:
	blacklist='nulo'

if 'country_code' in json:
	country_code=(response.json()['country_code'])
else:
	country_code='nulo'

if 'classification' in json:	
	classification=(response.json()['classification'])
else:
	classification='nulo'

myData.append([name,blacklist,country_code, classification, ip])
myFile = open('ipmaltiverse.csv', 'w')
with myFile:
	writer = csv.writer(myFile)
	writer.writerows(myData)