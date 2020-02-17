import requests
import csv
myData = [["blacklist", "classification","filename","md5"]]
api = 'https://www.virustotal.com/vtapi/v2/file/report'
params = {'apikey': 'c1a19808529d6a5b82b346a704ac1094488188b52fbe0b693a802d2fdc2d58ea', 'resource': '099963cf07ba7184ac0079947c2fe607'}
response = requests.get(api, params=params)
sha256=response.json()['sha256']
print(sha256)
apim = 'https://api.maltiverse.com/sample/'+sha256
		#auth_token='72d55285-4adb-4030-acd5-c4be234ab7f7'
response = requests.get(apim)
myData.append([response.json()['blacklist'][0]['description'],response.json()['classification'],response.json()['filename'][0], response.json()['md5']])
myFile = open('hashmaltiverse.csv', 'w')
with myFile:
	writer = csv.writer(myFile)
	writer.writerows(myData)