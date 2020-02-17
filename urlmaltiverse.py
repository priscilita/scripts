import requests
import csv
url= 'hxxps://www.bluedream.al/calendar/r83g9/'
has_slash=url[-1:len(url)] in '/'
if has_slash : 
	url=url[0:len(url)-1]
print(url)

url=url.replace('http://www.','').replace('hxxp://www.','').replace('https://www.','').replace('hxxps://www.','').replace('www.','')
print(url)
iv=url.replace('/','-')
print(iv)

myData = [["blacklist", "classification","filename","md5"]]

apim = 'https://api.maltiverse.com/hostname/'+iv
#https://api.maltiverse.com/hostname/divyapushti.org-wp-admin-cmLoLV
		#auth_token='72d55285-4adb-4030-acd5-c4be234ab7f7'
response = requests.get(apim)
print(response.json())
#myData.append([response.json()['blacklist'][0]['description'],response.json()['classification'],response.json()['filename'][0], response.json()['md5']])
#myFile = open('hashmaltiverse.csv', 'w')
#with myFile:
#	writer = csv.writer(myFile)
#	writer.writerows(myData)

#print(response.json())
#print(response.json()['hostname'])
#print(response.json()['blacklist'][0]['description'])
#print(response.json()['classification'])
