import requests
import csv
myData = [['hostname', 'blacklist','classification','domain','ip','tag']]

url= 'https://banco-online30horasatendimentoaocliente.clienteapp.info/30hrs/?id=ODE5OTE0Mjc0OTQ=&hash=e8e2d3b6571a26f441c7c2568234c9db'

p=url.replace('http://www.','').replace('hxxp://www.','').replace('https://','').replace('http://','').replace('https://www.','').replace('hxxps://www.','').replace('www.','')

casi_limpia=p.split('/')
hostname=(casi_limpia[0])


login_api = 'https://api.maltiverse.com/auth/login'
data = {
	"email": "priscila.maldonado@telefonica.com",
	"password": "123456"
}
response = requests.post(login_api, json = data)
token = 'Bearer ' + response.json()['auth_token']

hostname_api = 'https://api.maltiverse.com/bulk/hostname'
data = {
  "hostname": [
      hostname
  ]
}

headers = {'Content-Type': 'application/json', 'Authorization': token}
response = requests.post(hostname_api, json = data, headers=headers)
#print(response.json())
json=response.json()

if 'hostname' in json['hostname'][0]:
	hostname=(response.json()['hostname'][0]['as_name'])


	if 'blacklist' in json['hostname'][0]:
		blacklist=response.json()['hostname'][0]['blacklist'][0]['description']
	else:
		blacklist='nulo'
	if 'classification' in json['hostname'][0]:	
		classification=response.json()['hostname'][0]['classification']
	else:
		classification='nulo'

	if 'domain' in json['hostname'][0]:
		domain=response.json()['hostname'][0]['domain']
	else:
		domain='nulo'

	if 'ip_addr' in json['hostname'][0]['resolved_ip'][0]:	
		ip=response.json()['hostname'][0]['resolved_ip'][0]['ip_addr']
	else:
		ip='nulo'


	if 'tag' in json['hostname'][0]:	
		tag=response.json()['hostname'][0]['tag']
	else:
		tag='nulo'
else:
	hostname='nulo'

#print(response.json()['hostname'][0]['as_name'])
#print(response.json()['hostname'][0]['blacklist'][0]['description'])
#print(response.json()['hostname'][0]['classification'])
#print(response.json()['hostname'][0]['domain'])
#print(response.json()['hostname'][0]['resolved_ip'][0]['ip_addr'])
#print(response.json()['hostname'][0]['tag'])



myData.append([hostname,blacklist,classification,domain,ip,tag])
myFile = open('urlmaltiverse.csv', 'w')
with myFile:
	writer = csv.writer(myFile)
	writer.writerows(myData)