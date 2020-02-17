import requests
apim = 'https://api.maltiverse.com/ip/103.86.49.11:8080'
auth_token='faaea360-920b-461d-8552-ed06c104846a'
	
		#header = {'Authorization': 'Bearer ' + auth_token,'accept': 'application/json'}

response = requests.get(apim)
print(response.json())
#print(response.json()['as_name'])
#print(response.json()['blacklist'][0]['description'])
#print(response.json()['country_code'])
#print(response.json()['classification'])