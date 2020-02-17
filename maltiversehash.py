import urllib.request
import requests
import time
import re
import webbrowser
import csv
contents = urllib.request.urlopen("https://portal.cci-entel.cl/Threat_Intelligence/Boletines/487/").read().decode('utf-8')

urls = re.findall( r'href="([^"]*)', contents)
#print(urls)

prefijo = "www.virustotal.com/#/search/"

lista_limpia = list(filter(lambda url: prefijo in url, urls))

lista_ips = list(filter(lambda url: re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",url.replace(prefijo,"")), lista_limpia))

#print(lista_ips)

#from selenium import webdriver
#driver = webdriver.PhantomJS()

#MAC
#chrome_path = 'open -a /Applications/Google\ Chrome.app %s'
api = 'https://api.maltiverse.com'
contador =0 
tipo = ''


myData = [["hash", "blacklist", "classification","filename","md5"]]


for url in lista_limpia[0:1]:
	info = url.replace('https://www.virustotal.com/#/search/','')
	print(info)
	if (info.startswith('https') or info.startswith('http') or info.startswith('hxxps') or info.startswith('hxxp')):
		tipo ='url'
	else :
		if '.' in info:
			tipo ='ip'
		else :
			tipo = 'hash'
	
	print(tipo)

	if tipo == 'hash':
		apim = 'https://api.maltiverse.com/sample/'+info
		auth_token='72d55285-4adb-4030-acd5-c4be234ab7f7'
		response = requests.get(apim)
		print(response.json())
		print(response.json()['blacklist'][0]['description'])
		print(response.json()['classification'])
		print(response.json()['filename'])
		print(response.json()['md5'])

		#myData.append([response.json()['md5'],response.json()['positives']])
		#myFile = open('maltiversehash.csv', 'w')
		#with myFile:
		#	writer = csv.writer(myFile)
		#	writer.writerows(myData)

		#print(response.json()['md5'])
		#print(response.json()['positives'])
		#contador = contador + 1
	
	#if contador%4==0:
	#	time.sleep(60)
	#if tipo == 'ip':
		#info = url.replace('ip','')
	#	apim = 'https://api.maltiverse.com/ip/'+info
	#	print(apim)
	#	auth_token='72d55285-4adb-4030-acd5-c4be234ab7f7'
	
		#header = {'Authorization': 'Bearer ' + auth_token,'accept': 'application/json'}

	#	response = requests.get(apim)
	#	print(response.json()['as_name'])
	#	print(response.json()['blacklist'][0]['description'])
	#	print(response.json()['country_code'])
	#	print(response.json()['classification'])
