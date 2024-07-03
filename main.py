import re
import requests
import urllib3
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)


def send_request(method, ip, path):
	try:
		res = requests.get(
			url = f'{method}://{ip}/{path}',
			timeout=(3.0, 7.5),
			verify=False
		)
		return res.status_code, len(res.content), f'{method}://{ip}/{path}'
	except requests.RequestException as e:
		return None, None, f'{method}://{ip}/{path}'

def scan(ip):
	fuzz = [
		"wp-json/wp/v2/users",
		".htaccess",
		".DS_Store",
		"xmlrpc.php",
		".git/logs/HEAD",
		"web.config",
		"test.php",
		"icons/"
	]
	methods = ['http', 'https']
		
	with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
		future_to_url = {
			executor.submit(send_request, method, ip, path): (method, path)
			for path in fuzz
			for method in methods
		}
		
		for future in concurrent.futures.as_completed(future_to_url):
			method, path = future_to_url[future]
			try:
				status_code, content_len, url = future.result()
				if status_code == 200:
					print(f'{status_code}\t{content_len}\t{url}')
			except Exception as exc:
				print(f'{method}://{ip}/{path} generated an exception: {exc}')


with open('linebiz.html', 'r') as f:
	data = f.read().split('\n')

for i in data:
	if "https://www.shodan.io/host/" in i:
		# ip address 
		ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', i)
		scan(ip[0])