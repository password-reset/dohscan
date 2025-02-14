import argparse
import requests
import json
import socket
from urllib.parse import urljoin
import urllib3

#urllib3.disable_warnings()

def resolve_host(host):
	try:
		return socket.gethostbyname(host)
	except socket.gaierror:
		print(f"[-] Could not resolve {host}")
		return None

def check_doh(target):
	ip = resolve_host(target) if not target.replace('.', '').isdigit() else target
	if not ip:
		return

	headers = {'Content-Type': 'application/dns-message', 'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"}
	paths = ['/dns-query', '/doh', '/dns', '/resolve']

	for path in paths:
		base_url = f"https://{ip}"
		doh_url = urljoin(base_url, path)

		# Example DNS query in wire format for "www.google.com"
		# Transaction ID: 0x0001, Flags: Standard Query, Questions: 1, Answer RRs: 0
		# Authority RRs: 0, Additional RRs: 0, Query: www.google.com, Type: A, Class: IN
		query_data = bytes.fromhex(
			'0001' # Transaction ID
			'0000' # Flags (Standard Query)
			'0001' # Questions: 1
			'0000' # Answer RRs: 0
			'0000' # Authority RRs: 0
			'0000' # Additional RRs: 0
			'03777777' # 'www'
			'06676f6f676c65' # 'google'
			'03636f6d' # 'com'
			'00' # End of QNAME
			'0001' # Type: A
			'0001' # Class: IN
		)

		try:
			# check GET
			get_url = f"{doh_url}?dns={query_data.hex()}"
			get_response = requests.get(get_url, headers=headers, timeout=5, verify=True)
			print(get_response.text)
			if get_response.status_code == 200:
				print(f"[+] {target} ({ip}) accepts DoH queries via GET at {doh_url}")
				return True

			# check POST
			post_response = requests.post(doh_url, headers=headers, data=query_data, timeout=5, verify=True)
			print(post_response.text)
			if post_response.status_code == 200:
				print(f"[+] {target} ({ip}) accepts DoH queries via POST at {doh_url}")
				return True
		except requests.exceptions.RequestException as e:
			pass

	print(f"[-] {target} ({ip}) does not respond to DoH queries")
	return False


if __name__ == "__main__":

	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--ip', type=str, help="ip or hostname")
	parser.add_argument('-f', '--file', type=str, help="file containing ips or hostnames")

	args = parser.parse_args()

	if args.ip:
		check_doh(args.ip)
	elif args.file:
		with open(args.file, 'r') as f:
			targets = [line.strip() for line in f if line.strip()]
			for target in targets:
				check_doh(target)
	else:
		print("Provide an IP address, hostname, or a file with a list of targets.")
