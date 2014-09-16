import requests, json, logging, sys

class PassiveTotal:
	def __init__(self, apikey):
		
		self.__apikey = apikey
		
		self.__classifications = [ 'targeted', 'crime', 'benign', 'multiple' ]
		self.__actions = [ 'add', 'remove' ]
		
		self.__endpoint = 'https://www.passivetotal.org/api/'
		
		self.__logger = logging.getLogger('PassiveTotal')
		
	def setLogging(self, level):
		logger = logging.getLogger('PassiveTotal')
		if level == "INFO":
			logger.setLevel(logging.INFO)
		elif level == "WARN":
			logger.setLevel(logging.WARN)
		elif level == "DEBUG":
			logger.setLevel(logging.DEBUG)
		elif level == "ERROR":
			logger.setLevel(logging.ERROR)
		else:
			pass
		format = logging.Formatter('\033[1;32m%(levelname)-5s %(module)s:%(funcName)s():%(lineno)d %(asctime)s\033[0m| %(message)s')
		shandler = logging.StreamHandler(sys.stdout)
		shandler.setFormatter(format)
		logger.addHandler(shandler)
		return logger
		
	def classify(self, value, classification):
		url = self.__endpoint + 'classify'
		if classification.lower() not in self.__classifications:
			raise Exception("%s is not a valid classification type. Use %s." % ( classification, str(self.__classifications) ) )
		
		params = { 'apikey': self.__apikey, 'classification': classification.lower(), 'value': value }
		response = requests.post(url, params=params)
		self.__logger.debug("Response %d: %s %s" % (response.status_code, url, str(params)))
		if response.status_code == 200:
			return json.loads(response.content)
		else:
			self.__logger.error('Query failed: %s' % response.content)
			raise Exception('Query failed')
	
	def tag(self, value, tag, action):
		if action.lower() not in self.__actions:
			raise Exception("%s is not a valid tag action. Use %s." % ( action, str(self.__actions) ) )
		
		if action.lower() == 'add':
			url = self.__endpoint + 'tag/add'
		else:
			url = self.__endpoint + 'tag/remove'
		
		params = { 'apikey': self.__apikey, 'tag': tag, 'value': value }
		response = requests.post(url, params=params)
		self.__logger.debug("Response %d: %s %s" % (response.status_code, url, str(params)))
		if response.status_code == 200:
			return json.loads(response.content)
		else:
			self.__logger.error('Query failed: %s' % response.content)
			raise Exception('Query failed')
	
	def search(self, value):
		url = self.__endpoint + 'passive'
		params = { 'apikey': self.__apikey, 'value': value }
		response = requests.post(url, params=params)
		self.__logger.debug("Response %d: %s %s" % (response.status_code, url, str(params)))
		if response.status_code == 200:
			return json.loads(response.content)
		else:
			self.__logger.error('Query failed: %s' % response.content)
			raise Exception('Query failed')