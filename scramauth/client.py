import base64
import hashlib
import hmac
from collections import OrderedDict

from .session import ScramException, ScramSession


class ScramClientSession(ScramSession):
	def __init__(self, user, password, digest=hashlib.sha256, nonce=None, server_first=None):
		# init/internal
		self._step = 0
		self._digest = digest
		self._user = user
		self._password = password
		self._own_nonce = nonce or self.get_nonce(24)
		# exchange data
		self._salt = None
		self._iterations = None
		self._nonce = None
		# jump ahead
		if server_first is not None:
			self.create_client_first()
			self.create_client_final(server_first)
	
	def process_server_message(self, message):
		if self._step == 0:
			self.create_client_first()
		if self._step == 1:
			return self.create_client_final(message)
		elif self._step == 2:
			return self.check_server(message)
		else:
			raise ScramException("Already set up, nothing to do")
	
	@property
	def gs2_header(self):
		return ",".join(["n", ""]) + ","
	
	@property
	def client_first_bare(self):
		return ",".join(["n={}".format(self._user), "r={}".format(self._own_nonce)])
	
	@property
	def salted_password(self):
		if not hasattr(self, "_salted_password"):
			self._salted_password = self.pbkdf2(self._password, self._salt, self._iterations, digest=self._digest)
		return self._salted_password
	
	@property
	def client_key(self):
		if not hasattr(self, "_client_key"):
			self._client_key = hmac.new(self.salted_password, b"Client Key", self._digest).digest()
		return self._client_key
	
	@property
	def stored_key(self):
		if not hasattr(self, "_stored_key"):
			self._stored_key = self._digest(self.client_key).digest()
		return self._stored_key
	
	@property
	def server_key(self):
		if not hasattr(self, "_server_key"):
			self._server_key = hmac.new(self.salted_password, b"Server Key", self._digest).digest()
		return self._server_key
	
	def create_client_first(self):
		"""
		Create a client_first message

		:return: str
		"""
		self._step = 1
		self._client_first = self.gs2_header + self.client_first_bare
		return self._client_first
	
	def create_client_final(self, server_first):
		"""
		Create client_final message based on server_first message.

		:param server_first: str
		:return: str
		"""
		self._server_first = server_first
		parts = server_first.split(",")
		received = OrderedDict([tuple(p.split("=", 1)) for i, p in enumerate(parts)])
		if not received["r"].startswith(self._own_nonce):
			raise ScramException("Wrong incoming data, nonce does not start with own_nonce: {}.startswith({})", received["r"], self._own_nonce)
		else:
			self._nonce = received["r"]
			self._salt = base64.b64decode(received["s"])
			self._iterations = int(received["i"])
			self._client_final_without_proof = ",".join([
				"c={}".format(base64.b64encode(self.gs2_header.encode()).decode()),
				"r={}".format(self._nonce)
			])
			client_proof = bytes([a ^ b for (a, b) in zip(self.client_key, self.client_signature)])
			self._client_final = ",".join([self._client_final_without_proof, "p={}".format(base64.b64encode(client_proof).decode())])
			self._step = 2
			return self._client_final
	
	def check_server(self, server_final):
		"""
		Check server validation.

		:param server_final: str
		:return: bool
		"""
		self._server_final = server_final
		parts = server_final.split(",")
		received = OrderedDict([tuple(p.split("=", 1)) for i, p in enumerate(parts)])
		if "v" not in received:
			raise ScramException("Wrong incoming data, validation value not present")
		else:
			if received["v"] == base64.b64encode(self.server_signature).decode("utf-8"):
				self._step = 3
				return True
		return False

