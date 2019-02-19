import base64
import hashlib
from collections import OrderedDict

from .session import ScramException, ScramSession


class ScramServerSession(ScramSession):
	def __init__(self, storage_string, digest=hashlib.sha256, nonce=None, client_first=None):
		parts = storage_string.split("$")
		# init/internal
		self._step = 0
		self._digest = digest
		self._salt = base64.b64decode(parts.pop(0))
		self._iterations = int(parts.pop(0))
		self._own_nonce = nonce or self.get_nonce(24)
		# from storage
		parsed_digests = self.process_storage_string(parts)
		self._stored_key, self._server_key = parsed_digests.get(digest().name, (None, None))
		if not self._stored_key or not self._server_key:
			raise ScramException("Did not find data for digest {}, only {} available".format(digest().name, ", ".join(sorted(parsed_digests.keys()))))
		# exchange data
		self._gs2_header = None
		self._nonce = None
		# jump ahead
		if client_first is not None:
			self.create_server_first(client_first)
	
	@property
	def gs2_header(self):
		return self._gs2_header
	
	@property
	def client_key(self):
		return self._client_key
	
	@property
	def stored_key(self):
		return self._stored_key
	
	@property
	def server_key(self):
		return self._server_key
	
	def get_client_key(self, client_proof):
		return bytes(a ^ b for a, b in zip(client_proof, self.client_signature))
	
	@classmethod
	def process_storage_string(cls, digest_list):
		"""
		Parse parts made by get_storage_keys

		:param digest_list: iterable of get_storage_keys results 
		:return: dict(digest name, data tuple)
		"""
		r = {}
		for p in digest_list:
			digest_name, stored_key, server_key = p.split(":")
			r[digest_name] = (
				base64.b64decode(stored_key),
				base64.b64decode(server_key)
			)
		return r
	
	def process_client_message(self, message):
		"""
		Generic method to process incoming message, decides what to do based on internal data.

		:param message: str
		:return: str
		"""
		if self._step == 0:
			return self.create_server_first(message)
		elif self._step == 1:
			return self.create_server_final(message)
		else:
			raise ScramException("Already set up, nothing to do")
	
	def create_server_first(self, client_first):
		"""
		Prepare server_first message based on client_first.

		:param client_first: str
		:return: str
		"""
		if client_first[0] not in {"n", "p", "y"}:
			raise ScramException("Wrong client_first, unknown gs2 start")
		parts = client_first.split(",")
		data = OrderedDict()
		if parts[0] == "n" and parts[1] == "":
			self._client_first = client_first
			self._gs2_header = ",".join(parts[0:2]) + ","
			received = OrderedDict([tuple(p.split("=", 1)) for i, p in enumerate(parts) if i > 1])
			self._nonce = received["r"] + self._own_nonce
			data["r"] = self._nonce
			data["s"] = base64.b64encode(self._salt).decode("utf-8")
			data["i"] = self._iterations
			self._server_first = ",".join(["{0}={1}".format(*t) for t in data.items()])
			self._step = 1
			return self._server_first
		else:
			raise ScramException("Unsupported gs2 mode")
	
	def create_server_final(self, client_final):
		"""
		Prepare the server_final message based on client_final.

		If client does not verify properly, raises SCRAMException

		:param client_final: str
		:return: str
		"""
		self._client_final = client_final
		parts = client_final.split(",")
		received = OrderedDict([tuple(p.split("=", 1)) for i, p in enumerate(parts)])
		encoded_gs2_header = base64.b64encode(self.gs2_header.encode("utf-8")).decode("utf-8")
		if received["c"] != encoded_gs2_header:
			raise ScramException("Wrong incoming data: {} != {}", received["c"], encoded_gs2_header)
		elif received["r"] != self._nonce:
			raise ScramException("Wrong incoming data: {} != {}", received["r"], self._nonce)
		else:
			client_proof = base64.b64decode(received["p"])
			self._client_key = self.get_client_key(client_proof)
			stored_key = self._digest(self._client_key).digest()
			if stored_key == self.stored_key:
				self._server_final = "v={}".format(base64.b64encode(self.server_signature).decode("utf-8"))
				self._step = 2
				return self._server_final
			else:
				raise ScramException("Invalid client proof {} != {}", stored_key, self.stored_key)
	
