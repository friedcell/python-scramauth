import base64
import hashlib
import hmac
import os


class ScramException(Exception):
	pass
	

class ScramSession():
	@classmethod
	def generate_nonce(cls):
		"""
		Return a long enough random blurb
		
		:return: bytes
		"""
		return os.urandom(64)
	
	@classmethod
	def get_storage_string(cls, password, salt, iterations, digests=None):
		"""
		Return a string you can store in the database based on password, salt and iteration count.
		
		You can pass multiple digests. Older RFCs require support of SHA1, but I really wouldn't, so default is sha256 only.
		
		Digest data is result of get_storage_keys.
		
		String is of format:
		[b64 encoded salt]$[iteration count]$[digest 1 data]($[digest N data])
		
		:param password: str
		:param salt: bytes
		:param iterations: int
		:param digests: iterable
		:return: str
		"""
		if digests is None:
			digests = [hashlib.sha256]
		parts = [base64.b64encode(salt).decode("utf-8"), str(iterations)]
		for h in digests:
			parts.append(cls.get_storage_keys(password, salt, iterations, h))
		return "$".join(parts)
	
	@classmethod
	def get_storage_keys(cls, password, salt, iterations, digest):
		"""
		Return a : separated string with digest name, base64 encoded stored key and base64 encoded server key
		
		:param password: str
		:param salt: bytes
		:param iterations: int
		:param digest: hashlib algorithm constructor
		:return: str
		"""
		salted_password = cls.pbkdf2(password, salt, iterations, digest=digest)
		client_key = hmac.new(salted_password, b"Client Key", digest).digest()  # 4jTEe/bDZpbdbYUrmaqiuiZVVyg=
		stored_key = digest(client_key).digest()  # 6dlGYMOdZcOPutkcNY8U2g7vK9Y=
		server_key = hmac.new(salted_password, b"Server Key", digest).digest()  # D+CSWLOshSulAsxiupA+qs2/fTE='
		return ":".join([digest().name, base64.b64encode(stored_key).decode("utf-8"), base64.b64encode(server_key).decode("utf-8")])
	
	@classmethod
	def pbkdf2(cls, password, salt, iterations, dklen=0, digest=None):
		"""
		Return a pbkdf2 value based on inputs
		
		:param password: str
		:param salt: str/bytes
		:param iterations: int
		:param dklen: int
		:param digest: hashlib algorithm constructor
		:return: bytes
		"""
		if digest is None:
			digest = hashlib.sha256
		if not dklen:
			dklen = None
		elif dklen > (2 ** 32 - 1) * 32:
			raise OverflowError("dklen too big")
		password = password.encode("utf-8") if isinstance(password, str) else password
		salt = salt.encode("utf-8") if isinstance(salt, str) else salt
		return hashlib.pbkdf2_hmac(digest().name, password, salt, iterations, dklen)
	
	@classmethod
	def get_nonce(self, l):
		"""
		Return a base64 encoded nonce of specific length.
		
		:param l: int
		:return: str
		"""
		return base64.b64encode(self.generate_nonce()).decode("utf-8").strip("=")[0:l]
	
	@property
	def client_first_bare(self):
		return ",".join(self._client_first.split(",")[2:])
	
	@property
	def client_final_without_proof(self):
		if hasattr(self, "_client_final_without_proof"):
			return self._client_final_without_proof
		return ",".join([p for p in self._client_final.split(",") if not p.startswith("p=")])
	
	@property
	def auth_message(self):
		if not hasattr(self, "_auth_message"):
			self._auth_message = ",".join([
				self.client_first_bare,
				self._server_first,
				self.client_final_without_proof
			]).encode("utf-8")
		return self._auth_message
	
	@property
	def client_signature(self):
		return hmac.new(self.stored_key, self.auth_message, self._digest).digest()
	
	@property
	def server_signature(self):
		return hmac.new(self.server_key, self.auth_message, self._digest).digest()
	
