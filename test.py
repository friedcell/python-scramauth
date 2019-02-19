# -*- coding: utf-8 -*-
import base64
import hashlib
import unittest
from scramauth import ScramSession, ScramException, ScramClientSession, ScramServerSession

class TestSession(unittest.TestCase):
	def test_get_storage_string(self):
		b64_salt = "VPwa9ikofvY5m3WOeaWT6A=="
		self.assertEqual(
			"{}$4096$sha256:/g9sEYwbJPsA5RZA65D06nCy1WiBFSouIcHboyiVQQI=:9FWdtl8db5WxhbF3O9xroWfkV/X5zPFVT+DEHjQZXMg=".format(b64_salt),
			ScramSession.get_storage_string("pencil", base64.b64decode(b64_salt), 4096)
		)
	
	def test_get_storage_string_digests(self):
		b64_salt = "VPwa9ikofvY5m3WOeaWT6A=="
		self.assertEqual(
			"{}$4096$sha1:/5QpRNn4cMB4foWdkpAX+dNFjgU=:9FiEkyF9rj/iwMxT3yMD2EoCJT0=$sha256:/g9sEYwbJPsA5RZA65D06nCy1WiBFSouIcHboyiVQQI=:9FWdtl8db5WxhbF3O9xroWfkV/X5zPFVT+DEHjQZXMg=".format(b64_salt),
			ScramSession.get_storage_string("pencil", base64.b64decode(b64_salt), 4096, [hashlib.sha1, hashlib.sha256])
		)
	
	def test_pbkdf2(self):
		self.assertEqual(
			b"HZbuOlKbWl+eR8AfIposuKbhX30=", 
			base64.b64encode(ScramSession.pbkdf2("pencil", base64.b64decode("QSXCR+Q6sek8bf92"), 4096, digest=hashlib.sha1))
		)
		self.assertEqual(
			b"qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r+3EZ1rdhVY=",
			base64.b64encode(ScramSession.pbkdf2("pencil", base64.b64decode("QSXCR+Q6sek8bf92"), 4096, digest=hashlib.sha256))
		)
		self.assertEqual(
			b"qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r+3EZ1rdhVY=",
			base64.b64encode(ScramSession.pbkdf2("pencil", base64.b64decode("QSXCR+Q6sek8bf92"), 4096))
		)
		with self.assertRaisesRegex(OverflowError, "dklen too big"):
			ScramSession.pbkdf2("pencil", b"salt", 1, dklen=(2 ** 32) * 32)
	

class TestServer(unittest.TestCase):
	def test_init_error(self):
		stored_data = ScramSession.get_storage_string("pencil", base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ=="), 4096, [hashlib.sha256, hashlib.sha512])
		with self.assertRaisesRegex(ScramException, "Did not find data for digest sha1, only sha256, sha512 available"):
			ScramServerSession(stored_data, digest=hashlib.sha1)
	
	def test_jump_ahead(self):
		stored_data = ScramSession.get_storage_string("pencil", base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ=="), 4096, [hashlib.sha1])
		server = ScramServerSession(stored_data, digest=hashlib.sha1, client_first="n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", nonce="")
		self.assertIsNotNone(server._client_first)
		self.assertIsNotNone(server._server_first)
	
	def test_broken_client_first(self):
		stored_data = ScramSession.get_storage_string("pencil", base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ=="), 4096, [hashlib.sha1])
		with self.assertRaisesRegex(ScramException, "Wrong client_first, unknown gs2 start"):
			ScramServerSession(stored_data, digest=hashlib.sha1, client_first="x,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
	
	def test_unsupported_gs2(self):
		stored_data = ScramSession.get_storage_string("pencil", base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ=="), 4096, [hashlib.sha1])
		with self.assertRaisesRegex(ScramException, "Unsupported gs2 mode"):
			ScramServerSession(stored_data, digest=hashlib.sha1, client_first="p,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
	
	def test_wrong_client_last(self):
		stored_data = ScramSession.get_storage_string("pencil", base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ=="), 4096, [hashlib.sha1])
		server = ScramServerSession(stored_data, digest=hashlib.sha1)
		server._own_nonce = "3rfcNHYJY1ZVvWVs7j"
		server.create_server_first("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
		with self.assertRaisesRegex(ScramException, "Wrong incoming data.*"):
			server.create_server_final("c=biwl,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
		with self.assertRaisesRegex(ScramException, "Wrong incoming data.*"):
			server.create_server_final("c=biws,r=syko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
		with self.assertRaisesRegex(ScramException, "Invalid client proof.*"):
			server.create_server_final("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=x0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
	

class TestClient(unittest.TestCase):
	def test_jump_ahead(self):
		client = ScramClientSession("user", "pencil", digest=hashlib.sha1, nonce="fyko+d2lbbFgONRv9qkxdawL", server_first="r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
		self.assertIsNotNone(client._client_first)
		self.assertIsNotNone(client._server_first)
	
	def test_faulty_server_first(self):
		client = ScramClientSession("user", "pencil", digest=hashlib.sha1, nonce="fyko+d2lbbFgONRv9qkxdawL")
		with self.assertRaisesRegex(ScramException, "Wrong incoming data, nonce does not start with own_nonce.*"):
			client.create_client_final("r=syko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
	
	def test_faulty_server_final(self):
		client = ScramClientSession("user", "pencil", digest=hashlib.sha1, nonce="fyko+d2lbbFgONRv9qkxdawL", server_first="r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
		with self.assertRaisesRegex(ScramException, "Wrong incoming data, validation value not present.*"):
			client.check_server("p=rmF9pqV8S7suAoZWja4dJRkFsKQ=")
		self.assertFalse(client.check_server("v=xmF9pqV8S7suAoZWja4dJRkFsKQ="))
	

class TestExchange(unittest.TestCase):
	def test_sha256(self):
		# Example from RFC 5802
		client = ScramClientSession("user", "pencil", digest=hashlib.sha256)
		client._own_nonce = "rOprNGfwEbeRWgbNEkqO"
		stored_data = ScramSession.get_storage_string("pencil", base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ=="), 4096)
		self.assertEqual("W22ZaJ0SNY7soEsUEjb6gQ==$4096$sha256:WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=", stored_data)
		server = ScramServerSession(stored_data, digest=hashlib.sha256)
		server._own_nonce = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
		
		c1 = client.create_client_first()
		self.assertEqual("n,,n=user,r=rOprNGfwEbeRWgbNEkqO", c1)
		s1 = server.create_server_first(c1)
		self.assertEqual("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096", s1)
		
		c2 = client.create_client_final(s1)
		self.assertEqual("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=", c2)
		s2 = server.create_server_final(c2)
		self.assertEqual("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=", s2)
		
		check = client.check_server(s2)
		self.assertTrue(check)
	
	def test_sha1(self):
		# Example from RFC 5802
		client = ScramClientSession("user", "pencil", digest=hashlib.sha1, nonce="fyko+d2lbbFgONRv9qkxdawL")
		stored_data = ScramSession.get_storage_string("pencil", base64.b64decode("QSXCR+Q6sek8bf92"), 4096, digests=[hashlib.sha1])
		self.assertEqual("QSXCR+Q6sek8bf92$4096$sha1:6dlGYMOdZcOPutkcNY8U2g7vK9Y=:D+CSWLOshSulAsxiupA+qs2/fTE=", stored_data)
		server = ScramServerSession(stored_data, digest=hashlib.sha1, nonce="3rfcNHYJY1ZVvWVs7j")
		self.assertIsNotNone(server._server_key)
		self.assertIsNotNone(server._stored_key)
		self.assertEqual(base64.b64decode(b"QSXCR+Q6sek8bf92"), server._salt)
		self.assertEqual(4096, server._iterations)
		
		c1 = client.create_client_first()
		self.assertEqual("user", client._user)
		self.assertEqual("fyko+d2lbbFgONRv9qkxdawL", client._own_nonce)
		self.assertIsNone(client._nonce)
		self.assertEqual("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", client._client_first)
		self.assertEqual("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", c1)
		
		s1 = server.create_server_first(c1)
		self.assertEqual(c1, server._client_first)
		self.assertEqual("fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j", server._nonce)
		self.assertEqual("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", server._client_first)
		self.assertEqual("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", server._server_first)
		self.assertEqual("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", s1)
		
		c2 = client.create_client_final(s1)
		self.assertEqual(s1, client._server_first)
		self.assertEqual("fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j", client._nonce)
		self.assertEqual(base64.b64decode(b"QSXCR+Q6sek8bf92"), client._salt)
		self.assertEqual(4096, client._iterations)
		self.assertEqual(b"HZbuOlKbWl+eR8AfIposuKbhX30=", base64.b64encode(client.salted_password))
		self.assertEqual(b"4jTEe/bDZpbdbYUrmaqiuiZVVyg=", base64.b64encode(client.client_key))
		self.assertEqual(b"6dlGYMOdZcOPutkcNY8U2g7vK9Y=", base64.b64encode(client.stored_key))
		self.assertEqual("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j", client.client_final_without_proof)
		self.assertEqual(b"n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j", client.auth_message)
		self.assertEqual(b"XXE4xIawv6vfSePi2ovW5cedthM=", base64.b64encode(client.client_signature))
		self.assertEqual("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=", client._client_final)
		self.assertEqual("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=", c2)
		
		s2 = server.create_server_final(c2)
		self.assertEqual(c2, server._client_final)
		self.assertEqual(b"4jTEe/bDZpbdbYUrmaqiuiZVVyg=", base64.b64encode(server.client_key))
		self.assertEqual(b"rmF9pqV8S7suAoZWja4dJRkFsKQ=", base64.b64encode(server.server_signature))
		self.assertEqual("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", server._server_final)
		self.assertEqual("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", s2)
		
		check = client.check_server(s2)
		self.assertEqual(s2, client._server_final)
		self.assertEqual(b"D+CSWLOshSulAsxiupA+qs2/fTE=", base64.b64encode(client.server_key))
		self.assertEqual(b"rmF9pqV8S7suAoZWja4dJRkFsKQ=", base64.b64encode(client.server_signature))
		self.assertTrue(check)
	
	def test_sha1_jump_ahead(self):
		# Example from RFC 5802
		stored_data = ScramSession.get_storage_string("pencil", base64.b64decode("QSXCR+Q6sek8bf92"), 4096, digests=[hashlib.sha1])
		self.assertEqual("QSXCR+Q6sek8bf92$4096$sha1:6dlGYMOdZcOPutkcNY8U2g7vK9Y=:D+CSWLOshSulAsxiupA+qs2/fTE=", stored_data)
		
		client = ScramClientSession("user", "pencil", digest=hashlib.sha1, nonce="fyko+d2lbbFgONRv9qkxdawL")
		c1 = client.create_client_first()
		self.assertEqual("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", c1)
		
		server = ScramServerSession(stored_data, digest=hashlib.sha1, nonce="3rfcNHYJY1ZVvWVs7j")
		s1 = server.create_server_first(c1)
		self.assertEqual("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", s1)
		
		client = ScramClientSession("user", "pencil", digest=hashlib.sha1, nonce="fyko+d2lbbFgONRv9qkxdawL")
		c2 = client.create_client_final(s1)
		self.assertEqual("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=", c2)
		
		server = ScramServerSession(stored_data, digest=hashlib.sha1, nonce="3rfcNHYJY1ZVvWVs7j", client_first=c1)
		s2 = server.create_server_final(c2)
		self.assertEqual("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", s2)
		
		client = ScramClientSession("user", "pencil", digest=hashlib.sha1, nonce="fyko+d2lbbFgONRv9qkxdawL", server_first=s1)
		check = client.check_server(s2)
		self.assertTrue(check)
	
	def test_sha1_process_message(self):
		# Example from RFC 5802
		stored_data = ScramSession.get_storage_string("pencil", base64.b64decode("QSXCR+Q6sek8bf92"), 4096, digests=[hashlib.sha1])
		self.assertEqual("QSXCR+Q6sek8bf92$4096$sha1:6dlGYMOdZcOPutkcNY8U2g7vK9Y=:D+CSWLOshSulAsxiupA+qs2/fTE=", stored_data)
		
		client = ScramClientSession("user", "pencil", digest=hashlib.sha1, nonce="fyko+d2lbbFgONRv9qkxdawL")
		c1 = client.create_client_first()
		self.assertEqual("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", c1)
		
		server = ScramServerSession(stored_data, digest=hashlib.sha1, nonce="3rfcNHYJY1ZVvWVs7j")
		s1 = server.process_client_message(c1)
		self.assertEqual("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", s1)
		
		client = ScramClientSession("user", "pencil", digest=hashlib.sha1, nonce="fyko+d2lbbFgONRv9qkxdawL")
		c2 = client.process_server_message(s1)
		self.assertEqual("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=", c2)
		
		server = ScramServerSession(stored_data, digest=hashlib.sha1, nonce="3rfcNHYJY1ZVvWVs7j", client_first=c1)
		s2 = server.process_client_message(c2)
		self.assertEqual("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", s2)
		
		client = ScramClientSession("user", "pencil", digest=hashlib.sha1, nonce="fyko+d2lbbFgONRv9qkxdawL", server_first=s1)
		check = client.process_server_message(s2)
		self.assertTrue(check)
		
		with self.assertRaisesRegex(ScramException, "Already set up, nothing to do"):
			client.process_server_message("")
		
		with self.assertRaisesRegex(ScramException, "Already set up, nothing to do"):
			server.process_client_message("")
	

if __name__ == '__main__':
	unittest.main()
