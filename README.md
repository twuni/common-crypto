Public-Key Cryptography
=======================

Sample Code
-----------

Let's start with a simple message:

	String message = "Hello, world!";

To generate a new 4096-bit private key:
	
	PrivateKey privateKey = new KeyGenerator().generate( 4096 );

To encrypt the `message`:

	String encrypted = new Transformer( privateKey ).encrypt( message );

For decryption, you will need the public key:

	PublicKey publicKey = privateKey.getPublicKey();

To decrypt the `encrypted` string:

	String decrypted = new Transformer( publicKey ).decrypt( encrypted );
