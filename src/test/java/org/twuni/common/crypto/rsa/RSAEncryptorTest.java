package org.twuni.common.crypto.rsa;

import java.security.SecureRandom;

import org.junit.Assert;
import org.junit.Test;

public class RSAEncryptorTest {

	@Test
	public void testSomeCoolStuff() {

		RSAPrivateKey privateKey = new RSAPrivateKey( 2048, new SecureRandom() );
		RSAPublicKey publicKey = privateKey.getPublicKey();

		RSAEncryptor encryptor = new RSAEncryptor( publicKey.getModulus() );
		RSADecryptor decryptor = new RSADecryptor( publicKey.getModulus() );

		String expected = "This is a good test.";
		byte [] encrypted = encryptor.transform( privateKey, expected.getBytes() );
		String actual = new String( decryptor.transform( publicKey, encrypted ) );

		Assert.assertEquals( expected, actual );

	}

}
