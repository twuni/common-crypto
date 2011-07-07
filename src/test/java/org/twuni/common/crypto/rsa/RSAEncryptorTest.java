package org.twuni.common.crypto.rsa;

import java.security.SecureRandom;

import org.junit.Assert;
import org.junit.Test;
import org.twuni.common.crypto.InputLengthException;

public class RSAEncryptorTest {

	@Test
	public void testSingleBlockRoundTripFromPrivateKeySucceedsWhenInputLengthMatchesBlockSize() {

		String expected = "This is a good test. I approve of it.";

		RSAPrivateKey privateKey = new RSAPrivateKey( expected.length() * 8, new SecureRandom() );
		RSAPublicKey publicKey = privateKey.getPublicKey();

		RSAEncryptor encryptor = new RSAEncryptor( publicKey.getModulus() );
		RSADecryptor decryptor = new RSADecryptor( publicKey.getModulus() );

		byte [] encrypted = encryptor.transform( privateKey, expected.getBytes() );
		String actual = new String( decryptor.transform( publicKey, encrypted ) );

		Assert.assertEquals( expected, actual );

	}

	@Test
	public void testSingleBlockRoundTripFromPublicKeySucceedsWhenInputLengthMatchesBlockSize() {

		String expected = "This is a good test. I approve of it.";

		RSAPrivateKey privateKey = new RSAPrivateKey( expected.length() * 8, new SecureRandom() );
		RSAPublicKey publicKey = privateKey.getPublicKey();

		RSAEncryptor encryptor = new RSAEncryptor( publicKey.getModulus() );
		RSADecryptor decryptor = new RSADecryptor( publicKey.getModulus() );

		byte [] encrypted = encryptor.transform( publicKey, expected.getBytes() );
		String actual = new String( decryptor.transform( privateKey, encrypted ) );

		Assert.assertEquals( expected, actual );

	}

	@Test( expected = InputLengthException.class )
	public void testSingleBlockEncryptionFailsWhenInputLengthIsMoreThanBlockSize() {

		String expected = "This is a good test. I approve of it.";

		RSAPrivateKey privateKey = new RSAPrivateKey( ( expected.length() - 1 ) * 8, new SecureRandom() );
		RSAPublicKey publicKey = privateKey.getPublicKey();

		RSAEncryptor encryptor = new RSAEncryptor( publicKey.getModulus() );

		encryptor.transform( privateKey, expected.getBytes() );

	}

	@Test
	public void testSingleBlockRoundTripSucceedsWhenInputLengthIsLessThanBlockSize() {

		String expected = "This is a good test. I approve of it.";

		RSAPrivateKey privateKey = new RSAPrivateKey( ( expected.length() + 1 ) * 8, new SecureRandom() );
		RSAPublicKey publicKey = privateKey.getPublicKey();

		RSAEncryptor encryptor = new RSAEncryptor( publicKey.getModulus() );
		RSADecryptor decryptor = new RSADecryptor( publicKey.getModulus() );

		byte [] encrypted = encryptor.transform( publicKey, expected.getBytes() );
		String actual = new String( decryptor.transform( privateKey, encrypted ) );

		Assert.assertEquals( expected, actual );

	}

}
