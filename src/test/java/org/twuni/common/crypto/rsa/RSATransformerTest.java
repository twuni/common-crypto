package org.twuni.common.crypto.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class RSATransformerTest {

	private RSATransformer encryptor;
	private RSATransformer decryptor;

	@Before
	public void setUp() {
		RSAPrivateKey privateKey = new RSAPrivateKey( 512 );
		RSAPublicKey publicKey = privateKey.getPublicKey();
		encryptor = new RSATransformer( privateKey );
		decryptor = new RSATransformer( publicKey );
	}

	@Test
	public void testMultipleBlockRoundTrip() throws IOException {

		String expected = generateRandomString( 1234 );
		String actual = new String( decrypt( encrypt( expected.getBytes() ) ) );

		Assert.assertEquals( expected, actual );

	}

	private byte [] decrypt( byte [] message ) throws IOException {
		return decryptor.decrypt( message );
	}

	private byte [] encrypt( byte [] message ) throws IOException {
		return encryptor.encrypt( message );
	}

	private String generateRandomString( int length ) {
		Random random = new Random();
		byte [] buffer = new byte [length];
		random.nextBytes( buffer );
		return new BigInteger( buffer ).toString( 16 );
	}

}
