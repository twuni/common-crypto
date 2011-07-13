package org.twuni.common.crypto.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TransformerTest {

	private static final String EXPECTED = "This is a great place to sit and watch the stars on a moonless night. Have you ever considered gazing upon such celestial magnificence while resting your weary head on a pillow made of glass? No, of course you haven't.";

	private Transformer trusted;
	private Transformer untrusted;

	@Before
	public void setUp() {
		PrivateKey privateKey = new KeyGenerator().generate( 512 );
		PublicKey publicKey = privateKey.getPublicKey();
		trusted = new Transformer( privateKey );
		untrusted = new Transformer( publicKey );
	}

	@Test
	public void testMultipleBlockRoundTrip() throws IOException {

		String expected = generateRandomString( 1234 );
		String actual = new String( decrypt( encrypt( expected.getBytes() ) ) );

		Assert.assertEquals( expected, actual );

	}

	@Test
	public void testMultipleBlockRoundTripByteArray() throws IOException {

		byte [] expected = generateRandomBytes( 4096 );
		byte [] actual = decrypt( encrypt( expected ) );

		Assert.assertArrayEquals( expected, actual );

	}

	private byte [] decrypt( byte [] message ) throws IOException {
		return untrusted.decrypt( message );
	}

	private byte [] encrypt( byte [] message ) throws IOException {
		return trusted.encrypt( message );
	}

	private String generateRandomString( int length ) {
		return new BigInteger( generateRandomBytes( length ) ).toString( 16 );
	}

	private byte [] generateRandomBytes( int length ) {
		Random random = new Random();
		byte [] buffer = new byte [length];
		random.nextBytes( buffer );
		return buffer;
	}

}
