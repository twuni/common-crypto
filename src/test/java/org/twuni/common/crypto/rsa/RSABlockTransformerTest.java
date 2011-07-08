package org.twuni.common.crypto.rsa;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.twuni.common.crypto.InputLengthException;

public class RSABlockTransformerTest {

	private static final String EXPECTED = "This is a good test. I approve of it.";

	private RSAPrivateKeyGenerator keygen;

	@Before
	public void setUp() {
		keygen = new RSAPrivateKeyGenerator();
	}

	@Test
	public void testSingleBlockRoundTripSucceedsWhenInputLengthMatchesBlockSize() {
		assertRoundTrip( keygen.generate( EXPECTED.length() * 8 ) );
	}

	@Test( expected = InputLengthException.class )
	public void testSingleBlockEncryptionFailsWhenInputLengthIsMoreThanBlockSize() {
		assertRoundTrip( keygen.generate( ( EXPECTED.length() - 1 ) * 8 ) );
	}

	@Test
	public void testSingleBlockRoundTripSucceedsWhenInputLengthIsLessThanBlockSize() {
		assertRoundTrip( keygen.generate( ( EXPECTED.length() + 1 ) * 8 ) );
	}

	private void assertRoundTrip( RSAPrivateKey privateKey ) {
		assertRoundTripFromPrivateKey( privateKey );
		assertRoundTripFromPublicKey( privateKey );
	}

	private void assertRoundTripFromPrivateKey( RSAPrivateKey privateKey ) {

		RSAPublicKey publicKey = privateKey.getPublicKey();

		RSABlockEncryptor encryptor = new RSABlockEncryptor( publicKey.getModulus() );
		RSABlockDecryptor decryptor = new RSABlockDecryptor( publicKey.getModulus() );

		byte [] encrypted = encryptor.transform( privateKey, EXPECTED.getBytes() );
		byte [] decrypted = decryptor.transform( publicKey, encrypted );
		String actual = new String( decrypted );

		Assert.assertEquals( EXPECTED, actual );

	}

	private void assertRoundTripFromPublicKey( RSAPrivateKey privateKey ) {

		RSAPublicKey publicKey = privateKey.getPublicKey();

		RSABlockEncryptor encryptor = new RSABlockEncryptor( publicKey.getModulus() );
		RSABlockDecryptor decryptor = new RSABlockDecryptor( publicKey.getModulus() );

		byte [] encrypted = encryptor.transform( publicKey, EXPECTED.getBytes() );
		byte [] decrypted = decryptor.transform( privateKey, encrypted );
		String actual = new String( decrypted );

		Assert.assertEquals( EXPECTED, actual );

	}

}
