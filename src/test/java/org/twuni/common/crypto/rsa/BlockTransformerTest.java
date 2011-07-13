package org.twuni.common.crypto.rsa;

import java.util.Random;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.twuni.common.crypto.InputLengthException;

public class BlockTransformerTest {

	private static final int BLOCK_SIZE = 128;

	private KeyGenerator keygen;

	@Before
	public void setUp() {
		keygen = new KeyGenerator();
	}

	@Test
	public void testSingleBlockRoundTripSucceedsWhenInputLengthMatchesBlockSize() {
		assertRoundTrip( keygen.generate( BLOCK_SIZE ) );
	}

	@Test( expected = InputLengthException.class )
	public void testSingleBlockEncryptionFailsWhenInputLengthIsMoreThanBlockSize() {
		assertRoundTrip( keygen.generate( BLOCK_SIZE - 8 ) );
	}

	@Test
	public void testSingleBlockRoundTripSucceedsWhenInputLengthIsLessThanBlockSize() {
		assertRoundTrip( keygen.generate( BLOCK_SIZE + 8 ) );
	}

	private void assertRoundTrip( PrivateKey privateKey ) {
		assertRoundTripFromPrivateKey( privateKey );
		assertRoundTripFromPublicKey( privateKey );
	}

	private void assertRoundTripFromPrivateKey( PrivateKey privateKey ) {

		PublicKey publicKey = privateKey.getPublicKey();

		BlockEncryptor encryptor = new BlockEncryptor( publicKey.getModulus() );
		BlockDecryptor decryptor = new BlockDecryptor( publicKey.getModulus() );

		byte [] expected = generateRandomString( BLOCK_SIZE / 8 ).getBytes();
		byte [] encrypted = encryptor.transform( privateKey, expected );
		byte [] actual = decryptor.transform( publicKey, encrypted );

		Assert.assertArrayEquals( expected, actual );

	}

	private void assertRoundTripFromPublicKey( PrivateKey privateKey ) {

		PublicKey publicKey = privateKey.getPublicKey();

		BlockEncryptor encryptor = new BlockEncryptor( publicKey.getModulus() );
		BlockDecryptor decryptor = new BlockDecryptor( publicKey.getModulus() );

		byte [] expected = generateRandomString( BLOCK_SIZE / 8 ).getBytes();
		byte [] encrypted = encryptor.transform( publicKey, expected );
		byte [] actual = decryptor.transform( privateKey, encrypted );

		Assert.assertArrayEquals( expected, actual );

	}

	private String generateRandomString( int length ) {
		return "This is the most amazing wave of sickening chaos on the planet, except for the trillion bees and insects just fluttering quietly about.".substring( 0, length );
	}

	private byte [] generateRandomBytes( int length ) {
		Random random = new Random();
		byte [] buffer = new byte [length];
		random.nextBytes( buffer );
		return buffer;
	}

}
