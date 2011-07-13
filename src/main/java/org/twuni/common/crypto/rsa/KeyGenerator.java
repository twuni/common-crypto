package org.twuni.common.crypto.rsa;

import static java.math.BigInteger.ONE;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class KeyGenerator {

	private final Random random;

	/**
	 * Convenience constructor which uses a new {@link SecureRandom} instance to generate private
	 * keys. Same as calling <code>new KeyGenerator( new SecureRandom() )</code>.
	 */
	public KeyGenerator() {
		this( new SecureRandom() );
	}

	/**
	 * @param random
	 *            The random number generator to use for generated private keys.
	 */
	public KeyGenerator( Random random ) {
		this.random = random;
	}

	/**
	 * Convenience method which creates a new RSA private key with the given bit length using the
	 * default exponent of {@link PrivateKey#DEFAULT_EXPONENT}. Same as calling
	 * <code>generate( strength, {@link PrivateKey#DEFAULT_EXPONENT} )</code>.
	 * 
	 * @param strength
	 *            The number of bits to use for the generated private key.
	 */
	public PrivateKey generate( final int strength ) {
		return generate( strength, PrivateKey.DEFAULT_EXPONENT );
	}

	/**
	 * Generates a new private key with a length of <code>strength</code> bits using the given
	 * exponent.
	 * 
	 * @param strength
	 *            The number of bits to use for the generated private key.
	 * @param exponent
	 *            The exponent to use for the generated private key.
	 */
	public PrivateKey generate( final int strength, final BigInteger exponent ) {

		final int bitLength = ( strength + 1 ) / 2;

		BigInteger p = generatePrime( bitLength, exponent );
		BigInteger q = ONE;
		BigInteger n;

		do {
			p = p.max( q );
			do {
				q = generatePrime( strength - bitLength, exponent );
			} while( q.subtract( p ).abs().bitLength() < strength / 3 );
			n = p.multiply( q );
		} while( n.bitLength() != strength );

		if( p.compareTo( q ) < 0 ) {
			BigInteger t = p;
			p = q;
			q = t;
		}

		return new PrivateKey( p, q, exponent );

	}

	private BigInteger generatePrime( int bitLength, BigInteger e ) {
		BigInteger prime;
		do {
			prime = BigInteger.probablePrime( bitLength, random );
		} while( prime.mod( e ).equals( ONE ) || !e.gcd( prime.subtract( ONE ) ).equals( ONE ) );
		return prime;
	}

}
