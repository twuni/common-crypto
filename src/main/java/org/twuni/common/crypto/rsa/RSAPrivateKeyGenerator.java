package org.twuni.common.crypto.rsa;

import static java.math.BigInteger.ONE;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class RSAPrivateKeyGenerator {

	/**
	 * Convenience method which creates a new RSA private key with the given bit length using a new,
	 * unseeded SecureRandom instance. Same as calling
	 * <code>new RSAPrivateKey( strength, new SecureRandom() )</code>.
	 * 
	 * @param strength
	 *            The number of bits to use for the generated private key.
	 */
	public RSAPrivateKey generate( final int strength ) {
		return generate( strength, new SecureRandom() );
	}

	/**
	 * Convenience method which creates a new RSA private key with the given bit length using the
	 * given random number generator and with the default exponent of
	 * {@link RSAPrivateKey#DEFAULT_EXPONENT}. Same as calling
	 * <code>new RSAPrivateKey( strength, random, {@link RSAPrivateKey#DEFAULT_EXPONENT} )</code>.
	 * 
	 * @param strength
	 *            The number of bits to use for the generated private key.
	 * @param random
	 *            The random number generator to use for the generated private key.
	 */
	public RSAPrivateKey generate( final int strength, final Random random ) {
		return generate( strength, random, RSAPrivateKey.DEFAULT_EXPONENT );
	}

	/**
	 * @param strength
	 *            The number of bits to use for the generated private key.
	 * @param random
	 *            The random number generator to use for the generated private key.
	 * @param exponent
	 *            The exponent to use for the generated private key.
	 */
	public RSAPrivateKey generate( final int strength, final Random random, final BigInteger exponent ) {

		final int bitLength = ( strength + 1 ) / 2;

		BigInteger p = generatePrime( bitLength, exponent, random );
		BigInteger q = ONE;
		BigInteger n;

		do {
			p = p.max( q );
			do {
				q = generatePrime( strength - bitLength, exponent, random );
			} while( q.subtract( p ).abs().bitLength() < strength / 3 );
			n = p.multiply( q );
		} while( n.bitLength() != strength );

		if( p.compareTo( q ) < 0 ) {
			BigInteger t = p;
			p = q;
			q = t;
		}

		return new RSAPrivateKey( p, q, exponent );

	}

	private BigInteger generatePrime( int bitLength, BigInteger e, Random random ) {
		BigInteger prime;
		do {
			prime = BigInteger.probablePrime( bitLength, random );
		} while( prime.mod( e ).equals( ONE ) || !e.gcd( prime.subtract( ONE ) ).equals( ONE ) );
		return prime;
	}

}
