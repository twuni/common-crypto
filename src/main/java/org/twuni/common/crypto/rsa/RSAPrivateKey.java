package org.twuni.common.crypto.rsa;

import static java.math.BigInteger.ONE;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.twuni.common.crypto.Transformer;

public class RSAPrivateKey implements Transformer<BigInteger,BigInteger> {

	private static final BigInteger DEFAULT_EXPONENT = BigInteger.valueOf( 0x10001 );

	private final RSAPublicKey publicKey;
	private final BigInteger p;
	private final BigInteger q;
	private final BigInteger dP;
	private final BigInteger dQ;
	private final BigInteger inverse;

	/**
	 * Convenience constructor which creates an RSA private key with the given prime numbers, using
	 * the default exponent of 65537.
	 * 
	 * @param p
	 *            The greater of the two prime numbers used in the RSA algorithm.
	 * @param q
	 *            The lesser of the two prime numbers used in the RSA algorithm.
	 */
	public RSAPrivateKey( BigInteger p, BigInteger q ) {
		this( p, q, DEFAULT_EXPONENT );
	}

	/**
	 * Constructs an RSA private key with the given criteria.
	 * 
	 * @param p
	 *            The greater of the two prime numbers used in the RSA algorithm.
	 * @param q
	 *            The lesser of the two prime numbers used in the RSA algorithm.
	 * @param exponent
	 *            The exponent used in the RSA algorithm.
	 */
	public RSAPrivateKey( BigInteger p, BigInteger q, BigInteger exponent ) {

		BigInteger d = exponent.modInverse( p.subtract( ONE ).multiply( q.subtract( ONE ) ) );

		this.publicKey = new RSAPublicKey( p.multiply( q ), exponent );
		this.p = p;
		this.q = q;
		this.dP = d.remainder( p.subtract( ONE ) );
		this.dQ = d.remainder( q.subtract( ONE ) );
		this.inverse = q.modInverse( p );

	}

	/**
	 * Convenience constructor which creates a new RSA private key with the given bit length using a
	 * new, unseeded SecureRandom instance. Same as calling
	 * <code>new RSAPrivateKey( strength, new SecureRandom() )</code>.
	 * 
	 * @param strength
	 *            The number of bits to use for this private key.
	 */
	public RSAPrivateKey( final int strength ) {
		this( strength, new SecureRandom() );
	}

	/**
	 * Convenience constructor which creates a new RSA private key with the given bit length using
	 * the given random number generator and with the default exponent of 65537. Same as calling
	 * <code>new RSAPrivateKey( strength, random, 0x10001 )</code>.
	 * 
	 * @param strength
	 *            The number of bits to use for this private key.
	 * @param random
	 *            The random number generator to use for this private key.
	 */
	public RSAPrivateKey( final int strength, final Random random ) {
		this( strength, random, DEFAULT_EXPONENT );
	}

	/**
	 * @param strength
	 *            The number of bits to use for this private key.
	 * @param random
	 *            The random number generator to use for this private key.
	 * @param exponent
	 *            The exponent to use for the RSA algorithm.
	 */
	public RSAPrivateKey( final int strength, final Random random, final BigInteger exponent ) {

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

		BigInteger d = exponent.modInverse( p.subtract( ONE ).multiply( q.subtract( ONE ) ) );

		this.publicKey = new RSAPublicKey( n, exponent );
		this.p = p;
		this.q = q;
		this.dP = d.remainder( p.subtract( ONE ) );
		this.dQ = d.remainder( q.subtract( ONE ) );
		this.inverse = q.modInverse( p );

	}

	public RSAPublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Encrypts the given input using the Chinese-Remainder Theorem.
	 */
	@Override
	public BigInteger transform( BigInteger input ) {

		BigInteger mP, mQ, h, m;

		mP = ( input.remainder( p ) ).modPow( dP, p );
		mQ = ( input.remainder( q ) ).modPow( dQ, q );

		h = mP.subtract( mQ );
		h = h.multiply( inverse );
		h = h.mod( p );

		m = h.multiply( q );
		m = m.add( mQ );

		return m;

	}

	private BigInteger generatePrime( int bitLength, BigInteger e, Random random ) {
		BigInteger p;
		do {
			p = BigInteger.probablePrime( bitLength, random );
		} while( p.mod( e ).equals( ONE ) || !e.gcd( p.subtract( ONE ) ).equals( ONE ) );
		return p;
	}

}
