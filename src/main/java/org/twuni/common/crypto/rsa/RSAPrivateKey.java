package org.twuni.common.crypto.rsa;

import static java.math.BigInteger.ONE;

import java.math.BigInteger;
import java.util.Random;

import org.twuni.common.crypto.Transformer;

public class RSAPrivateKey implements Transformer<BigInteger, BigInteger> {

	private final RSAPublicKey publicKey;
	private final BigInteger p;
	private final BigInteger q;
	private final BigInteger dP;
	private final BigInteger dQ;
	private final BigInteger inverse;

	public RSAPrivateKey( RSAPublicKey publicKey, BigInteger p, BigInteger q, BigInteger dP, BigInteger dQ, BigInteger inverse ) {
		this.publicKey = publicKey;
		this.p = p;
		this.q = q;
		this.dP = dP;
		this.dQ = dQ;
		this.inverse = inverse;
	}

	public RSAPrivateKey( final int strength, final Random random ) {
		this( strength, random, BigInteger.valueOf( 0x10001 ) );
	}

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
