package org.twuni.common.crypto.rsa;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * This should *NOT* be used in practice! It attempts to derive a private key from a given public
 * key.
 */
public class KeyDeriver {

	/**
	 * Reverse-engineers the given RSA public key to find its associated private key.
	 */
	public PrivateKey derive( PublicKey publicKey ) {

		BigInteger p, q;

		List<BigInteger> factors = factor( publicKey.getModulus() );

		p = factors.get( 0 );
		q = factors.get( 1 );

		if( p.compareTo( q ) < 0 ) {
			BigInteger t = p;
			p = q;
			q = t;
		}

		return new PrivateKey( p, q, publicKey.getExponent() );

	}

	private List<BigInteger> factor( BigInteger number ) {

		List<BigInteger> factors = new ArrayList<BigInteger>();

		if( number.compareTo( BigInteger.valueOf( 2 ) ) < 0 ) {
			factors.add( BigInteger.valueOf( 1 ) );
			return factors;
		}

		BigInteger limit = getFactorizationUpperBound( number );

		for( BigInteger i = BigInteger.valueOf( 2 ); i.compareTo( limit ) <= 0; i = i.add( BigInteger.ONE ) ) {
			if( number.mod( i ).equals( BigInteger.ZERO ) ) {
				factors.add( i );
				factors.addAll( factor( number.divide( i ) ) );
				return factors;
			}
		}

		factors.add( number );

		return factors;

	}

	private BigInteger getFactorizationUpperBound( BigInteger number ) {
		// Ideally, this would return the square root of the given number.
		return number.divide( BigInteger.valueOf( 2 ) );
	}

}
