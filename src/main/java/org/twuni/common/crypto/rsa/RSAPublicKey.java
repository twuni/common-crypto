package org.twuni.common.crypto.rsa;

import java.math.BigInteger;

import org.twuni.common.crypto.Base64;
import org.twuni.common.crypto.Transformer;

public class RSAPublicKey implements Transformer<BigInteger, BigInteger> {

	private final BigInteger modulus;
	private final BigInteger exponent;

	public RSAPublicKey( BigInteger modulus, BigInteger exponent ) {
		this.modulus = modulus;
		this.exponent = exponent;
	}

	public BigInteger getModulus() {
		return modulus;
	}

	public BigInteger getExponent() {
		return exponent;
	}

	@Override
	public BigInteger transform( BigInteger input ) {
		return input.modPow( exponent, modulus );
	}

	@Override
	public String toString() {

		StringBuilder string = new StringBuilder();

		string.append( Base64.encode( modulus.toByteArray() ) ).append( "\n" );
		string.append( Base64.encode( exponent.toByteArray() ) );

		return string.toString();

	}

}
