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

	/**
	 * Serializes the essential fields of this key as a newline-delimited, base64-encoded string.
	 */
	public String serialize() {

		StringBuilder string = new StringBuilder();

		string.append( Base64.encode( modulus.toByteArray() ) ).append( "\n" );
		string.append( Base64.encode( exponent.toByteArray() ) );

		return string.toString();

	}

	/**
	 * Constructs a new RSA public key using the given serial, generated by calling
	 * {@link RSAPublicKey#serialize()}.
	 * 
	 * @param serial
	 *            The base64-encoded serialization of the public key, obtained by calling
	 *            {@link RSAPublicKey#serialize()}.
	 */
	public static RSAPublicKey deserialize( String serial ) {

		String [] args = serial.split( "\n" );

		BigInteger modulus = new BigInteger( Base64.decode( args[0] ) );
		BigInteger exponent = new BigInteger( Base64.decode( args[1] ) );

		return new RSAPublicKey( modulus, exponent );

	}

	@Override
	public String toString() {
		return serialize();
	}

}
