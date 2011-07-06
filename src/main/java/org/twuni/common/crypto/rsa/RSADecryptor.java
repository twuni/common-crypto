package org.twuni.common.crypto.rsa;

import java.math.BigInteger;

import org.twuni.common.crypto.InputLengthException;

public class RSADecryptor extends RSAStreamTransformer {

	private final BigInteger modulus;

	public RSADecryptor( BigInteger modulus ) {
		this.modulus = modulus;
	}

	private int getInputBlockSize() {
		return ( modulus.bitLength() + 7 ) / 8;
	}

	@Override
	protected BigInteger read( byte [] buffer, int offset, int length ) {

		if( length > getInputBlockSize() + 1 || length == getInputBlockSize() + 1 ) {
			throw new InputLengthException();
		}

		byte [] block = buffer;

		if( !( offset == 0 && length == buffer.length ) ) {
			block = new byte [length];
			System.arraycopy( buffer, offset, block, 0, length );
		}

		BigInteger result = new BigInteger( 1, block );

		if( result.compareTo( modulus ) >= 0 ) {
			throw new InputLengthException();
		}

		return result;

	}

	@Override
	protected byte [] write( BigInteger result ) {

		byte [] output = result.toByteArray();

		if( output[0] == 0 ) {
			byte [] buffer = new byte [output.length - 1];
			System.arraycopy( output, 1, buffer, 0, buffer.length );
			return buffer;
		}

		return output;

	}

}
