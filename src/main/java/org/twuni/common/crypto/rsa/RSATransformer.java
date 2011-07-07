package org.twuni.common.crypto.rsa;

import java.math.BigInteger;

import org.twuni.common.crypto.ByteArrayTransformer;
import org.twuni.common.crypto.Transformer;

abstract class RSATransformer implements ByteArrayTransformer<BigInteger, BigInteger> {

	protected abstract BigInteger read( byte [] buffer, int offset, int length );

	protected abstract byte [] write( BigInteger result );

	@Override
	public byte [] transform( Transformer<BigInteger, BigInteger> transformer, byte [] buffer ) {
		return transform( transformer, buffer, 0, buffer.length );
	}

	@Override
	public byte [] transform( Transformer<BigInteger, BigInteger> transformer, byte [] buffer, int offset, int length ) {
		return write( transformer.transform( read( buffer, offset, length ) ) );
	}

}
