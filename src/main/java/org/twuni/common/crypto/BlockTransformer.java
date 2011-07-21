package org.twuni.common.crypto;

import java.util.Arrays;

public abstract class BlockTransformer<From, To> {

	public abstract int getInputBlockSize();

	public abstract int getOutputBlockSize();

	protected abstract From read( byte [] buffer );

	protected abstract byte [] write( To result );

	public byte [] transform( Transformer<From, To> transformer, byte [] buffer ) {
		return transform( transformer, buffer, 0, buffer.length );
	}

	public byte [] transform( Transformer<From, To> transformer, byte [] buffer, int offset, int length ) {
		return write( transformer.transform( read( buffer, offset, length ) ) );
	}

	private From read( byte [] buffer, int offset, int length ) {
		if( offset != 0 || length < buffer.length ) {
			return read( Arrays.copyOfRange( buffer, offset, offset + length ) );
		} else {
			return read( buffer );
		}
	}

}
