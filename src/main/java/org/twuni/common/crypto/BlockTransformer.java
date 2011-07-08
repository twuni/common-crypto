package org.twuni.common.crypto;

public abstract class BlockTransformer<From, To> {

	public abstract int getInputBlockSize();

	public abstract int getOutputBlockSize();

	protected abstract From read( byte [] buffer, int offset, int length );

	protected abstract byte [] write( To result );

	public byte [] transform( Transformer<From, To> transformer, byte [] buffer ) {
		return transform( transformer, buffer, 0, buffer.length );
	}

	public byte [] transform( Transformer<From, To> transformer, byte [] buffer, int offset, int length ) {
		return write( transformer.transform( read( buffer, offset, length ) ) );
	}

}
