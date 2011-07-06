package org.twuni.common.crypto;

public interface StreamTransformer<From, To> {

	public byte [] transform( Transformer<From, To> transformer, byte [] buffer );

	public byte [] transform( Transformer<From, To> transformer, byte [] buffer, int offset, int length );

}
