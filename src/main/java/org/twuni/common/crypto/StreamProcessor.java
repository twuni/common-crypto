package org.twuni.common.crypto;


public interface StreamProcessor<From,To> {
	
	public byte [] process( Transformer<From,To> transformer, byte [] buffer, int offset, int length );

}
