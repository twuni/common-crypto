package org.twuni.common.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class ByteArrayTransformer<From, To> {

	public byte [] transform( BlockTransformer<From, To> transformer, Transformer<From, To> key, byte [] message, int offset, int length ) throws IOException {
		if( offset == 0 || length == message.length ) {
			return transform( transformer, key, message );
		}
		return transform( transformer, key, Arrays.copyOfRange( message, offset, length ) );
	}

	public byte [] transform( BlockTransformer<From, To> transformer, Transformer<From, To> key, byte [] message ) throws IOException {

		ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		int blockSize = transformer.getInputBlockSize();
		int numberOfBlocks = (int) Math.ceil( message.length / (double) blockSize );

		for( int i = 0; i < numberOfBlocks; i++ ) {
			int offset = i * blockSize;
			int length = offset + blockSize > message.length ? message.length - offset : blockSize;
			buffer.write( transformer.transform( key, message, offset, length ) );
		}

		return buffer.toByteArray();

	}

}
