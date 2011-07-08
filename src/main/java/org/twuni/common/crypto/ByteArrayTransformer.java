package org.twuni.common.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ByteArrayTransformer<From, To> {

	public byte [] transform( BlockTransformer<From, To> transformer, Transformer<From, To> key, byte [] message ) throws IOException {

		ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		int blockSize = transformer.getInputBlockSize();
		int numberOfBlocks = (int) Math.ceil( (double) message.length / (double) blockSize );

		for( int i = 0; i < numberOfBlocks; i++ ) {
			int offset = i * blockSize;
			int length = offset + blockSize > message.length ? message.length - offset : blockSize;
			buffer.write( transformer.transform( key, message, offset, length ) );
		}

		return buffer.toByteArray();

	}

}
