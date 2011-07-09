package org.twuni.common.crypto.rsa;

import java.io.IOException;
import java.math.BigInteger;

import org.twuni.common.crypto.ByteArrayTransformer;
import org.twuni.common.crypto.Transformer;

public class RSATransformer extends ByteArrayTransformer<BigInteger, BigInteger> {

	private final RSABlockEncryptor encryptor;
	private final RSABlockDecryptor decryptor;
	private final Transformer<BigInteger, BigInteger> key;

	public RSATransformer( RSAPrivateKey key ) {
		this.encryptor = new RSABlockEncryptor( key.getPublicKey().getModulus() );
		this.decryptor = new RSABlockDecryptor( key.getPublicKey().getModulus() );
		this.key = key;
	}

	public RSATransformer( RSAPublicKey key ) {
		this.encryptor = new RSABlockEncryptor( key.getModulus() );
		this.decryptor = new RSABlockDecryptor( key.getModulus() );
		this.key = key;
	}

	public byte [] encrypt( byte [] message ) throws IOException {
		return encrypt( message, 0, message.length );
	}

	public byte [] encrypt( byte [] message, int offset, int length ) throws IOException {
		return transform( encryptor, key, message, offset, length );
	}

	public byte [] decrypt( byte [] message ) throws IOException {
		return decrypt( message, 0, message.length );
	}

	public byte [] decrypt( byte [] message, int offset, int length ) throws IOException {
		return transform( decryptor, key, message, offset, length );
	}

}
