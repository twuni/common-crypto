package org.twuni.common.crypto.rsa;

import java.io.IOException;
import java.math.BigInteger;

import org.twuni.common.crypto.Base64;
import org.twuni.common.crypto.ByteArrayTransformer;

public class Transformer extends ByteArrayTransformer<BigInteger, BigInteger> {

	private final BlockEncryptor encryptor;
	private final BlockDecryptor decryptor;
	private final org.twuni.common.crypto.Transformer<BigInteger, BigInteger> key;

	public Transformer( PrivateKey key ) {
		this.encryptor = new BlockEncryptor( key.getPublicKey().getModulus() );
		this.decryptor = new BlockDecryptor( key.getPublicKey().getModulus() );
		this.key = key;
	}

	public Transformer( PublicKey key ) {
		this.encryptor = new BlockEncryptor( key.getModulus() );
		this.decryptor = new BlockDecryptor( key.getModulus() );
		this.key = key;
	}

	public String encrypt( String message ) throws IOException {
		return Base64.encode( encrypt( message.getBytes() ) );
	}

	public byte [] encrypt( byte [] message ) throws IOException {
		return encrypt( message, 0, message.length );
	}

	public byte [] encrypt( byte [] message, int offset, int length ) throws IOException {
		return transform( encryptor, key, message, offset, length );
	}

	public String decrypt( String message ) throws IOException {
		return new String( decrypt( Base64.decode( message ) ) );
	}

	public byte [] decrypt( byte [] message ) throws IOException {
		return decrypt( message, 0, message.length );
	}

	public byte [] decrypt( byte [] message, int offset, int length ) throws IOException {
		return transform( decryptor, key, message, offset, length );
	}

}
