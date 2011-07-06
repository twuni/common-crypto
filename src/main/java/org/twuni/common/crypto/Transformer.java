package org.twuni.common.crypto;

public interface Transformer<From, To> {

	public To transform( From from );

}
