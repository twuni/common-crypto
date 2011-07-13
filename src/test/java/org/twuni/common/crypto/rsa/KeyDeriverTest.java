package org.twuni.common.crypto.rsa;

import org.junit.Assert;
import org.junit.Test;

public class KeyDeriverTest {

	@Test
	public void testGeneratePrivateKeyFromTrivialPublicKey() {
		PrivateKey privateKey = new KeyGenerator().generate( 16 );
		PublicKey publicKey = privateKey.getPublicKey();
		Assert.assertEquals( privateKey, new KeyDeriver().derive( publicKey ) );
	}

}
