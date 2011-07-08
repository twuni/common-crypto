package org.twuni.common.crypto.rsa;

import org.junit.Assert;
import org.junit.Test;

public class RSAReversePrivateKeyGeneratorTest {

	@Test
	public void testGeneratePrivateKeyFromTrivialPublicKey() {
		RSAPrivateKey privateKey = new RSAPrivateKeyGenerator().generate( 16 );
		RSAPublicKey publicKey = privateKey.getPublicKey();
		Assert.assertEquals( privateKey, new RSAReversePrivateKeyGenerator().generate( publicKey ) );
	}

}
