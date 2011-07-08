package org.twuni.common.crypto;

import org.junit.Assert;
import org.junit.Test;

public class Base64Test {

	@Test
	public void testEncodeWithoutPadding() {
		String input = "This is a test.";
		String expected = "VGhpcyBpcyBhIHRlc3Qu";
		String actual = Base64.encode( input.getBytes() );
		Assert.assertEquals( expected, actual );
	}

	@Test
	public void testEncodeWithSinglePadding() {
		String input = "This is another test...";
		String expected = "VGhpcyBpcyBhbm90aGVyIHRlc3QuLi4=";
		String actual = Base64.encode( input.getBytes() );
		Assert.assertEquals( expected, actual );
	}

	@Test
	public void testEncodeWithDoublePadding() {
		String input = "Yet another test...";
		String expected = "WWV0IGFub3RoZXIgdGVzdC4uLg==";
		String actual = Base64.encode( input.getBytes() );
		Assert.assertEquals( expected, actual );
	}

	@Test
	public void testDecodeWithoutPadding() {
		String input = "VGhpcyBpcyBhIHRlc3Qu";
		String expected = "This is a test.";
		String actual = new String( Base64.decode( input ) );
		Assert.assertEquals( expected, actual );
	}

	@Test
	public void testDecodeWithSinglePadding() {
		String input = "VGhpcyBpcyBhbm90aGVyIHRlc3QuLi4=";
		String expected = "This is another test...";
		String actual = new String( Base64.decode( input ) );
		Assert.assertEquals( expected, actual );
	}

	@Test
	public void testDecodeWithDoublePadding() {
		String input = "WWV0IGFub3RoZXIgdGVzdC4uLg==";
		String expected = "Yet another test...";
		String actual = new String( Base64.decode( input ) );
		Assert.assertEquals( expected, actual );
	}

}
