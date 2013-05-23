package com.opentrust.spi.helpers;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;

import org.apache.commons.codec.binary.Base64InputStream;
import org.bouncycastle.util.io.Streams;

public class Base64Helper {

	public static byte[] decodeFromFile(String string) throws IOException {
		FileInputStream fis = new FileInputStream(string);
		Base64InputStream is = new Base64InputStream(fis);		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		Streams.pipeAll(is, baos);
		return baos.toByteArray();
	}

}
