package com.opentrust.spi.crypto;

import java.io.FileInputStream;
import java.io.IOException;

import org.bouncycastle.util.io.Streams;

public class FileHelper {

	public static byte[] load(String absolutePath) throws IOException {
		FileInputStream fis = null;
		try
		{
			fis = new FileInputStream(absolutePath);
			return Streams.readAll(fis);
		}
		finally
		{
			if (fis != null)
				try {
					fis.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
		}
	}

}
