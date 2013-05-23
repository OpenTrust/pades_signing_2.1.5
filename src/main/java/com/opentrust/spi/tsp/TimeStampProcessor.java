package com.opentrust.spi.tsp;

import java.io.InputStream;


public interface TimeStampProcessor {
	public static String PROPERTY = "com.opentrust.spi.tsp.TimeStampProcessor";

	public byte[] timestamp(byte[] data)throws Exception;

	public byte[] timestamp(InputStream stream)throws Exception;

	public byte [] sendRequest (byte [] request) throws Exception;
	
	public boolean useNonce ();
	
	public String getDigestAlgorithm();
	
	public String getUrl ();
	
	public String getPolicyId();
	
	
	
	
}
