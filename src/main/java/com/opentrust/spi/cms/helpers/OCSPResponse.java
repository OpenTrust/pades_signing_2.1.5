package com.opentrust.spi.cms.helpers;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.ocsp.BasicOCSPResp;


public class OCSPResponse {

	org.bouncycastle.ocsp.BasicOCSPResp response;
	byte [] encoded;
	
	
	public OCSPResponse(BasicOCSPResp ocsp) throws IOException
	{
		this.response = ocsp;
		this.encoded = ocsp.getEncoded();
	}
	
	public OCSPResponse(byte [] encoded) throws IOException
	{
		this.encoded = encoded;
		ASN1InputStream ais = new ASN1InputStream(encoded);
		ASN1Sequence readObject = (ASN1Sequence) ais.readObject();
		
		response = new BasicOCSPResp(new BasicOCSPResponse(readObject));
	}
	
	public byte[] getEncoded() {
		return encoded;
	}

	public static OCSPResponse parseResponse(byte [] encoded) throws IOException
	{
		return new OCSPResponse(encoded);
	}
}
