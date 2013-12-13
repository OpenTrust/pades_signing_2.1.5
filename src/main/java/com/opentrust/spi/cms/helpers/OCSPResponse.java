package com.opentrust.spi.cms.helpers;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespGenerator;


public class OCSPResponse {

	org.bouncycastle.ocsp.BasicOCSPResp response;
	byte [] encoded;
	
	
	public OCSPResponse(BasicOCSPResp ocsp) throws IOException
	{
		this.response = ocsp;
		// We need the OCSP envelop for inclusion in CMS, so recreate the envelop
		// from the OCSP basic response sequence
		OCSPRespGenerator gen = new OCSPRespGenerator();
		OCSPResp ocspResponse;
        try {
            ocspResponse = gen.generate(OCSPRespGenerator.SUCCESSFUL, ocsp);
        } catch (OCSPException e) {
            // should not happen
            throw new IOException(e.toString(), e);
        }
		this.encoded = ocspResponse.getEncoded();
	}
	
	public OCSPResponse(byte [] encoded) throws IOException
	{
		this.encoded = encoded;
		ASN1Sequence readObject = parseAsn1(encoded);
		
		response = new BasicOCSPResp(new BasicOCSPResponse(readObject));
	}

    private ASN1Sequence parseAsn1(byte[] encoded) throws IOException {
        ASN1InputStream ais = new ASN1InputStream(encoded);
		ASN1Sequence readObject = (ASN1Sequence) ais.readObject();
        return readObject;
    }
	
	public byte[] getEncoded() {
		return encoded;
	}

	public static OCSPResponse parseResponse(byte [] encoded) throws IOException
	{
		return new OCSPResponse(encoded);
	}
}
