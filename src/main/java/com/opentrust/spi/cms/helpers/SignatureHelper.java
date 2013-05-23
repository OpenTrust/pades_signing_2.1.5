package com.opentrust.spi.cms.helpers;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERObjectIdentifier;

import com.keynectis.sequoia.ca.crypto.utils.OIDUtils;

public class SignatureHelper {

	
	public static void main(String [] args)
	{
		DERObjectIdentifier test = new ASN1ObjectIdentifier("pikachu");
	}
	
	public static DERObjectIdentifier tryParseOid(String oid)
	{
		try
		{
			return new ASN1ObjectIdentifier(oid);			
		}
		catch (Exception e)
		{
			return null;
		}
	}
	public static String getSignatureAlgoFromDigestAndKeyAlgo(String digestAlg, String algorithm) {
		
		DERObjectIdentifier oid;
		oid = tryParseOid(digestAlg);
		if (oid != null)
		{
			digestAlg = OIDUtils.getName(oid);
			if (digestAlg == null)
				throw new NullPointerException("Unknown oid " + oid.getId()); 
		}
		digestAlg = digestAlg.replace("-", "");
		oid = tryParseOid(algorithm);
		if (oid != null)
		{
			algorithm = OIDUtils.getName(oid);
			if (algorithm == null)
				throw new NullPointerException("Unknown oid " + oid.getId()); 
		} 		
		if (algorithm.toLowerCase().contains("with"))
			return algorithm;
		return digestAlg + "With" + algorithm;
	}
	
	public static String convertOidIfRequired(String algo)
	{
		try
		{
			DERObjectIdentifier oid = new ASN1ObjectIdentifier(algo);
			algo = OIDUtils.getName(oid);
			
		} catch (Exception e) {}
		
		return algo;
	}

}
