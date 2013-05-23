package com.opentrust.spi.cms.helpers;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;

import com.opentrust.spi.tsp.TimestampToken;
import com.opentrust.spi.tsp.impl.BCTimeStampToken;

/*
import com.opentrust.spi.tsp.TimestampToken;
import com.opentrust.spi.tsp.TimestampTokenManagerFactory;
*/

public class UnsignedAttributesHelper {

	/****** SETTERS *******/
	public static void addTimestampAttribute(Hashtable<DERObjectIdentifier, Attribute> unsignedAttributesHashtable,
			byte[] timeStampTokenBytes) throws IOException {
		if (timeStampTokenBytes == null)
			return;
		
		DERObject derObj = new ASN1InputStream(new ByteArrayInputStream(timeStampTokenBytes)).readObject();
		DERSet derSet = new DERSet(derObj);
		Attribute unsignAtt = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, derSet);
		unsignedAttributesHashtable.put(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, unsignAtt);
	}

	
	
	
	/****** GETTERS 
	 * @throws TSPException 
	 * @throws CMSException *******/
	public static List<TimestampToken> getSignatureTimestamps(AttributeTable table) throws IOException, CMSException, TSPException {
		List<TimestampToken> signatureTimeStamps = new ArrayList<TimestampToken>();
		if (table == null) 
			return signatureTimeStamps;
		
		Attribute tspAtt = table.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
		if (tspAtt == null)
			return signatureTimeStamps;
		
		ASN1Set tspAttrValues = tspAtt.getAttrValues();
		if (tspAttrValues == null) 
			return signatureTimeStamps;
		
		DEREncodable dob = tspAttrValues.getObjectAt(0);
		if (dob == null)
			return signatureTimeStamps;

		byte[] encodedTsp = dob.getDERObject().getEncoded();
		if (encodedTsp != null) {
			TimestampToken token = parseTsp(encodedTsp);
			signatureTimeStamps.add(token);
		}
		
		return signatureTimeStamps;
	}




	public static TimestampToken parseTsp(byte[] encodedTsp) throws CMSException, TSPException, IOException {
		return new BCTimeStampToken(encodedTsp);
	}
	

}
