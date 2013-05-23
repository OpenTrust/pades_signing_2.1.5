/*
 * Copyright 2004 by Paulo Soares.
 *
 * The contents of this file are subject to the Mozilla Public License Version 1.1
 * (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the License.
 *
 * The Original Code is 'iText, a free JAVA-PDF library'.
 *
 * The Initial Developer of the Original Code is Bruno Lowagie. Portions created by
 * the Initial Developer are Copyright (C) 1999, 2000, 2001, 2002 by Bruno Lowagie.
 * All Rights Reserved.
 * Co-Developer of the code is Paulo Soares. Portions created by the Co-Developer
 * are Copyright (C) 2000, 2001, 2002 by Paulo Soares. All Rights Reserved.
 *
 * Contributor(s): all the names of the contributors are added in the source code
 * where applicable.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * LGPL license (the "GNU LIBRARY GENERAL PUBLIC LICENSE"), in which case the
 * provisions of LGPL are applicable instead of those above.  If you wish to
 * allow use of your version of this file only under the terms of the LGPL
 * License and not to allow others to use your version of this file under
 * the MPL, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the LGPL.
 * If you do not delete the provisions above, a recipient may use your version
 * of this file under either the MPL or the GNU LIBRARY GENERAL PUBLIC LICENSE.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MPL as stated above or under the terms of the GNU
 * Library General Public License as published by the Free Software Foundation;
 * either version 2 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Library general Public License for more
 * details.
 *
 * If you didn't download this code from the following link, you should check if
 * you aren't using an obsolete version:
 * http://www.lowagie.com/iText/
 */
package com.opentrust.spi.pdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
import org.bouncycastle.asn1.esf.SignerAttribute;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.ess.ContentHints;
import org.bouncycastle.asn1.ess.ContentIdentifier;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertParser;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;

import com.keynectis.sequoia.security.clients.interfaces.ITspClient;
import com.opentrust.spi.cms.CMSForPAdESBasicGenerator;
import com.opentrust.spi.cms.CMSSignedDataWrapper;
import com.opentrust.spi.cms.CMSVerifier;
import com.opentrust.spi.cms.ExceptionHandlerTyped;
import com.opentrust.spi.cms.helpers.ContentSignerWithProvidedSignatureValue;
import com.opentrust.spi.cms.helpers.OCSPResponse;
import com.opentrust.spi.cms.helpers.SignatureHelper;
import com.opentrust.spi.crypto.CryptoConstants;
import com.opentrust.spi.crypto.DigestHelper;
import com.opentrust.spi.crypto.CryptoConstants.AlgorithmID;
import com.opentrust.spi.crypto.CryptoConstants.AlgorithmType;
import com.opentrust.spi.crypto.ExceptionHandler;
import com.opentrust.spi.logger.Channel;
import com.opentrust.spi.logger.SPILogger;
//import com.opentrust.spi.ocsp.OCSPResponse;
import com.opentrust.spi.tsp.TimeStampProcessor;
import com.opentrust.spi.tsp.TimeStampProcessorFactory;
import com.opentrust.spi.tsp.TimestampToken;
import com.opentrust.spi.tsp.impl.BCTimeStampToken;
import com.spilowagie.text.ExceptionConverter;
import com.spilowagie.text.pdf.AcroFields;
import com.spilowagie.text.pdf.PdfName;

/**
 * This class does all the processing related to signing and verifying a PKCS#7 or PKCS#1 PDF-embedded
 * signature.
 * <p>
 * It's based in code found at org.bouncycastle.
 */
public class PDFEnvelopedSignature {
	private static SPILogger log = SPILogger.getLogger("PDFSIGN");

	private Collection<OCSPResponse> ocspResponses;
	
	private String timeStampDigestAlgo;
	
	private String timeStampPolicyId;
	
	private boolean timeStampUseNonce;
	
	private int version, signerversion;
	private ASN1ObjectIdentifier cmsContentType;

	private Collection certs, crls;

	private X509Certificate signCert;

	private byte[] pkcs1SigValue;

	private String dataDigestAlgorithm, keyAndParameterAlgorithm;

	private Signature sig;

	private byte adbePkcs7Sha1Data[];
	
	private TimestampToken timestampToken;
 
    private static final String ID_RSA = AlgorithmID.KEY_RSA.getOID();
    private static final String ID_DSA = "1.2.840.10040.4.1";

    /**
     * properties from PDF signature dictionary (M, Location, Reason, ContactInfo)
     */
    private String reason;
    private String location;
    private String contactInfo;
    private byte[] dictionaryCert;
    private int[] byteRange;
    private byte[] contentsKey; // the original <CONTENTS> content
    
    // Used to retrieve info for signature (revision, coversWholeDocument, fieldPositions...)
    private AcroFields acroFields;
    private String signatureFieldName;
    
    private Calendar dicoSignDate;

    private Calendar cmsSignDate;
	
    /**
     * Holds value of property signName.
     */
    private String signName;
    
    private CMSSignedDataWrapper cmsSignature;
    private MessageDigest verifyDigest;
    private MessageDigest contentTimestampVerifyDigest;
    private OutputStream sigOut;
    private ByteArrayOutputStream bOut;
    private CMSSignedDataStreamGenerator cmsGenerator;
    
    TimestampToken docTimestampTStoken;//For "Document TimeStamp" signatures (PAdES LTV)

    ITspClient tspClient;
	public ITspClient getTspClient() {
		return tspClient;
	}

	public void setTspClient(ITspClient tspClient) {
		this.tspClient = tspClient;
	}

	private String subFilter;
		public static String SF_ADBE_X509_RSA_SHA1 = "adbe.x509.rsa_sha1";
		public static String SF_ADBE_PKCS7_DETACHED = "adbe.pkcs7.detached";
		public static String SF_ADBE_PKCS7_SHA1 = "adbe.pkcs7.sha1";
		public static String SF_ETSI_CADES_DETACHED = "ETSI.CAdES.detached";
		public static String SF_ETSI_RFC3161 = "ETSI.RFC3161";
    		
    // PKCS#1 signature verification
    /**
     * Verifies a signature using the sub-filter adbe.x509.rsa_sha1.
     * @param contentsKey the /Contents key
     * @param certsKey the /Cert key
     * @param provider the provider or <code>null</code> for the default provider
     */    
    public PDFEnvelopedSignature(byte[] contentsKey, byte[] certsKey, String provider, AcroFields acroFields, String signatureFieldName) {
        try {
    		log.debug(Channel.TECH, "Verifying a adbe.x509.rsa_sha1 signature");
    		this.acroFields = acroFields;
    		this.signatureFieldName = signatureFieldName;
    		this.subFilter = SF_ADBE_X509_RSA_SHA1;
    		this.dictionaryCert = certsKey;
            X509CertParser cr = new X509CertParser();
            cr.engineInit(new ByteArrayInputStream(certsKey));
            certs = cr.engineReadAll();
            signCert = (X509Certificate)certs.iterator().next();
		    crls = new ArrayList();
            ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(contentsKey));
            pkcs1SigValue = ((DEROctetString)in.readObject()).getOctets();
            
		    Cipher c = Cipher.getInstance("RSA/NONE/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
		    c.init(Cipher.DECRYPT_MODE, signCert);
		    byte[] raw = c.doFinal(pkcs1SigValue);
		    ASN1Sequence in3 = (ASN1Sequence)ASN1Object.fromByteArray(raw);
		    DigestInfo di = DigestInfo.getInstance(in3);
		    dataDigestAlgorithm = di.getAlgorithmId().getAlgorithm().getId();
		    keyAndParameterAlgorithm = ID_RSA;
		    
            if (provider == null)
                sig = Signature.getInstance(getSignatureAlgorithm());
            else
                sig = Signature.getInstance(getSignatureAlgorithm(), provider);
            sig.initVerify(signCert.getPublicKey());
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }
	
	/**
     * Verifies a signature using the sub-filter adbe.pkcs7.detached or
     * adbe.pkcs7.sha1 or ETSI.CAdES.detached or ETSI.RFC3161
     * @param contentsKey the /Contents key
     * @param provider the provider or <code>null</code> for the default provider
	 * @param acroFields 
     */    
    protected PDFEnvelopedSignature(byte[] contentsKey, String provider, PdfName subFilter, AcroFields acroFields, String signatureFieldName) {
    	try {
    		log.debug(Channel.TECH, "Verifying an adbe.pkcs7.detached, adbe.pkcs7.sha1 or ETSI.CAdES.detached signature");
    		this.acroFields = acroFields;
    		this.signatureFieldName = signatureFieldName;
    		this.contentsKey = contentsKey;
    		if(subFilter==PdfName.ADBE_PKCS7_DETACHED) this.subFilter = SF_ADBE_PKCS7_DETACHED;
    		else if(subFilter==PdfName.ADBE_PKCS7_SHA1) this.subFilter = SF_ADBE_PKCS7_SHA1;
    		else if(subFilter==PdfName.ETSI_CADES_DETACHED) this.subFilter = SF_ETSI_CADES_DETACHED;
    		else if(subFilter==PdfName.ETSI_RFC3161) this.subFilter = SF_ETSI_RFC3161;
    		else throw new IllegalArgumentException("Unknown subFilter found in signature dictionary : " + (subFilter==null?null:new String(subFilter.getBytes())));
    		
    		log.debug(Channel.TECH, "Signature subFilter is %1$s", this.subFilter);

    		if(this.subFilter == SF_ETSI_RFC3161) {
    			// Then contentsKey contains a TimeStamptoken
    			//docTimestampTStoken = TimestampTokenManagerFactory.getInstance().getTimeStampToken(contentsKey);
    			docTimestampTStoken = new BCTimeStampToken(contentsKey);
    			dataDigestAlgorithm = docTimestampTStoken.getMessageImprintAlgName();
    			verifyDigest = MessageDigest.getInstance(dataDigestAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
    		} else {
	    		cmsSignature = new CMSSignedDataWrapper(contentsKey); // uses provider BC, not provider given as parameter. TODO ?
		    	// the version
		        version = cmsSignature.getVersion();
		        log.debug(Channel.TECH, "Parsing CMS Data, version=%1$s", version);
		    	
		        cmsContentType = cmsSignature.getContentType();
		        log.debug(Channel.TECH, "Parsing CMS Data, cmsContentType=%1$s", cmsContentType);
		        
		        if (cmsSignature.hasMultipleSignerInfos())
		            throw new IllegalArgumentException("This PKCS#7 object has multiple SignerInfos - only one is supported at this time"); // and even forbidden for PAdES ?
				
		        // the digestAlgorithms property is not fetched. We have no use for it, it is used internally by CMSSignature 
				
				certs = cmsSignature.getSignatureCertificateInfo();
				crls = cmsSignature.getCRLs();
		        ocspResponses = cmsSignature.getOCSPResponses();
				log.debug(Channel.TECH, "Parsing CMS Data, certs=%1$s", certs);
				log.debug(Channel.TECH, "Parsing CMS Data, crls=%1$s", crls);
				log.debug(Channel.TECH, "Parsing CMS Data, ocspResponses=%1$s", ocspResponses);
		
		        signerversion = cmsSignature.getSignerVersion();
				log.debug(Channel.TECH, "Parsing CMS Data, signerversion=%1$s", signerversion);
				
				signCert = (X509Certificate)cmsSignature.getSignerCertificate();
		        if (signCert == null) {
		            throw new IllegalArgumentException("Can't find signing certificate");
		        }
				log.debug(Channel.TECH, "Parsing CMS Data, signCert=%1$s", signCert);
		
				dataDigestAlgorithm = cmsSignature.getDataDigestAlgorithm();
				log.debug(Channel.TECH, "Parsing CMS Data, dataDigestAlgorithm=%1$s", dataDigestAlgorithm);
				keyAndParameterAlgorithm = cmsSignature.getEncryptionAlgorithm();
				log.debug(Channel.TECH, "Parsing CMS Data, keyAndParameterAlgorithm=%1$s", keyAndParameterAlgorithm);
		
				List<TimestampToken> timestps = cmsSignature.getSignatureTimestamps();
				if(!timestps.isEmpty()) {
					timestampToken = timestps.get(0);
					log.debug(Channel.TECH, "Parsing CMS Data, found timestamp token with date %1$s", timestampToken.getDateTime());
				} else log.debug(Channel.TECH, "Parsing CMS Data, no timestamp token found");
				
				// sigAttr and digestAttr properties are not fetched. We have no use for them, they are used internally by CMSSignature
		
				if(cmsSignature.getSigningTime()!=null)  {
					cmsSignDate = Calendar.getInstance();
					cmsSignDate.setTime(cmsSignature.getSigningTime());
				}
				log.debug(Channel.TECH, "Parsing CMS Data, cmsSignDate=%1$s", cmsSignDate);
				
				adbePkcs7Sha1Data = cmsSignature.getEncodedEncapsulatedData();
				if(adbePkcs7Sha1Data!=null) {
					if(this.subFilter != SF_ADBE_PKCS7_SHA1) throw new Exception("Invalid CMS : cannot have encapsulated data for " + this.subFilter + " subfilter");
					verifyDigest = MessageDigest.getInstance("SHA1", BouncyCastleProvider.PROVIDER_NAME);
				} else {
					if(this.subFilter == SF_ADBE_PKCS7_SHA1) throw new Exception("Invalid CMS : must have encapsulated data for " + SF_ADBE_PKCS7_SHA1 + " subfilter");
					verifyDigest = MessageDigest.getInstance(dataDigestAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
					try {
						if(cmsSignature.getContentTimestamp()!=null && cmsSignature.getContentTimestamp().getMessageImprintAlgName()!=null)
							contentTimestampVerifyDigest = MessageDigest.getInstance(cmsSignature.getContentTimestamp().getMessageImprintAlgName(), BouncyCastleProvider.PROVIDER_NAME);
						//TODO : fo not compute digest for ContentTS when digestAlgo is the same as dataDigestAlgorithm
					} catch(Exception e) {
						log.error(Channel.TECH, "Error while parsing content timestamp : %1$s", e);
					}
				}
    		}
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

	/**
     * Used to build a PKCS7 object given all its properties (digest, certs, crls, raw signature, adbePkcs7Sha1...).
     **/
    
    //FIXME : move to other class !!!
   public PDFEnvelopedSignature(byte[] digest, Certificate[] certChain, CRL[] crlList, OCSPResponse[] ocspResponseEncoded, String dataHashAlgorithm, String provider, byte signature[], byte adbePkcs7Sha1Data[], String digestEncryptionAlgorithm, Date signingTime) {
       	try {
       		log.debug(Channel.TECH, "Building PDFEnvelopedSignature object");
       		Hashtable<DERObjectIdentifier, Attribute> signedAttributesHashtable = new Hashtable<DERObjectIdentifier, Attribute>();
			
			List<OCSPResponse> ocspResponses = ocspResponseEncoded==null?null:Arrays.asList(ocspResponseEncoded);
			List<CRL> crls = null;
			if(crlList!=null) {
				crls = Arrays.asList(crlList);
			}
			
			AlgorithmID algorithmID = CryptoConstants.AlgorithmID.valueOfTag(dataHashAlgorithm);
			if (algorithmID == null || algorithmID.getType() != AlgorithmType.DIGEST)
				throw new NoSuchAlgorithmException("Unknown Hash Algorithm " + dataHashAlgorithm);
	
			Attribute messageDigestAttribute = new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(digest)));

			signedAttributesHashtable.put(CMSAttributes.messageDigest, messageDigestAttribute);
        	this.signCert = (X509Certificate)certChain[0];
        	dataDigestAlgorithm = algorithmID.getOID();
        	this.crls =crls;
        	this.certs = Arrays.asList(certChain);
        	this.ocspResponses = ocspResponses;
	        keyAndParameterAlgorithm = digestEncryptionAlgorithm;
    		this.adbePkcs7Sha1Data = adbePkcs7Sha1Data;
			cmsGenerator = (CMSSignedDataStreamGenerator)CMSForPAdESBasicGenerator.buildCMSSignedGenerator(new ContentSignerWithProvidedSignatureValue(signature, AlgorithmID.valueOfTag(getSignatureAlgorithm()).getOID()),
    			true, BouncyCastleProvider.PROVIDER_NAME, signedAttributesHashtable, signCert, certs, signingTime, dataDigestAlgorithm, crls, ocspResponses);
			bOut = new ByteArrayOutputStream();
	        sigOut = cmsGenerator.open(bOut, adbePkcs7Sha1Data!=null);
	        if(adbePkcs7Sha1Data!=null) sigOut.write(adbePkcs7Sha1Data);
	    } catch (Exception e) {
	        throw new ExceptionConverter(e);
	    }
	 }

    /**
     * Update the digest with the specified bytes. This method is used both for signing and verifying
     * @param buf the data buffer
     * @param off the offset in the data buffer
     * @param len the data length
     * @throws SignatureException on error
     */
    public void update(byte[] buf, int off, int len) throws SignatureException {
    	if(sigOut!=null) // adbe.pkcs7.detached or adbe.pkcs7.sha1 (PKCS#7) generation
			try {
				if(adbePkcs7Sha1Data!=null) //adbe.pkcs7.sha1
					verifyDigest.update(buf, off, len); // verifyDigest is used to compute sha1 digest on document
				else // adbe.pkcs7.detached
					sigOut.write(buf, off, len);
			} catch (IOException e) {
				throw new ExceptionConverter(e);
			}
		else if(verifyDigest!=null) { // adbe.pkcs7.detached or adbe.pkcs7.sha1 (PKCS#7) verification
			verifyDigest.update(buf, off, len);
			if(contentTimestampVerifyDigest!=null)
				contentTimestampVerifyDigest.update(buf, off, len); //Also compute digest for contentTimestamp
		}
		else if(sig!=null) //adbe.x509.rsa_sha1 (PKCS#1) verification
			sig.update(buf, off, len);
    }
    
    private boolean verified = false;
    private boolean verificationResult = false;

    /**
     * Verify the signature and digest(s) conformity
     * @throws SignatureException on error
     * @return <CODE>true</CODE> if the signature checks out, <CODE>false</CODE> otherwise
     */
    public boolean verify() {
    	if(!verified) {
	        try {
		        verificationResult = true;
	        	if(verifyDigest!=null) {
	        		if(adbePkcs7Sha1Data!=null) {
	        			// PKCS7 verification (with encapsulated data)
	        			verificationResult = CMSVerifier.verify(cmsSignature) && Arrays.equals(verifyDigest.digest(), cmsSignature.getEncodedEncapsulatedData());
	        		} else if(docTimestampTStoken!=null) {
	        			verificationResult = docTimestampTStoken.verifySignature() && docTimestampTStoken.verifyImprint(verifyDigest.digest());
	        		} else {
	        			verificationResult = CMSVerifier.verifyReference(verifyDigest.digest(), cmsSignature); // PKCS7 verification
	        			if(contentTimestampVerifyDigest!=null)
	        				contentTimestampDigest = contentTimestampVerifyDigest.digest();
	        		}
	        	} else 
	        		verificationResult = sig.verify(pkcs1SigValue); // PKCS1 verification
	        } catch(Exception e) {
	        	ExceptionHandler.handleNoThrow(e, "error while verifying signature");
	        	verificationResult = false;
	        }
	        verified = true;
    	}
    	return verificationResult;
    }

	private byte[] encodedPKCS7;
	/**
     * Gets the bytes for the PKCS7SignedData object (performs actual signing when sigOut not null)
     * @param secondDigest NOT USED
     * @param signingTime NOT USED
     * @return the bytes for the PKCS7SignedData object
     */
    protected byte[] getEncodedPKCS7(byte secondDigest[], String signingTime) {
    	if(encodedPKCS7==null) {
	    	try {
	    		if(cmsSignature==null) {
		    		if(adbePkcs7Sha1Data!=null) //adbe.pkcs7.sha1
		    			sigOut.write(verifyDigest.digest());
			    	sigOut.close();
			    	byte[] bytes = bOut.toByteArray();
			    	this.cmsSignature = new CMSSignedDataWrapper(bytes);
			    	if(getServerTimestamp()!=null) getUpdatedEncodedPKCS7WithAddedTS();
	    		}
	    		encodedPKCS7 = cmsSignature.getEncoded();
	        } catch (Exception e) {
	        	ExceptionHandlerTyped.handle(SignatureException.class, e,"Could not retrieve bytes for signature");
	        }
    	}
        return encodedPKCS7;
    }
    
    public byte[] getUpdatedEncodedPKCS7WithAddedTS() throws NoSuchAlgorithmException, IOException, NoSuchFieldException, TSPException, CMSException {
    	timestampToken = addTSToCMS(cmsSignature,getTimeStampDigestAlgo(), tspClient);
    	return cmsSignature.getEncoded();
    }

    
    public static TimestampToken addTSToCMS(CMSSignedDataWrapper cmsSignature, String algoId, ITspClient tspClient) 
    		throws NoSuchAlgorithmException, IOException, NoSuchFieldException, TSPException, CMSException {
	   	//byte[] tsResponse = getTSResponse2(cmsSignature.getSignatureValue(), user, password, serverTimestamp, algoId, policyId, useNonce);
    	byte[] tsResponse;
		try {
			byte [] digest = DigestHelper.getDigest(cmsSignature.getSignatureValue(), algoId);
			byte [] fullresponse = tspClient.getTsp(digest, algoId);
			TimeStampResponse response = new TimeStampResponse(fullresponse);
			tsResponse = response.getTimeStampToken().getEncoded();
			
		} catch (Exception e) {
			throw new RuntimeException("Error getting timestamp", e);
		}
	   	TimestampToken timestampToken = new BCTimeStampToken(tsResponse);
	   	cmsSignature.appendSignatureTimeStamp(timestampToken.getEncoded());
    	return timestampToken;
    }
    /*
    public static byte[] getTSResponse2(byte[] hash, String user, String password, String serverTimestamp, String algoId, String policyId, boolean useNonce) throws NoSuchAlgorithmException, IOException, NoSuchFieldException, TSPException, CMSException, SPITimestampException {
		TimeStampProcessor timeStampProcessor = TimeStampProcessorFactory.getInstance().
		getTimeStampProcessor(serverTimestamp, policyId, algoId, true);
		return timeStampProcessor.timestamp(hash);
	}
    public static byte[] getTSResponse2(InputStream stream, String user, String password, String serverTimestamp, String algoId, String policyId, boolean useNonce) throws NoSuchAlgorithmException, IOException, NoSuchFieldException, TSPException, CMSException, SPITimestampException {
		TimeStampProcessor timeStampProcessor = TimeStampProcessorFactory.getInstance().
		getTimeStampProcessor(serverTimestamp, policyId, algoId, true);
		return timeStampProcessor.timestamp(stream);
	}	
    
    protected byte [] getTsp(byte [] hash, String hashAlgorithm) throws Exception
    {
    	return tspClient.getTsp(hash, hashAlgorithm);
    }
	*/



    /**
     * Get the X.509 certificates associated with this PKCS#7 object
     * @return the X.509 certificates associated with this PKCS#7 object
     */
    public Certificate[] getCertificates() {
        return (X509Certificate[])certs.toArray(new X509Certificate[certs.size()]);
    }
    
    /**
     * Get the X.509 certificate revocation lists associated with this PKCS#7 object
     * @return the X.509 certificate revocation lists associated with this PKCS#7 object
     */
    public Collection getCRLs() {
        return crls;
    }
    
	/**
	 * Set the X.509 certificate revocation lists associated with this PKCS#7 object
	 * @param crls
	 */
	public void setCRLs(Collection crls) {
		this.crls = crls;
	}
	
	/**
     * Get the X.509 certificate actually used to sign the digest.
     * @return the X.509 certificate actually used to sign the digest
     */
    public X509Certificate getSigningCertificate() {
        return signCert;
    }
    
    /**
     * Get the version of the PKCS#7 object. Always 1
     * @return the version of the PKCS#7 object. Always 1
     */
    public int getVersion() {
        return version;
    }
    
    /**
     * Get the version of the PKCS#7 "SignerInfo" object. Always 1
     * @return the version of the PKCS#7 "SignerInfo" object. Always 1
     */
    public int getSigningInfoVersion() {
        return signerversion;
    }
    
	public ASN1ObjectIdentifier getCmsContentType() {
		return cmsContentType;
	}

	/**
	 * Get the algorithm used to calculate the message digest
	 * 
	 * @return the algorithm used to calculate the message digest
	 */
	public String getSignatureAlgorithm() {
		if(keyAndParameterAlgorithm==null) return null;
		String dea = keyAndParameterAlgorithm;
		if (keyAndParameterAlgorithm.equals(ID_RSA)) dea = "RSA";
		else if (keyAndParameterAlgorithm.equals(ID_DSA)) dea = "DSA";
		else {
			AlgorithmID algo = AlgorithmID.valueOfOID(keyAndParameterAlgorithm);
			if(algo==null) algo = AlgorithmID.valueOfTag(keyAndParameterAlgorithm);
			
			if (algo.equals(CryptoConstants.AlgorithmID.SIGNATURE_RSA_MD5)
					|| algo.equals(CryptoConstants.AlgorithmID.SIGNATURE_RSA_RIPEMD160) || algo.equals(CryptoConstants.AlgorithmID.SIGNATURE_RSA_SHA1)
					|| algo.equals(CryptoConstants.AlgorithmID.SIGNATURE_RSA_SHA256) || algo.equals(CryptoConstants.AlgorithmID.SIGNATURE_RSA_SHA384)
					|| algo.equals(CryptoConstants.AlgorithmID.SIGNATURE_RSA_SHA512)) {
				dea = "RSA";
			} else if (algo.equals(CryptoConstants.AlgorithmID.SIGNATURE_DSA_SHA1)) {
				dea = "DSA";
			}
		}

		return SignatureHelper.getSignatureAlgoFromDigestAndKeyAlgo(getDataDigestAlgorithm(), dea);
	}

	/**
	 * Returns the algorithm.
	 * 
	 * @return the digest algorithm
	 */
	public String getDataDigestAlgorithm() {
		String da = dataDigestAlgorithm;

		AlgorithmID algorithmID = CryptoConstants.AlgorithmID.valueOfOID(dataDigestAlgorithm);
		if (algorithmID != null)
			da = algorithmID.getTag();
		return da;
	}

    /**
     * Loads the default root certificates at &lt;java.home&gt;/lib/security/cacerts
     * with the default provider.
     * @return a <CODE>KeyStore</CODE>
     */    
    public static KeyStore loadCacertsKeyStore() {
        return loadCacertsKeyStore(null);
    }

    /**
     * Loads the default root certificates at &lt;java.home&gt;/lib/security/cacerts.
     * @param provider the provider or <code>null</code> for the default provider
     * @return a <CODE>KeyStore</CODE>
     */    
    public static KeyStore loadCacertsKeyStore(String provider) {
        File file = new File(System.getProperty("java.home"), "lib");
        file = new File(file, "security");
        file = new File(file, "cacerts");
        FileInputStream fin = null;
        try {
            fin = new FileInputStream(file);
            KeyStore k;
            if (provider == null)
                k = KeyStore.getInstance("JKS");
            else
                k = KeyStore.getInstance("JKS", provider);
            k.load(fin, null);
            return k;
        }
        catch (Exception e) {
            throw new ExceptionConverter(e);
        }
        finally {
            try{if (fin != null) {fin.close();}}catch(Exception ex){}
        }
    }
    
    /**
     * Verifies a single certificate.
     * @param cert the certificate to verify
     * @param crls the certificate revocation list or <CODE>null</CODE>
     * @param calendar the date or <CODE>null</CODE> for the current date
     * @return a <CODE>String</CODE> with the error description or <CODE>null</CODE>
     * if no error
     */    
    public static String verifyCertificate(X509Certificate cert, Collection crls, OCSPResponse ocspResponse, Calendar calendar) {
        if (calendar == null)
            calendar = new GregorianCalendar();
        if (cert.hasUnsupportedCriticalExtension())
            return "Has unsupported critical extension";
        try {
            cert.checkValidity(calendar.getTime());
        }
        catch (Exception e) {
            return e.getMessage();
        }
        if (crls != null) {
            for (Iterator it = crls.iterator(); it.hasNext();) {
                if (((CRL)it.next()).isRevoked(cert))
                    return "Certificate revoked";
            }
        }
        if (ocspResponse != null) {
        	//TODO implement OCSP response validation
        	log.debug(Channel.TECH, "Certificate validation against OCSP response not implemented, skipped");
        }
        return null;
    }
    
    /**
     * Verifies a certificate chain against a KeyStore.
     * @param certs the certificate chain
     * @param keystore the <CODE>KeyStore</CODE>
     * @param crls the certificate revocation list or <CODE>null</CODE>
     * @param calendar the date or <CODE>null</CODE> for the current date
     * @return <CODE>null</CODE> if the certificate chain could be validated or a
     * <CODE>Object[]{cert,error}</CODE> where <CODE>cert</CODE> is the
     * failed certificate and <CODE>error</CODE> is the error message
     */    
    public static Object[] verifyCertificates(Certificate certs[], KeyStore keystore, Collection crls, OCSPResponse ocspResponse, Calendar calendar) {
        if (calendar == null)
            calendar = new GregorianCalendar();
        for (int k = 0; k < certs.length; ++k) {
            X509Certificate cert = (X509Certificate)certs[k];
            String err = verifyCertificate(cert, crls, ocspResponse, calendar);
            if (err != null)
                return new Object[]{cert, err};
            try {
                for (Enumeration aliases = keystore.aliases(); aliases.hasMoreElements();) {
                    try {
                        String alias = (String)aliases.nextElement();
                        if (!keystore.isCertificateEntry(alias))
                            continue;
                        X509Certificate certStoreX509 = (X509Certificate)keystore.getCertificate(alias);
                        if (verifyCertificate(certStoreX509, crls, ocspResponse, calendar) != null)
                            continue;
                        try {
                            cert.verify(certStoreX509.getPublicKey());
                            return null;
                        }
                        catch (Exception e) {
                            continue;
                        }
                    }
                    catch (Exception ex) {
                    }
                }
            }
            catch (Exception e) {
            }
            int j;
            for (j = 0; j < certs.length; ++j) {
                if (j == k)
                    continue;
                X509Certificate certNext = (X509Certificate)certs[j];
                try {
                    cert.verify(certNext.getPublicKey());
                    break;
                }
                catch (Exception e) {
                }
            }
            if (j == certs.length)
                return new Object[]{cert, "Cannot be verified against the KeyStore or the certificate chain"};
        }
        return new Object[]{null, "Invalid state. Possible circular certificate chain"};
    }

    /**
     * Get the "issuer" from the TBSCertificate bytes that are passed in
     * @param enc a TBSCertificate in a byte array
     * @return a DERObject
     */
    private static DERObject getIssuer(byte[] enc) {
        try {
            ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(enc));
            ASN1Sequence seq = (ASN1Sequence)in.readObject();
            return (DERObject)seq.getObjectAt(seq.getObjectAt(0) instanceof DERTaggedObject ? 3 : 2);
        }
        catch (IOException e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Get the "subject" from the TBSCertificate bytes that are passed in
     * @param enc A TBSCertificate in a byte array
     * @return a DERObject
     */
    private static DERObject getSubject(byte[] enc) {
        try {
            ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(enc));
            ASN1Sequence seq = (ASN1Sequence)in.readObject();
            return (DERObject)seq.getObjectAt(seq.getObjectAt(0) instanceof DERTaggedObject ? 5 : 4);
        }
        catch (IOException e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Get the issuer fields from an X509 Certificate
     * @param cert an X509Certificate
     * @return an X509Name
     */
    public static X509Name getIssuerFields(X509Certificate cert) {
        try {
            return new X509Name((ASN1Sequence)getIssuer(cert.getTBSCertificate()));
        }
        catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Get the subject fields from an X509 Certificate
     * @param cert an X509Certificate
     * @return an X509Name
     */
    public static X509Name getSubjectFields(X509Certificate cert) {
        try {
            return new X509Name((ASN1Sequence)getSubject(cert.getTBSCertificate()));
        }
        catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }
    
    /**
     * Gets the bytes for the PKCS#1 object.
     * @return a byte array
     */
    public byte[] getEncodedPKCS1() {
        try {
//            if (externalDigest != null)
//                digest = externalDigest;
//            else
                pkcs1SigValue = sig.sign();
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            
            ASN1OutputStream dout = new ASN1OutputStream(bOut);
            dout.writeObject(new DEROctetString(pkcs1SigValue));
            dout.close();
            
            return bOut.toByteArray();
        }
        catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }
    
    /**
     * @deprecated not used anymore
     */    
    public void setExternalDigest(byte signature[], byte adbePkcs7Sha1Data[], String digestEncryptionAlgorithm) {
    }
    
    /**
     * Gets the bytes for the PKCS7SignedData object.
     * @return the bytes for the PKCS7SignedData object
     * @throws SPISignatureException 
     */
    public byte[] getEncodedPKCS7(){
        return getEncodedPKCS7(null, null);
    }
    
	/**
	 * Holds value of properties for timestamp server.
	 */
	private String usernameTimestamp = null;

	private String passwordTimestamp = null;

	private String serverTimestamp = null;

    public byte[] getSignedAttrs() throws IOException {
    	return cmsSignature.getEncodedSignedAttrs();
    }
    
    /**
     * @deprecated not used anymore
     */    
    public byte[] getAuthenticatedAttributeBytes(byte secondDigest[], Calendar signingTime) {
    	return null;
    }

    public String getReason() {
        return this.reason;
    }
    
    public void setReason(String reason) {
        this.reason = reason;
    }
    
    public String getLocation() {
        return this.location;
    }
    
    public void setLocation(String location) {
        this.location = location;
    }
    
    public String getContactInfo() {
		return contactInfo;
	}

	public void setContactInfo(String contactInfo) {
		this.contactInfo = contactInfo;
	}

    public byte[] getDictionaryCert() {
		return dictionaryCert;
	}

	public void setDictionaryCert(byte[] dictionaryCert) {
		this.dictionaryCert = dictionaryCert;
	}

	public int[] getByteRange() {
		return byteRange;
	}

	public void setByteRange(int[] byteRange) {
		this.byteRange = byteRange;
	}

	public byte[] getCONTENTSContent() {
		return contentsKey;
	}

	private int xRefComputedRevision;
	public void setXRefComputedRevision(int xRefComputedRevision) {
		this.xRefComputedRevision = xRefComputedRevision;
	}
	public int getXRefComputedRevision() {
		return xRefComputedRevision;
	}
	
	//AcroFields properties
	public boolean signatureCoversWholeDocument() {
		return acroFields.signatureCoversWholeDocument(signatureFieldName);
	}
	public int getRevision() {
		return acroFields.getRevision(signatureFieldName);
	}
	public int getTotalRevisions() {
		return acroFields.getTotalRevisions();
	}
	public int getRevisionLength() {
		return acroFields.getRevisionLength(signatureFieldName);
	}
	public float[] getFieldPositions() {
		return acroFields.getFieldPositions(signatureFieldName);
	}
	public List<String> getSignatureNames() {
		return acroFields.getSignatureNames();
	}
	
	public List<String> getSignatureNames(boolean withDocTS) {
		return acroFields.getSignatureNames(withDocTS);
	}

	public String getSubFilter() {
		return subFilter;
	}

    public Calendar getSignDate() {
        return this.dicoSignDate!=null?this.dicoSignDate:this.cmsSignDate;
    }
    
    public Calendar getDicoSignDate() {
        return this.dicoSignDate;
    }

    public Calendar getCmsSignDate() {
		return this.cmsSignDate;
	}

    public void setDicoSignDate(Calendar signDate) {
        this.dicoSignDate = signDate;
    }
    
    public String getSignName() {
        return this.signName;
    }
    
    public void setSignName(String signName) {
        this.signName = signName;
    }
    
    /**
     * a class that holds an X509 name
     */
    public static class X509Name {
        /**
         * country code - StringType(SIZE(2))
         */
        public static final DERObjectIdentifier C = new DERObjectIdentifier("2.5.4.6");

        /**
         * organization - StringType(SIZE(1..64))
         */
        public static final DERObjectIdentifier O = new DERObjectIdentifier("2.5.4.10");

        /**
         * organizational unit name - StringType(SIZE(1..64))
         */
        public static final DERObjectIdentifier OU = new DERObjectIdentifier("2.5.4.11");

        /**
         * Title
         */
        public static final DERObjectIdentifier T = new DERObjectIdentifier("2.5.4.12");

        /**
         * common name - StringType(SIZE(1..64))
         */
        public static final DERObjectIdentifier CN = new DERObjectIdentifier("2.5.4.3");

        /**
         * device serial number name - StringType(SIZE(1..64))
         */
        public static final DERObjectIdentifier SN = new DERObjectIdentifier("2.5.4.5");

        /**
         * locality name - StringType(SIZE(1..64))
         */
        public static final DERObjectIdentifier L = new DERObjectIdentifier("2.5.4.7");

        /**
         * state, or province name - StringType(SIZE(1..64))
         */
        public static final DERObjectIdentifier ST = new DERObjectIdentifier("2.5.4.8");

        /** Naming attribute of type X520name */
        public static final DERObjectIdentifier SURNAME = new DERObjectIdentifier("2.5.4.4");
        /** Naming attribute of type X520name */
        public static final DERObjectIdentifier GIVENNAME = new DERObjectIdentifier("2.5.4.42");
        /** Naming attribute of type X520name */
        public static final DERObjectIdentifier INITIALS = new DERObjectIdentifier("2.5.4.43");
        /** Naming attribute of type X520name */
        public static final DERObjectIdentifier GENERATION = new DERObjectIdentifier("2.5.4.44");
        /** Naming attribute of type X520name */
        public static final DERObjectIdentifier UNIQUE_IDENTIFIER = new DERObjectIdentifier("2.5.4.45");

        /**
         * Email address (RSA PKCS#9 extension) - IA5String.
         * <p>Note: if you're trying to be ultra orthodox, don't use this! It shouldn't be in here.
         */
        public static final DERObjectIdentifier EmailAddress = new DERObjectIdentifier("1.2.840.113549.1.9.1");

        /**
         * email address in Verisign certificates
         */
        public static final DERObjectIdentifier E = EmailAddress;

        /** object identifier */
        public static final DERObjectIdentifier DC = new DERObjectIdentifier("0.9.2342.19200300.100.1.25");

        /** LDAP User id. */
        public static final DERObjectIdentifier UID = new DERObjectIdentifier("0.9.2342.19200300.100.1.1");

        /** A LinkedHashMap with default symbols */
        public static LinkedHashMap DefaultSymbols = new LinkedHashMap();
        
        static {
            DefaultSymbols.put(C, "C");
            DefaultSymbols.put(O, "O");
            DefaultSymbols.put(T, "T");
            DefaultSymbols.put(OU, "OU");
            DefaultSymbols.put(CN, "CN");
            DefaultSymbols.put(L, "L");
            DefaultSymbols.put(ST, "ST");
            DefaultSymbols.put(SN, "SN");
            DefaultSymbols.put(EmailAddress, "E");
            DefaultSymbols.put(DC, "DC");
            DefaultSymbols.put(UID, "UID");
            DefaultSymbols.put(SURNAME, "SURNAME");
            DefaultSymbols.put(GIVENNAME, "GIVENNAME");
            DefaultSymbols.put(INITIALS, "INITIALS");
            DefaultSymbols.put(GENERATION, "GENERATION");
        }
        /** A LinkedHashMap with values */
        public LinkedHashMap values = new LinkedHashMap();

        /**
         * Constructs an X509 name
         * @param seq an ASN1 Sequence
         */
        public X509Name(ASN1Sequence seq) {
            Enumeration e = seq.getObjects();
            
            while (e.hasMoreElements()) {
                ASN1Set set = (ASN1Set)e.nextElement();
                
                for (int i = 0; i < set.size(); i++) {
                    ASN1Sequence s = (ASN1Sequence)set.getObjectAt(i);
                    String id = (String)DefaultSymbols.get(s.getObjectAt(0));
                    if (id == null)
                        continue;
                    ArrayList vs = (ArrayList)values.get(id);
                    if (vs == null) {
                        vs = new ArrayList();
                        values.put(id, vs);
                    }
                    vs.add(((DERString)s.getObjectAt(1)).getString());
                }
            }
        }
        /**
         * Constructs an X509 name
         * @param dirName a directory name
         */
        public X509Name(String dirName) {
            X509NameTokenizer   nTok = new X509NameTokenizer(dirName);
            
            while (nTok.hasMoreTokens()) {
                String  token = nTok.nextToken();
                int index = token.indexOf('=');
                
                if (index == -1) {
                    throw new IllegalArgumentException("badly formated directory string");
                }
                
                String id = token.substring(0, index).toUpperCase();
                String value = token.substring(index + 1);
                ArrayList vs = (ArrayList)values.get(id);
                if (vs == null) {
                    vs = new ArrayList();
                    values.put(id, vs);
                }
                vs.add(value);
            }
            
        }
        
        public String getField(String name) {
            ArrayList vs = (ArrayList)values.get(name);
            return vs == null ? null : (String)vs.get(0);
        }

        /**
         * gets a field array from the values LinkedHashMap
         * @param name
         * @return an ArrayList
         */
        public ArrayList getFieldArray(String name) {
            ArrayList vs = (ArrayList)values.get(name);
            return vs == null ? null : vs;
        }
        
        /**
         * getter for values
         * @return a LinkedHashMap with the fields of the X509 name
         */
        public LinkedHashMap getFields() {
            return values;
        }
        
        /**
         * @see java.lang.Object#toString()
         */
        public String toString() {
            return values.toString();
        }
    }
    
    /**
     * class for breaking up an X500 Name into it's component tokens, ala
     * java.util.StringTokenizer. We need this class as some of the
     * lightweight Java environment don't support classes like
     * StringTokenizer.
     */
    public static class X509NameTokenizer {
        private String          oid;
        private int             index;
        private StringBuffer    buf = new StringBuffer();
        
        public X509NameTokenizer(
        String oid) {
            this.oid = oid;
            this.index = -1;
        }
        
        public boolean hasMoreTokens() {
            return (index != oid.length());
        }
        
        public String nextToken() {
            if (index == oid.length()) {
                return null;
            }
            
            int     end = index + 1;
            boolean quoted = false;
            boolean escaped = false;
            
            buf.setLength(0);
            
            while (end != oid.length()) {
                char    c = oid.charAt(end);
                
                if (c == '"') {
                    if (!escaped) {
                        quoted = !quoted;
                    }
                    else {
                        buf.append(c);
                    }
                    escaped = false;
                }
                else {
                    if (escaped || quoted) {
                        buf.append(c);
                        escaped = false;
                    }
                    else if (c == '\\') {
                        escaped = true;
                    }
                    else if (c == ',') {
                        break;
                    }
                    else {
                        buf.append(c);
                    }
                }
                end++;
            }
            
            index = end;
            return buf.toString().trim();
        }
    }
    
	public String getPasswordTimestamp() {
		return passwordTimestamp;
	}

	public void setPasswordTimestamp(String passwordTimestamp) {
		this.passwordTimestamp = passwordTimestamp;
	}

	public String getServerTimestamp() {
		return serverTimestamp;
	}

	public void setServerTimestamp(String serverTimestamp) {
		this.serverTimestamp = serverTimestamp;
	}

	public String getUsernameTimestamp() {
		return usernameTimestamp;
	}

	public void setUsernameTimestamp(String usernameTimestamp) {
		this.usernameTimestamp = usernameTimestamp;
	}

	public byte[] getSignatureValue() {
		return cmsSignature.getSignatureValue();
	}

	public byte[] getDigest() {
		return cmsSignature.getDigestAttribute();
	}

	private byte[] contentTimestampDigest;
	public byte[] getContentTimestampDigest() {
		return contentTimestampDigest;
	}
	
	
	public ESSCertID getSigningCertificateAttribute() {
		return cmsSignature.getSigningCertificateAttribute();
	}

	public ESSCertIDv2 getSigningCertificateV2Attribute() {
		return cmsSignature.getSigningCertificateV2Attribute();
	}

	public SignaturePolicyIdentifier getSignaturePolicyIdentifierAttribute() {
		return cmsSignature.getSignaturePolicyIdentifierAttribute();
	}

	public SignerInformationStore getCounterSignatures() {
		return cmsSignature.getCounterSignatures();
	}

	public DEREncodable getContentTypeAttribute() {
		return cmsSignature.getContentTypeAttribute();
	}

	public DEREncodable getContentReferenceAttribute() {
		return cmsSignature.getContentReferenceAttribute();
	}

	public ContentIdentifier getContentIdentifierAttribute() {
		return cmsSignature.getContentIdentifierAttribute();
	}

	public ContentHints getContentHintsAttribute() {
		return cmsSignature.getContentHintsAttribute();
	}

	public CommitmentTypeIndication getCommitmentTypeIndicationAttribute() {
		return cmsSignature.getCommitmentTypeIndicationAttribute();
	}

	public SignerLocation getSignerLocationAttribute() {
		return cmsSignature.getSignerLocationAttribute();
	}

	public SignerAttribute getSignerAttributesAttribute() {
		return cmsSignature.getSignerAttributesAttribute();
	}

	public TimestampToken getContentTimestamp() {
		try {
			return cmsSignature.getContentTimestamp();
		} catch (Exception e) {
			throw new ExceptionConverter(e);
		}
	}

	public TimestampToken getDocTimeStampValue() {
		return this.docTimestampTStoken;
	}
	
	public Signature getSig() {
		return sig;
	}

	public void setSig(Signature sig) {
		this.sig = sig;
	}

	public TimestampToken getTimestampToken() {
		return timestampToken;
	}

	public String getTimeStampDigestAlgo() {
		return timeStampDigestAlgo;
	}

	public void setTimeStampDigestAlgo(String timeStampDigestAlgo) {
		this.timeStampDigestAlgo = timeStampDigestAlgo;
	}

	public String getTimeStampPolicyId() {
		return timeStampPolicyId;
	}

	public void setTimeStampPolicyId(String timeStampPolicyId) {
		this.timeStampPolicyId = timeStampPolicyId;
	}

	public boolean isTimeStampUseNonce() {
		return timeStampUseNonce;
	}

	public void setTimeStampUseNonce(boolean timeStampUseNonce) {
		this.timeStampUseNonce = timeStampUseNonce;
	}

	public void setOcspResponses(Collection<OCSPResponse> ocspResponses) {
		this.ocspResponses = ocspResponses;
	}

	public Collection<OCSPResponse> getOcspResponses() {
		return ocspResponses;
	}

	public String getSignatureFieldName() {
		return signatureFieldName;
	}
}
