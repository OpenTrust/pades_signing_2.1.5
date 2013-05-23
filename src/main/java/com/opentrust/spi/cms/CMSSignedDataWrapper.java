package com.opentrust.spi.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
import org.bouncycastle.asn1.esf.SignerAttribute;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.ess.ContentHints;
import org.bouncycastle.asn1.ess.ContentIdentifier;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import com.opentrust.spi.cms.helpers.OCSPResponse;
import com.opentrust.spi.cms.helpers.SignatureHelper;
import com.opentrust.spi.cms.helpers.SignedAttributesHelper;
import com.opentrust.spi.cms.helpers.UnsignedAttributesHelper;
import com.opentrust.spi.logger.Channel;
import com.opentrust.spi.logger.SPILogger;
import com.opentrust.spi.tsp.TimestampToken;


public class CMSSignedDataWrapper {
	private static SPILogger log = SPILogger.getLogger("CMS");

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	protected CMSSignedData cmsSignedData = null;
	protected SignerInformation firstSignerInfo = null;
	protected List<TimestampToken> signatureTimeStamps = null;
	protected boolean hasMultipleSignerInfos = false;

	public CMSSignedDataWrapper(InputStream inputStream) throws SignatureException, CMSException {
		this(new CMSSignedData(inputStream));
	}
	
	public CMSSignedDataWrapper(byte[] data) throws SignatureException, CMSException {
		this(new CMSSignedData(data));
	}

	public CMSSignedDataWrapper(CMSSignedData cmsSignedData) {
		try {
			this.cmsSignedData = cmsSignedData;
			parseCms();
		} catch (Exception e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
	}
	
	private void parseCms() {
		Collection signers = cmsSignedData.getSignerInfos().getSigners();
		if(signers.size()!=1) 
			hasMultipleSignerInfos = true;
		
		Iterator iterator = signers.iterator();
		firstSignerInfo = (SignerInformation) iterator.next();		
	}
	
	public boolean hasMultipleSignerInfos() {
		return hasMultipleSignerInfos;
	}
	
	public ASN1ObjectIdentifier getContentType() {
		ContentInfo ci = cmsSignedData.getContentInfo();
		if(ci==null) return null;
		return ci.getContentType();
	}

	public int getVersion() {
		return cmsSignedData.getVersion();
	}
	
	public int getSignerVersion() {
		return firstSignerInfo.getVersion();
	}

	public void appendSignatureTimeStamp(byte[] timeStampTokenBytes) {
		try {
			AttributeTable at = firstSignerInfo.getUnsignedAttributes();
			firstSignerInfo = SignerInformation.replaceUnsignedAttributes(firstSignerInfo, appendTimestampAttribute(timeStampTokenBytes, at));
			Collection<SignerInformation> signers = new ArrayList<SignerInformation>(1);
			signers.add(firstSignerInfo);
			SignerInformationStore sis = new SignerInformationStore(signers);
			cmsSignedData = CMSSignedData.replaceSigners(cmsSignedData, sis);
		} catch (Exception e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
	}

	protected static AttributeTable appendTimestampAttribute(
			byte[] timeStampTokenBytes, AttributeTable attributeTable)
	{
		Hashtable unsignedAttributesHT;
		if (attributeTable == null) {
			unsignedAttributesHT = new Hashtable();
		} else {
			unsignedAttributesHT = attributeTable.toHashtable();
		}
		
		try {
			UnsignedAttributesHelper.addTimestampAttribute(unsignedAttributesHT, timeStampTokenBytes);
		} catch(Exception e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
		attributeTable = new AttributeTable(unsignedAttributesHT);
		return attributeTable;
	}

	// adds unsigned certs & revocation infos (CRL or OCSP) to existing certs & revocation info list ('certificates' and 'crls' CMS fields)
	public void appendValidationValues(Collection certificateValues, Collection revocationValues) {
		try {
			Store certStore = cmsSignedData.getCertificates();
			Store crlStore = cmsSignedData.getCRLs();
	
			if (certificateValues != null && !certificateValues.isEmpty()) {
				Collection<Certificate> existingCerts = getSignatureCertificateInfo();
				Set<Certificate> newCerts = new HashSet<Certificate>(existingCerts); // 'Set' to avoid duplicates
				newCerts.addAll(certificateValues);
				certStore = new JcaCertStore(newCerts);
			}
			
			if (revocationValues != null && !revocationValues.isEmpty()) {
				Collection<CRL> existingCrls = getUnsignedCRLs();
				Set<CRL> newCrls = new HashSet<CRL>(existingCrls); // 'Set' to avoid duplicates
				//FIXME : also add OCSP info (use OtherRevocationInfoFormat of RevocationInfoChoices, see RFC 3852)
				for(Object o : revocationValues) {
					if(o instanceof CRL) newCrls.add((CRL)o);
				}
				crlStore = new JcaCRLStore(newCrls);
			}

			cmsSignedData = CMSSignedData.replaceCertificatesAndCRLs(cmsSignedData, certStore, cmsSignedData.getAttributeCertificates(), crlStore);
		} catch (Exception e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
	}

	public byte[] getEncoded() {
		try {
			return cmsSignedData.getEncoded();
		} catch (IOException e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
		return null;
	}

	public String getSignatureAlgorithm() {
		return SignatureHelper.getSignatureAlgoFromDigestAndKeyAlgo(getDataDigestAlgorithm(), getEncryptionAlgorithm());
	}

	public String getDataDigestAlgorithm() {
		return firstSignerInfo.getDigestAlgOID();
	}

	public String getEncryptionAlgorithm() {
		return firstSignerInfo.getEncryptionAlgOID();
	}

	public List<Certificate> getSignatureCertificateInfo() {
		try {
			Store certificateStore = cmsSignedData.getCertificates();
			Collection<X509CertificateHolder> certificateCollection = certificateStore.getMatches(null);
			List<Certificate> x509CertsCollection = new ArrayList<Certificate>(certificateCollection.size());
			for(X509CertificateHolder certHolder : certificateCollection) {
				x509CertsCollection.add(CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME).generateCertificate(new ByteArrayInputStream(certHolder.getEncoded())));
			}
			return x509CertsCollection;
		} catch (Exception e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
		return null;
	}
	
	public Collection<CRL> getCRLs() {
		Collection<CRL> crls = new HashSet<CRL>();
		try {
			crls.addAll(getUnsignedCRLs());
			crls.addAll(getSignedCRLs());
			return crls;
		} catch (Exception e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
		return crls;
	}
	
	// unsigned CRLs at the root of CMS structure (outside signerInfos)
	public Collection<CRL> getUnsignedCRLs() {
		try {
			Collection<CertificateList> crlCollection = cmsSignedData.getCRLs().getMatches(null);
			
			// Then we need to "cast" from bouncycastle.CertificateList to java.CRL
			Collection<CRL> x509CrlsCollection = new HashSet<CRL>(crlCollection.size());
			for(CertificateList certList : crlCollection) {
				x509CrlsCollection.add(CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME).generateCRL(new ByteArrayInputStream(certList.getEncoded())));
			}
			return x509CrlsCollection;
		} catch (Exception e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
		return null;
	}
	
	// CRLS found as signed ID_ADBE_REVOCATION attribute
	public Collection<CRL> getSignedCRLs() {
		try {
			AttributeTable table = firstSignerInfo.getSignedAttributes();
			return SignedAttributesHelper.getSignedCRLs(table);
		} catch (Exception e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
		return null;
	}
	
	public CertStore getSignatureCRLStore() {
		try {
			CertStore crlStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(getCRLs()), BouncyCastleProvider.PROVIDER_NAME);
			return crlStore;
		} catch (Exception e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
		return null;
	}

	public Set<OCSPResponse> getOCSPResponses() {
		try {
			Set<OCSPResponse> ocspResponses = getUnsignedOCSPResponses();
			ocspResponses.addAll(getSignedOCSPResponses());
			return ocspResponses;
		} catch (Exception e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
		return null;
	}
	
	// OCSP responses found as signed ID_ADBE_REVOCATION attribute
	public Set<OCSPResponse> getSignedOCSPResponses() {
		try {
			AttributeTable table = firstSignerInfo.getSignedAttributes();
			return SignedAttributesHelper.getSignedOCSPResponses(table);
		} catch (Exception e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
		return null;
	}
	
	// unsigned OCSPs at the root of CMS structure (outside signerInfos)
	public Set<OCSPResponse> getUnsignedOCSPResponses() {
		try {
			//FIXME : really fetch those values !
			Set<OCSPResponse> ocspResponses = new HashSet<OCSPResponse>();
			return ocspResponses;
		} catch (Exception e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
		return null;
	}
	
	public List<TimestampToken> getSignatureTimestamps() {
		if (signatureTimeStamps == null) {
			try {
				signatureTimeStamps = UnsignedAttributesHelper.getSignatureTimestamps(firstSignerInfo.getUnsignedAttributes());
			} catch (Exception e) {
				ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
			}
		}
		return signatureTimeStamps;
	}
                  
	public TimestampToken getContentTimestamp() {
		try {
			return SignedAttributesHelper.getContentTimestamp(firstSignerInfo.getSignedAttributes());
		} catch (Exception e) {
			ExceptionHandlerTyped.<SPISignatureException>handle(SPISignatureException.class, e);
		}
		return null;
	}
    		                    
	public byte[] getSignatureValue() {
		return firstSignerInfo.getSignature();
	}

	public Certificate getSignerCertificate() {
		try {
			Collection certificateCollection = cmsSignedData.getCertificates().getMatches(firstSignerInfo.getSID());
			Iterator iterator = certificateCollection.iterator();
			X509CertificateHolder certHolder = (X509CertificateHolder) iterator.next();
			return CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME).generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
		} catch (Exception e) {
			log.error(Channel.TECH, "Could not extract signer certificate from CMS signature : %1$s", e);
		}
		return null;
	}

	public Date getSigningTime() {
		return SignedAttributesHelper.getSigningTime(firstSignerInfo.getSignedAttributes());
	}

	public byte[] getDigestAttribute() {
		return SignedAttributesHelper.getDigestAttribute(firstSignerInfo.getSignedAttributes());
	}

	public ASN1ObjectIdentifier getContentTypeAttribute() {
		return SignedAttributesHelper.getContentTypeAttribute(firstSignerInfo.getSignedAttributes());
	}

	public ESSCertID getSigningCertificateAttribute() {
		return SignedAttributesHelper.getSigningCertificateAttribute(firstSignerInfo.getSignedAttributes());
	}

	public ESSCertIDv2 getSigningCertificateV2Attribute() {
		return SignedAttributesHelper.getSigningCertificateV2Attribute(firstSignerInfo.getSignedAttributes());
	}

	public SignaturePolicyIdentifier getSignaturePolicyIdentifierAttribute() {
		return SignedAttributesHelper.getSignaturePolicyIdentifierAttribute(firstSignerInfo.getSignedAttributes());
	}

	public DEREncodable getContentReferenceAttribute() {
		return SignedAttributesHelper.getContentReferenceAttribute(firstSignerInfo.getSignedAttributes());
	}

	public ContentIdentifier getContentIdentifierAttribute() {
		return SignedAttributesHelper.getContentIdentifierAttribute(firstSignerInfo.getSignedAttributes());
	}

	public ContentHints getContentHintsAttribute() {
		return SignedAttributesHelper.getContentHintsAttribute(firstSignerInfo.getSignedAttributes());
	}

	public CommitmentTypeIndication getCommitmentTypeIndicationAttribute() {
		return SignedAttributesHelper.getCommitmentTypeIndicationAttribute(firstSignerInfo.getSignedAttributes());
	}

	public SignerLocation getSignerLocationAttribute() {
		return SignedAttributesHelper.getSignerLocationAttribute(firstSignerInfo.getSignedAttributes());
	}

	public SignerAttribute getSignerAttributesAttribute() {
		return SignedAttributesHelper.getSignerAttributesAttribute(firstSignerInfo.getSignedAttributes());
	}

	public SignerInformationStore getCounterSignatures() {
		return firstSignerInfo.getCounterSignatures();
	}

	// For external signatures, inputStream parameter is the data being signed (external eContent)
	public boolean verifyExternalWithContent(InputStream inputStream)
			throws CMSException, IOException,
			NoSuchAlgorithmException, NoSuchProviderException,
			CertStoreException, OperatorCreationException, CertificateException {
		CMSSignedDataParser sp = new CMSSignedDataParser(new CMSTypedStream(inputStream), cmsSignedData.getEncoded());
		sp.getSignedContent().drain(); //here digests are computed and passed to newly created SignerInformation objects
		
		Collection signers = sp.getSignerInfos().getSigners();
		if(signers.size()!=1) hasMultipleSignerInfos = true;
		Iterator iterator = signers.iterator();
		firstSignerInfo = (SignerInformation) iterator.next();

		return CMSVerifier.verify(firstSignerInfo, cmsSignedData.getCertificates());
	}

	// For encapsulated signatures, data being signed is inside the CMS structure, under the EncapsulatedContentInfo field
	public boolean verifyEncapsulated() throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, CertStoreException, OperatorCreationException, CMSException {
		return CMSVerifier.verify(firstSignerInfo, cmsSignedData.getCertificates());
	}

	// For external signatures, digest parameter is the digest of the data being signed (external eContent pre-digested with digestAlgo specified in signerInfo)
	public boolean verifyExternalWithReference(byte[] digest) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException {
		return CMSVerifier.verifyReference(digest, firstSignerInfo, cmsSignedData.getCertificates());
	}
	
	public byte[] getEncodedSignedAttrs() throws IOException {
		return firstSignerInfo.getEncodedSignedAttributes();
	}
	
	public byte[] getEncodedEncapsulatedData() throws IOException {
		CMSProcessable content = cmsSignedData.getSignedContent();
		if(content==null) return null;
		return (byte[])content.getContent();
	}
}