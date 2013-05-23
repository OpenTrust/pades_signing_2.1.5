package com.opentrust.spi.cms;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Collection;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.operator.OperatorCreationException;

import com.opentrust.spi.cms.helpers.ContentSignerWithProvidedSignatureValue;
import com.opentrust.spi.cms.helpers.OCSPResponse;
import com.opentrust.spi.cms.helpers.SignedAttributesHelper;


// Generates CMS signatures suitable for PAdES v2 (or CMS or Basic) compatibility
public class CMSForPAdESBasicGenerator extends CMSGenerator {
	protected CMSForPAdESBasicGenerator(String provider, Certificate certificate, String digestAlgorithm) throws NoSuchAlgorithmException {
		super(provider, certificate, digestAlgorithm);
	}
	
	public CMSForPAdESBasicGenerator(String provider,
			Certificate certificate, PrivateKey privateKey,
			Collection certStore, Date signingTime,
			String digestAlgorithm, Collection<CRL> signedCrls, Collection<OCSPResponse> signedOcspResponses) throws NoSuchAlgorithmException {
		this(provider, certificate, digestAlgorithm);
		this.privateKey = privateKey;
		this.certStore = certStore;
		this.signingTime = signingTime;
		this.signedCrls = signedCrls;
		this.signedOcspResponses = signedOcspResponses;
	}

	// Performs CMS signing on provided content
	// optionally, content can be encapsulated in CMS
	public static byte[] signContent(String provider, InputStream inputStream,
			Certificate certificate, PrivateKey privateKey,
			Collection certStore, Date signingTime,
			String digestAlgorithm, Collection<CRL> signedCrls, Collection<OCSPResponse> signedOcspResponses,
			boolean encapsulate) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			CertStoreException, CMSException, IOException, CRLException, OperatorCreationException, CertificateEncodingException, URISyntaxException, SignatureException {

		CMSForPAdESBasicGenerator cmsGenerator = new CMSForPAdESBasicGenerator(provider, certificate, privateKey, certStore, signingTime,
				digestAlgorithm, signedCrls, signedOcspResponses);
		
		return cmsGenerator.signContent(inputStream, encapsulate);
	}
	
	// Performs CMS signing on pre-digested content
	public static byte[] signReference(String provider, byte[] digest, Certificate certificate,
			PrivateKey privateKey, Collection<Certificate> certStore,
			Date signingTime, String digestAlgorithm, Collection<CRL> signedCrls, Collection<OCSPResponse> signedOcspResponses)
			throws InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException,
			CertStoreException, CMSException, IOException,
			CRLException, OperatorCreationException, CertificateEncodingException, URISyntaxException, SignatureException {
		
		CMSForPAdESBasicGenerator cmsGenerator = new CMSForPAdESBasicGenerator(provider, certificate, privateKey, certStore, signingTime,
				digestAlgorithm, signedCrls, signedOcspResponses);
		
		return cmsGenerator.signReference(digest);
	}

	protected Collection<CRL> signedCrls;
    protected Collection<OCSPResponse> signedOcspResponses;
 	
    @Override
 	protected void populateSignedAttributesHashtable() throws CRLException, IOException, CertificateEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
    	SignedAttributesHelper.addSigningTimeAttribute(signedAttributesHashtable, signingTime);
		SignedAttributesHelper.addRevocationValuesAttribute(signedAttributesHashtable, signedCrls, signedOcspResponses); 
   }

    // used from iText-OTPatch.PDFEnvelopedSignature
    public static CMSSignedGenerator buildCMSSignedGenerator(
			ContentSignerWithProvidedSignatureValue contentSigner,
			boolean isStream,
			String provider,
			Hashtable<DERObjectIdentifier, Attribute> signedAttributesHashtable,
			Certificate signCert, Collection<Certificate> certs, Date signingTime,
			String dataDigestAlgorithm, List<CRL> crls,
			List<OCSPResponse> ocspResponses) throws NoSuchAlgorithmException, CertificateEncodingException, SignatureException, OperatorCreationException, CRLException, NoSuchProviderException, CMSException, IOException {
		CMSForPAdESBasicGenerator cmsGenerator = new CMSForPAdESBasicGenerator(provider, signCert, dataDigestAlgorithm);
		cmsGenerator.contentSigner = contentSigner;
		cmsGenerator.certStore = certs;
		cmsGenerator.signingTime = signingTime;
		cmsGenerator.signedCrls = crls;
		cmsGenerator.signedOcspResponses = ocspResponses;
		cmsGenerator.signedAttributesHashtable = signedAttributesHashtable;
		
		return cmsGenerator.buildCMSSignedGenerator(isStream);
	}

 }
