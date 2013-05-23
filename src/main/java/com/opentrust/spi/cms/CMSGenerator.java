package com.opentrust.spi.cms;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Hashtable;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.io.Streams;

import com.keynectis.sequoia.ca.crypto.utils.OIDUtils;
import com.keynectis.sequoia.ca.crypto.utils.PKCS12File;
import com.opentrust.spi.cms.helpers.ContentSignerWithProvidedSignatureValue;
import com.opentrust.spi.cms.helpers.DefaultSignedAttributeTableGeneratorWithoutDefaultSigningTime;
import com.opentrust.spi.cms.helpers.SignatureHelper;
import com.opentrust.spi.cms.helpers.SignedAttributesHelper;


public class CMSGenerator {
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	// Performs CMS signing on provided content
	public static byte[] sign(String documentFileName, String keyStoreFileName,
			String password) throws IOException, CMSException, OperatorCreationException, URISyntaxException, GeneralSecurityException {
		/*
		KeyStore keyStore = KeyStoreHelper.load(keyStoreFileName, password);
		String alias = KeyStoreHelper.getDefaultAlias(keyStore);
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
		Certificate certificate = keyStore.getCertificate(alias);
		*/
		PKCS12File p12 = new PKCS12File(keyStoreFileName, password);
		

		byte[] signatureBytes = null;
		InputStream inputStream = new FileInputStream(documentFileName);
		try {
			signatureBytes = signContent(BouncyCastleProvider.PROVIDER_NAME, inputStream, p12.mCertificate, p12.mPrivateKey,
					null, null, OIDUtils.getOID("SHA-1").getId(), null, false);
		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException e) {
					// ignore it
				}
			}
		}
		return signatureBytes;
	}

	// Performs CMS signing on provided content
	// optionally, content can be encapsulated in CMS
	public static byte[] signContent(String provider, InputStream inputStream,
			Certificate certificate, PrivateKey privateKey,
			Collection<Certificate> certStore, Date signingTime,
			String digestAlgorithm, Collection<CRL> unsignedCrls,
			boolean encapsulate) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			CertStoreException, CMSException, IOException, CRLException, OperatorCreationException, CertificateEncodingException, URISyntaxException, SignatureException {

		CMSGenerator cmsGenerator = new CMSGenerator(provider, certificate, digestAlgorithm);
		cmsGenerator.privateKey = privateKey;
		cmsGenerator.certStore = certStore;
		cmsGenerator.signingTime = signingTime;
		cmsGenerator.unsignedCrls = unsignedCrls;
		
		return cmsGenerator.signContent(inputStream, encapsulate);
	}
	
	public byte[] signContent(InputStream inputStream,
			boolean encapsulate) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			CertStoreException, CMSException, IOException, CRLException, OperatorCreationException, CertificateEncodingException, URISyntaxException, SignatureException {

		CMSSignedDataStreamGenerator signGen = (CMSSignedDataStreamGenerator) buildCMSSignedGenerator(true); 
		
		byte[] signature = null;
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		OutputStream outputStream = null;
		try {
			outputStream = signGen.open(byteArrayOutputStream, encapsulate);
			Streams.pipeAll(inputStream, outputStream);
		} finally {// close the streams
			if (outputStream != null) {
				try {
					outputStream.close();
				} catch (IOException e) {
					// ignore it
				}
			}
		}

		if (byteArrayOutputStream != null) {
			signature = byteArrayOutputStream.toByteArray();
			try {
				byteArrayOutputStream.close();
			} catch (IOException e) {
				// ignore it
			}
		}
		return signature;
	}

	// Performs CMS signing on pre-digested content
	public static byte[] signReference(byte[] digest, String keyStoreFileName,
			String password) throws IOException, CMSException, OperatorCreationException, URISyntaxException, GeneralSecurityException {
		PKCS12File p12 = new PKCS12File(keyStoreFileName, password);
		/*
		KeyStore keyStore = KeyStoreHelper.load(keyStoreFileName, password);
		String alias = KeyStoreHelper.getDefaultAlias(keyStore);
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
		Certificate certificate = keyStore.getCertificate(alias);
		*/
		return signReference(BouncyCastleProvider.PROVIDER_NAME, digest, p12.mCertificate,
				p12.mPrivateKey, null, null, OIDUtils.getOID("SHA-1").getId(), null);
	}

	// Performs CMS signing on pre-digested content
	public static byte[] signReference(String provider, byte[] digest, Certificate certificate,
			PrivateKey privateKey, Collection<Certificate> certStore,
			Date signingTime, String digestAlgorithm, Collection<CRL> unsignedCrls)
			throws InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException,
			CertStoreException, CMSException, IOException,
			CRLException, OperatorCreationException, CertificateEncodingException, URISyntaxException, SignatureException {

		CMSGenerator cmsGenerator = new CMSGenerator(provider, certificate, digestAlgorithm);
		cmsGenerator.privateKey = privateKey;
		cmsGenerator.certStore = certStore;
		cmsGenerator.signingTime = signingTime;
		cmsGenerator.unsignedCrls = unsignedCrls;
		
		return cmsGenerator.signReference(digest);
	}
	
	public byte[] signReference(byte[] digest)
			throws InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException,
			CertStoreException, CMSException, IOException,
			CRLException, OperatorCreationException, CertificateEncodingException, URISyntaxException, SignatureException {
		
		SignedAttributesHelper.addMessageDigestAttribute(signedAttributesHashtable, digest);
		
		CMSSignedDataGenerator signGen = (CMSSignedDataGenerator) buildCMSSignedGenerator(false); 

		CMSSignedData signedData = signGen.generate(new CMSAbsentContent(), false);		
		return signedData.getEncoded();
	}
    
	protected String provider = BouncyCastleProvider.PROVIDER_NAME;
	protected Certificate certificate;
	protected Collection<Certificate> certStore;
	protected Hashtable<DERObjectIdentifier, Attribute> signedAttributesHashtable = new Hashtable<DERObjectIdentifier, Attribute>();
	protected Date signingTime;
	protected String digestAlg;
	protected Collection<CRL> unsignedCrls;
	protected PrivateKey privateKey;
	protected ContentSignerWithProvidedSignatureValue contentSigner;
	
	protected CMSGenerator(String provider, Certificate certificate, String digestAlgorithm) throws NoSuchAlgorithmException {
		if(provider!=null) this.provider = provider; // otherwise we keep default = BouncyCastle
		this.certificate = certificate;
		this.digestAlg = digestAlgorithm;
		if(digestAlg==null) throw new NoSuchAlgorithmException("Could not map " + digestAlgorithm + " to a known algorithm");
	}

	protected CMSSignedGenerator buildCMSSignedGenerator(boolean isStream) throws SignatureException,
			OperatorCreationException, CertificateEncodingException, CMSException, CRLException, IOException,
			NoSuchAlgorithmException, NoSuchProviderException {
		populateSignedAttributesHashtable();

		AttributeTable signedAttributesTable = new AttributeTable(signedAttributesHashtable);

		String signatureAlgorithm = null;
		if (privateKey != null)
			signatureAlgorithm = SignatureHelper.getSignatureAlgoFromDigestAndKeyAlgo(digestAlg,
					privateKey.getAlgorithm());
		else if (contentSigner != null)
			signatureAlgorithm = contentSigner.getAlgorithm();
		if (signatureAlgorithm == null)
			throw new SignatureException("Could not find/build signatureAlgorithm");

		ContentSigner usedContentSigner = contentSigner;
		if (usedContentSigner == null)
		{
			//usedContentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(provider).build(privateKey);
			usedContentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);
		}

		CMSSignedGenerator signGen = null;
		if (isStream)
			signGen = new CMSSignedDataStreamGenerator();
		else
			signGen = new CMSSignedDataGenerator();
		JcaSignerInfoGeneratorBuilder sigBuilder = new JcaSignerInfoGeneratorBuilder(
				new JcaDigestCalculatorProviderBuilder().setProvider(provider).build());
		sigBuilder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGeneratorWithoutDefaultSigningTime(
				signedAttributesTable));
		SignerInfoGenerator signerInfoGen = sigBuilder.build(usedContentSigner, (X509Certificate) certificate);
		signGen.addSignerInfoGenerator(signerInfoGen);

		if (certStore == null)
			certStore = new ArrayList<Certificate>();
		if (!certStore.contains(certificate))
			certStore.add(certificate);
		signGen.addCertificates(new JcaCertStore(certStore));
		if (unsignedCrls != null)
			signGen.addCRLs(new JcaCRLStore(unsignedCrls));
		return signGen;
	}

	protected void populateSignedAttributesHashtable() throws CRLException, IOException, CertificateEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
		if(signingTime==null) signingTime = new Date();
    	SignedAttributesHelper.addSigningTimeAttribute(signedAttributesHashtable, signingTime);
    }
}