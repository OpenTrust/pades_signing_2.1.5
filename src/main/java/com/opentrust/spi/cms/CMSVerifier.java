package com.opentrust.spi.cms;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import com.opentrust.spi.cms.helpers.SignatureHelper;
import com.opentrust.spi.cms.helpers.SignedAttributesHelper;
import com.opentrust.spi.crypto.DigestHelper;
import com.opentrust.spi.logger.Channel;
import com.opentrust.spi.logger.SPILogger;



public class CMSVerifier {
	private static SPILogger log = SPILogger.getLogger("CMS");
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	public static boolean verify(String documentFileName, byte[] signatureBytes)
			throws CMSException, IOException, NoSuchAlgorithmException,
			NoSuchProviderException, CertStoreException,
			OperatorCreationException, CertificateException {

		CMSSignedDataParser sp = new CMSSignedDataParser(new CMSTypedStream(new FileInputStream(
				documentFileName)), signatureBytes);
		sp.getSignedContent().drain();

		Store certStore = sp.getCertificates();
		SignerInformationStore signers = sp.getSignerInfos();
		Collection c = signers.getSigners();
		Iterator it = c.iterator();
		while (it.hasNext()) {
			boolean verifResult = verify((SignerInformation) it.next(), certStore);
			if(!verifResult) return false;
		}
		return true;
	}

	public static boolean verify(byte[] contentBytes, byte[] signatureBytes)
			throws CMSException, IOException, NoSuchAlgorithmException,
			NoSuchProviderException, CertStoreException,
			OperatorCreationException, CertificateException {
	
		CMSSignedData sp = new CMSSignedData(new CMSProcessableByteArray(contentBytes), signatureBytes);
		
		Store certStore = sp.getCertificates();
		SignerInformationStore signers = sp.getSignerInfos();
		Collection c = signers.getSigners();
		Iterator it = c.iterator();
		while (it.hasNext()) {
			boolean verifResult = verify((SignerInformation) it.next(), certStore);
			if(!verifResult) return false;
		}
		return true;
	}

	public static boolean verify(CMSSignedDataWrapper signature)
			throws CMSException, IOException, NoSuchAlgorithmException,
			NoSuchProviderException, CertStoreException,
			OperatorCreationException, CertificateException {
		return verify(signature.firstSignerInfo, signature.cmsSignedData.getCertificates());
	}
	
	public static boolean verify(SignerInformation signer, Store certStore)
			throws CMSException, IOException, NoSuchAlgorithmException,
			NoSuchProviderException, CertStoreException,
			OperatorCreationException, CertificateException {
		Collection certCollection = certStore.getMatches(signer.getSID());
	
		Iterator certIt = certCollection.iterator();
		X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
		Certificate x509Cert = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
	
		JcaSimpleSignerInfoVerifierBuilder sigVerifBuilder = new JcaSimpleSignerInfoVerifierBuilder();
		SignerInformationVerifier signerInfoVerif = sigVerifBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(x509Cert.getPublicKey());
		//the digest verification is included // Verif on public key so that cert verifications are not performed (done in dssl layer)
		boolean rawVerif = signer.verify(signerInfoVerif);
		// If RFC 3852 non-conformity -> CMSException
		log.debug(Channel.TECH, "Raw signature verification results in '%1$s'", rawVerif);
		boolean signerCertRefVerif = signingCertificateAttributeVerif(signer, x509Cert); // TODO : also done in dssl layer. Should this verification be removed from here ?
		log.debug(Channel.TECH, "Signer-cert-ref verification results in '%1$s'", signerCertRefVerif);
		
		return rawVerif && signerCertRefVerif;
	}

	// Not covered by this function : caller should check that the algo he used for contentDigest is the same as the algo in the signatureBytes CMS
	public static boolean verifyReference(byte[] contentDigest,
			byte[] signatureBytes) throws CMSException, IOException,
			NoSuchAlgorithmException, NoSuchProviderException,
			CertStoreException, InvalidKeyException,
			SignatureException, OperatorCreationException, CertificateException {

		CMSSignedData signedData = new CMSSignedData(signatureBytes);

		Store certStore = signedData.getCertificates();
		SignerInformationStore signers = signedData.getSignerInfos();
		Collection c = signers.getSigners();
		Iterator it = c.iterator();
		while (it.hasNext()) {
			boolean verifResult = verifyReference(contentDigest, (SignerInformation) it.next(), certStore);
			if(!verifResult) return false;
		}
		return true;
	}
	
	// Not covered by this function : caller should check that the algo he used for contentDigest is the same as the algo in the SignerInformation object
	public static boolean verifyReference(byte[] contentDigest, SignerInformation signer, Store certStore) throws CertificateException, IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException{
		// verifying reference : only if message digest is there as a signed attribute
		AttributeTable table = signer.getSignedAttributes();
		if(table!=null) {
			Attribute hash = table.get(CMSAttributes.messageDigest);
			if(hash!=null) {
				// FIXME return more details
				if (!MessageDigest.isEqual(contentDigest, ((ASN1OctetString) hash.getAttrValues().getObjectAt(0)).getOctets()))
					throw new SignatureException("Digest mismatch.");
			}
		}

		// verifying signature
		Collection certCollection = certStore.getMatches(signer.getSID());

		Iterator certIt = certCollection.iterator();
		X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
		Certificate x509Cert = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(cert.getEncoded()));

		java.security.Signature signature = null;
		if (signer.getEncodedSignedAttributes() != null) {
			String signatureAlgorithm = getSignatureAlgorithm(signer);
			signature = java.security.Signature.getInstance(signatureAlgorithm,
					BouncyCastleProvider.PROVIDER_NAME);
			signature.initVerify(x509Cert.getPublicKey());
			signature.update(signer.getEncodedSignedAttributes());
		} else {
			// TODO: Support something else than RSA
			signature = java.security.Signature.getInstance("NONEwithRSA", BouncyCastleProvider.PROVIDER_NAME);
			signature.initVerify(x509Cert.getPublicKey());
			AlgorithmIdentifier digestAlgOID = signer.getDigestAlgorithmID();
			if (digestAlgOID.getParameters() == null)
				digestAlgOID = new AlgorithmIdentifier(digestAlgOID.getObjectId(), new DERNull());
			DigestInfo di = new DigestInfo(digestAlgOID, contentDigest);
			signature.update(di.getDEREncoded());
		}
		
		boolean rawVerif = signature.verify(signer.getSignature());
		// If RFC 3852 non-conformity -> CMSException
		log.debug(Channel.TECH, "Raw signature verification results in '%1$s'", rawVerif);
		boolean signerCertRefVerif = signingCertificateAttributeVerif(signer, x509Cert);  // TODO : also done in dssl layer. Should this verification be removed from here ?
		log.debug(Channel.TECH, "Signer-cert-ref verification results in '%1$s'", signerCertRefVerif);
		
		return rawVerif && signerCertRefVerif;
	}

	// Not covered by this function : caller should check that the algo he used for contentDigest is the same as the algo in the SignerInformation object
	public static boolean verifyReference(byte[] contentDigest, CMSSignedDataWrapper signature) 
			throws CertificateException, IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException
			{
		return verifyReference(contentDigest, signature.firstSignerInfo, signature.cmsSignedData.getCertificates());
	}

	private static String getSignatureAlgorithm(SignerInformation signer) {
		String encOid = signer.getEncryptionAlgOID();
		String digestOid = signer.getDigestAlgOID();
		return SignatureHelper.getSignatureAlgoFromDigestAndKeyAlgo(digestOid, encOid);
	}
	
	private static boolean signingCertificateAttributeVerif(SignerInformation signer, Certificate x509Cert) throws CertificateException, NoSuchAlgorithmException {
		boolean signerCertRefVerif = true;
		ESSCertID signingCertRef = SignedAttributesHelper.getSigningCertificateAttribute(signer.getSignedAttributes());
		if(signingCertRef!=null) {
			log.debug(Channel.TECH, "signer-cert-ref attribute found");
			byte[] certHash = DigestHelper.getDigest(x509Cert.getEncoded(), "SHA1");
			signerCertRefVerif = Arrays.equals(certHash, signingCertRef.getCertHash());
		} else {
			ESSCertIDv2 signingCertRefV2 = SignedAttributesHelper.getSigningCertificateV2Attribute(signer.getSignedAttributes());
			if(signingCertRefV2!=null) {
				log.debug(Channel.TECH, "signer-cert-ref-v2 attribute found");
				String hashAlgorithm = signingCertRefV2.getHashAlgorithm().getObjectId().getId();
				byte[] certHash = DigestHelper.getDigest(x509Cert.getEncoded(), hashAlgorithm);
				signerCertRefVerif = Arrays.equals(certHash, signingCertRefV2.getCertHash());
			}
		}
		return signerCertRefVerif;
	}
	
	
}