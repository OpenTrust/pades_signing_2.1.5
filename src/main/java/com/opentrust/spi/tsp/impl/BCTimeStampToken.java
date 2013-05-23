/*
 * Created on 19 janv. 2005
 *
 */
package com.opentrust.spi.tsp.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Vector;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.tsp.Accuracy;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;

import com.keynectis.sequoia.ca.crypto.utils.OIDUtils;
import com.opentrust.spi.tsp.TimestampToken;

/**
 * Implémentation d'un jeton d'hotodatage à base du provider Bouncy Castle
 * @author mehdi.bouallagui
 */
public class BCTimeStampToken implements TimestampToken {

	TimeStampToken timeStampToken;

	public BCTimeStampToken(byte [] b) throws CMSException, TSPException, IOException
	{
		CMSSignedData cms = new CMSSignedData(b);
		timeStampToken = new TimeStampToken(cms);
	}
	/**
	 * Constructeur prenant en paramêtre une instance concrete de jeton d'horodatage à base de BC
	 * @param timeStampToken
	 */
	public BCTimeStampToken(TimeStampToken timeStampToken) {
		if (timeStampToken == null) {
			throw new NullPointerException("timeStampToken argument is null");
		}
		this.timeStampToken = timeStampToken;
	}

	/**
	 * @see com.kotio.commons.tsa.TimestampToken#getDateTime()
	 */
	public Date getDateTime() throws NoSuchFieldException {
		try {			
			return timeStampToken.getTimeStampInfo().getGenTime();
		} catch (Exception e) {
			NoSuchFieldException ex = new NoSuchFieldException("Can extract generation time in timestamp info");
			ex.initCause(e);
			throw ex;
		}
	}

	/**
	 * @see com.kotio.commons.tsa.TimestampToken#getAccuracy()
	 */
	public String getAccuracy() throws NoSuchFieldException {
		try {
			Accuracy accuracy = timeStampToken.getTimeStampInfo().getAccuracy();
			DERInteger seconds = accuracy.getSeconds();
			DERInteger millis = accuracy.getMillis();
			DERInteger micros = accuracy.getMicros();
			StringBuffer accuracyStringBuffer = new StringBuffer();
			if (seconds != null) {
				accuracyStringBuffer.append(seconds.getValue());
				accuracyStringBuffer.append(" sec ");
			}
			if (millis != null) {
				accuracyStringBuffer.append(millis.getValue());
				accuracyStringBuffer.append(" millis ");
			}
			if (micros != null) {
				accuracyStringBuffer.append(micros.getValue());
				accuracyStringBuffer.append(" micors ");
			}
			if (accuracyStringBuffer.length() == 0)
				throw new NullPointerException();
			return accuracyStringBuffer.toString();

		} catch (Exception e) {
			NoSuchFieldException ex = new NoSuchFieldException("Can extract accuracy in timestamp info");
			ex.initCause(e);
			throw ex;
		}
	}

	/**
	 * @see com.kotio.commons.timestamp.opentsa.TimestampToken#getPolicy(java.lang.Object)
	 */
	public String getPolicy() {
		return timeStampToken.getTimeStampInfo().getPolicy();
	}

	/**
	 * @see com.kotio.commons.tsa.TimestampToken#getNonce()
	 */
	public BigInteger getNonce() throws NoSuchFieldException {
		try {
			return timeStampToken.getTimeStampInfo().getNonce();
		} catch (Exception e) {
			NoSuchFieldException ex = new NoSuchFieldException("Can extract Nonce in timestamp info");
			ex.initCause(e);
			throw ex;
		}
	}

	/**
	 * @see com.kotio.commons.tsa.TimestampToken#getSignerCertificate()
	 */
	public Certificate getSignerCertificate() throws NoSuchFieldException {
		try {
			// Force bouncy castle provider
			Collection collection = timeStampToken.getCertificatesAndCRLs(
					"Collection", BouncyCastleProvider.PROVIDER_NAME)
					.getCertificates(timeStampToken.getSID());
			if (collection != null && collection.size() != 0) {
				return (Certificate) (collection.toArray())[0];
			} else {
				throw new NoSuchFieldException("Signer certificate");
			}
		} catch (Exception e) {
			NoSuchFieldException ex = new NoSuchFieldException("Cannot extract signer certificate from timestamp info");
			ex.initCause(e);
			throw ex;
		}
	}

	public CertStore getCertificatesAndCRLs() throws NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchFieldException {
		try {
			// Force bouncy castle provider
			return timeStampToken.getCertificatesAndCRLs("Collection", BouncyCastleProvider.PROVIDER_NAME);
		} catch (CMSException e) {
			NoSuchFieldException ex = new NoSuchFieldException("Cannot extract CertificatesAndCRLs from timestamp info");
			ex.initCause(e);
			throw ex;
		}

	}

	/**
	 * @throws SignatureException 
	 * @see com.kotio.commons.tsa.TimestampToken#verifySignature()
	 */
	public boolean verifySignature() throws SignatureException {
		try {
			timeStampToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build((X509Certificate) getSignerCertificate()));
		} catch (Exception e) {
			throw new SignatureException(e);
		}
		return true;
	}

	/**
	 * @throws DigestException 
	 * @see com.kotio.commons.tsa.TimestampToken#verifyImprint(byte[])
	 */
	public boolean verifyImprint(byte[] dataImprint) throws DigestException {
		byte[] timestampImprint = null;
		try {
			timestampImprint=timeStampToken.getTimeStampInfo().getMessageImprintDigest();
			if (Arrays.equals(timestampImprint, dataImprint))
				return true;
		} catch (Exception e) {
			
			StringBuffer message = new StringBuffer(
					"Timestamp imprint mismatch: " + "Expecting "
							+ new String(Base64.encode(dataImprint)));
			
			if (timestampImprint != null) {
				message.append("; found "
						+ new String(Base64.encode(timestampImprint)));
			}
			
			throw new DigestException(message.toString(), e);
		}
		return false;
	}

	/**
	 * Cette implémentation ne retourne que les bytes correspondant au token.(pas ceux de response) 
	 * 
	 * @see com.kotio.commons.tsa.TimestampToken#getEncoded()
	 */
	public byte[] getEncoded() throws IOException {
		return timeStampToken.getEncoded();
	}

	/**
	 * Aucune vérification de la révocation n'est effectuée. L'implémentation se base sur 
	 * Java Certification Path API.
	 * @see com.kotio.commons.tsa.TimestampToken#verifyCertPath(java.security.cert.Certificate[])
	 */
	public boolean verifyCertPath(Certificate[] trustedCertificates) {
		Certificate targetCertificate;
		try {
			targetCertificate = getSignerCertificate();
		} catch (NoSuchFieldException e1) {
			return false;
		}

		Vector certificateCollection = new Vector();
		certificateCollection.add(targetCertificate);
		HashSet trustedAnchors = new HashSet();

		for (int i = 0; i < trustedCertificates.length; i++) {
			try {
				X509Certificate certificate = (X509Certificate) trustedCertificates[i];
				trustedAnchors.add(new TrustAnchor(certificate, null));
			} catch (Exception e) {
			}
		}

		X509CertSelector targetConstraints = new X509CertSelector();

		targetConstraints.setCertificate((X509Certificate) targetCertificate);

		CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(
				certificateCollection);
		CertStore store = null;
		try {
			store = CertStore.getInstance("Collection", ccsp);
		} catch (Exception e) {
			return false;
		}

		PKIXBuilderParameters params = null;
		try {
			params = new PKIXBuilderParameters(trustedAnchors,
					targetConstraints);
		} catch (Exception e) {
			return false;
		}

		params.setRevocationEnabled(false);

		params.addCertStore(store);

		try {
			params.setDate(getDateTime());
		} catch (NoSuchFieldException e1) {
			return false;
		}
		CertPathBuilder builder;
		try {
			builder = CertPathBuilder.getInstance("PKIX");
		} catch (NoSuchAlgorithmException e) {
			return false;
		}
		try {
			builder.build(params);
		} catch (Exception e) {
			return false;
		}
		return true;
	}
	
	public String getMessageImprintAlgName() {		
		return getTSPAlgorithmNameFromOID(timeStampToken.getTimeStampInfo().getMessageImprintAlgOID());
	}
	
	private String getTSPAlgorithmNameFromOID(String oid) {
		String algo = OIDUtils.getName(new DERObjectIdentifier(oid));
		if (algo == null)
			throw new IllegalArgumentException ("No TSP digest algorithm corresponds to OID:"+oid);
		return algo;
	}	
}