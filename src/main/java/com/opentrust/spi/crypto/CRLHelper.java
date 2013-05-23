/*
 * Created on 26 juin 2005
 */
package com.opentrust.spi.crypto;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

import sun.misc.BASE64Decoder;

/**
 * @author mehdi.bouallagui
 */
public class CRLHelper {
	
	/**
	 * @param x509crl
	 * @param x509certificate
	 * @param date
	 * @return
	 */
	public static boolean isRevoked(X509CRL x509crl,
			X509Certificate x509certificate, Date date) {
		if (getRevocationDate(x509crl, x509certificate, date) != null) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * get a certificate revocation date  
	 * @param x509crl
	 * @param x509certificate
	 * @param date
	 * @return the rec
	 */
	public static Date getRevocationDate(X509CRL x509crl,
			X509Certificate x509certificate, Date date) {

		BigInteger iSerialNumber = x509certificate.getSerialNumber();
		X509CRLEntry xEntry = x509crl.getRevokedCertificate(iSerialNumber);

		// Le certificat n'appartient pas à la liste de révocation
		if (xEntry == null)
			return null;

		// Le certificat appartient à la CRL. On va vérifier si le
		// certificat
		// a été révoqué avant ou après la date donnée en paramètre.
		Date revocationDate = xEntry.getRevocationDate();

		if (revocationDate.before(date)) {
			return revocationDate;
		} else {
			return null;
		}
	}

	public static CRL getCRL(String b64String) throws IOException,
			CRLException, CertificateException {
		byte[] a = new BASE64Decoder().decodeBuffer(b64String);
		ByteArrayInputStream bis = new ByteArrayInputStream(a);
		CRL crl = null;
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		while (bis.available() > 0)
			crl = cf.generateCRL(bis);
		return crl;
	}

	public static CRL getCRL(byte[] bytes) throws IOException, CRLException,
			CertificateException {
		ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
		return getCRL(bis);
	}

	public static CRL getCRL(File file) throws IOException,
			CertificateException, CRLException {
		InputStream fileInputStream = new FileInputStream(file);
		CRL crl = getCRL(fileInputStream);
		fileInputStream.close();
		return crl;
	}

	private static CRL getCRL(InputStream inputStream) throws CRLException,
			IOException, CertificateException {
		CRL crl = null;
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		while (inputStream.available() > 0)
			crl = cf.generateCRL(inputStream);
		if (crl == null) {
			throw new CRLException("Could not parse crl");
		}
		return crl;
	}
	
	public static byte[] getFingerPrint(CRL crl,
			String algorithm) throws CRLException,
			NoSuchAlgorithmException {
		return DigestHelper.getDigest(((X509CRL)crl).getEncoded(), algorithm);
	}
	
	private static DERObject getExtensionValue(X509CRL crl, String oid) throws IOException {
		if (crl == null) {
			return null;
		}
		byte[] bytes = crl.getExtensionValue(oid);
		if (bytes == null) {
			return null;
		}
		ASN1InputStream extValIs = new ASN1InputStream(new ByteArrayInputStream(bytes));
		ASN1OctetString octetStr = (ASN1OctetString) extValIs.readObject();
		extValIs = new ASN1InputStream(new ByteArrayInputStream(octetStr.getOctets()));
		return extValIs.readObject();
	}

	public static BigInteger getCRLNumber(X509CRL crl) throws CRLException {
	BigInteger number = BigInteger.valueOf(0);
	try {
		DERObject obj = getExtensionValue(crl, X509Extension.cRLNumber.getId());
		DERInteger crlnum = CRLNumber.getInstance(obj);
		number = crlnum.getPositiveValue();
	} catch (IOException e) {
		throw new CRLException("Error retrieving CRL number", e);
	}
	return number;
	}
	
	public static byte[] getAuthorityKeyIdentifier(X509CRL crl) throws CRLException {
		byte[] result = null;
		try {
			byte[] extvalue = crl.getExtensionValue(X509Extension.authorityKeyIdentifier.getId());
			if (extvalue != null) {
				AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifierStructure(extvalue);
				result = keyId.getKeyIdentifier();
			}
		} catch (IOException e) {
			throw new CRLException("Error retrieving CRL authority key identifier", e);
		}
		return result;
	}
	
	/**
	 * Returns true if given certificate is CRL issuer, aka the issuer name and authority key
	 * identifier match and certificate has CRL signature key usage.
	 * @param crl
	 * @param acCertificate
	 * @return
	 * @throws CRLException
	 * @throws CertificateException 
	 */
	public static boolean isCRLIssuer(X509CRL crl, X509Certificate acCertificate) throws CRLException, CertificateException {
		boolean result = false;
		
		if (!CertificateHelper.hasKeyUsage(acCertificate, CertificateHelper.KEY_USAGE_CRLSIGN_INDEX))
			return false;
		
		X500Principal issuerDN = crl.getIssuerX500Principal();
		if (acCertificate.getSubjectX500Principal().equals(issuerDN)) {
			byte[] issuerKeyIdASN1 = CRLHelper.getAuthorityKeyIdentifier(crl);
			byte[] subjKeyIdANS1 = CertificateHelper.getSubjectKeyIdentifier(acCertificate);
			if (subjKeyIdANS1 != null && Arrays.equals(issuerKeyIdASN1, subjKeyIdANS1)) {
				result = true;
			}
		}
		return result;
	}
}
