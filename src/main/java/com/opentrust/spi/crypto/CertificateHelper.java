package com.opentrust.spi.crypto;

import java.io.ByteArrayInputStream;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;

import javax.crypto.interfaces.DHPublicKey;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

/*
 * Created on 6 juin 2005
 */

/**
 * Classe utilitaire présentant des méthodes pour la gestion des certificats
 * 
 * @author mehdi.bouallagui
 */
public class CertificateHelper {

	public static final String RDN_CN_TYPE = "cn";

	public static final String CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----";

	public static final String CERTIFICATE_END = "-----END CERTIFICATE-----";

	public static final int KEY_USAGE_LEN = 9;

	public static final String[] KEY_USAGE = new String[] { "digitalSignature",
			"nonRepudiation", "keyEncipherment", "dataEncipherment",
			"keyAgreement", "keyCertSign", "cRLSign", "encipherOnly",
			"decipherOnly" };
	
	public static final int KEY_USAGE_DIGITALSIGNATURE_INDEX	= 0;
	public static final int KEY_USAGE_NONREPUDIATION_INDEX		= 1;
	public static final int KEY_USAGE_KEYENCIPHERMENT_INDEX		= 2;
	public static final int KEY_USAGE_DATAENCIPHERMENT_INDEX	= 3;
	public static final int KEY_USAGE_KEYAGREEMENT_INDEX		= 4;
	public static final int KEY_USAGE_KEYCERTSIGN_INDEX			= 5;
	public static final int KEY_USAGE_CRLSIGN_INDEX				= 6;
	public static final int KEY_USAGE_ENCIPHERONLY_INDEX		= 7;
	public static final int KEY_USAGE_DECIPHERONLY_INDEX		= 8;

	public final static Hashtable<String, String> EXTENDED_KEY_USAGE_TABLE = new Hashtable<String, String>();
	static {
		EXTENDED_KEY_USAGE_TABLE.put("anyExtendedKeyUsage", "2.5.29.37.0");
		EXTENDED_KEY_USAGE_TABLE.put("serverAuth", "1.3.6.1.5.5.7.3.1");
		EXTENDED_KEY_USAGE_TABLE.put("clientAuth", "1.3.6.1.5.5.7.3.2");
		EXTENDED_KEY_USAGE_TABLE.put("codeSigning", "1.3.6.1.5.5.7.3.3");
		EXTENDED_KEY_USAGE_TABLE.put("emailProtection", "1.3.6.1.5.5.7.3.4");
		EXTENDED_KEY_USAGE_TABLE.put("ipsecEndSystem", "1.3.6.1.5.5.7.3.5");
		EXTENDED_KEY_USAGE_TABLE.put("ipsecTunnel", "1.3.6.1.5.5.7.3.6");
		EXTENDED_KEY_USAGE_TABLE.put("ipsecUser", "1.3.6.1.5.5.7.3.7");
		EXTENDED_KEY_USAGE_TABLE.put("timeStamping", "1.3.6.1.5.5.7.3.8");
		EXTENDED_KEY_USAGE_TABLE.put("ocspSigning", "1.3.6.1.5.5.7.3.9");
		EXTENDED_KEY_USAGE_TABLE.put("iKEIntermediate", "1.3.6.1.5.5.8.2.2");
		EXTENDED_KEY_USAGE_TABLE.put("microsoftSGC", "1.3.6.1.4.1.311.10.3.3");
		EXTENDED_KEY_USAGE_TABLE.put("netscapeSGC", "2.16.840.1.113730.4.1");
	}
		
	/**
	 * construit un objet Certificate à partir d'une chaîne encodée en base 64.
	 * qui est une représentation PEM d'un certificat. Il peut contenir ou non les
	 * délimteur "-----BEGIN/END CERTIFICATE-----".
	 * 
	 * @param b64String
	 *            chaine en base 64 représentant un certificat (PEM ou DER)
	 * @return certificat
	 * @throws IOException
	 *             dans le cas d'un problème de décodage du base 64
	 * @throws CertificateException
	 *             dans le cas d'un problème de parsing du certificat
	 */
	public static Certificate getCertificate(String b64String)
			throws IOException, CertificateException {
		Certificate cert = null;
		if (!b64String.startsWith(CERTIFICATE_BEGIN)
				&& !b64String.endsWith(CERTIFICATE_END)) {
			byte[] certBytes = Base64.decode(b64String);
			if (certBytes == null || certBytes.length == 0) {
				throw new CertificateException("Decoded certificate is null or empty");
			}
			cert = getCertificate(certBytes);
		} else {
			InputStream is = new ByteArrayInputStream(
					b64String.getBytes());
			cert = getCertificate(is);
			is.close();
		}
		return cert;
	}

	/**
	 * construit un byte[] correspondant à un objet Certificate à partir d'une
	 * chaîne encodée en base 64. qui est une représentation PEM d'un
	 * certificat. Il peut contenir ou non les délimteur
	 * "-----BEGIN/END CERTIFICATE-----".
	 * 
	 * @param b64String
	 *            chaine en base 64 représentant un certificat (PEM ou DER)
	 * @return certificat
	 * @throws IOException
	 *             dans le cas d'un problème de décodage du base 64
	 * @throws CertificateException
	 *             dans le cas d'un problème de parsing du certificat
	 */
	public static byte[] getCertificateEncoded(String b64String)
			throws IOException, CertificateException {
		byte[] certBytes = null;
		if (!b64String.startsWith(CERTIFICATE_BEGIN)
				&& !b64String.endsWith(CERTIFICATE_END)) {
			certBytes = Base64.decode(b64String);
			if (certBytes == null || certBytes.length == 0)
				throw new CertificateException("Decoded certificate is null or empty");
		} else {
			InputStream is = new ByteArrayInputStream(
					b64String.getBytes());
			Certificate cert = getCertificate(is);
			is.close();
			certBytes = cert.getEncoded();
		}
		return certBytes;
	}

	/**
	 * construit un objet Certificate à partir de sa réprésentation en tableau
	 * d'octets
	 * 
	 * @param certificateBytes
	 *            tableau représentant le certificat
	 * @return certificat
	 * @throws IOException
	 *             dans le cas d'un problème de manipulation du contenu du
	 *             tableau
	 * @throws CertificateException
	 *             dans le cas d'un problème de parsing du certificat
	 */
	public static Certificate getCertificate(byte[] certificateBytes)
			throws IOException, CertificateException {
		InputStream byteArrayInputStream = new ByteArrayInputStream(
				certificateBytes);
		Certificate certificate = getCertificate(byteArrayInputStream);
		byteArrayInputStream.close();
		return certificate;
	}

	/**
	 * construit un object Certificate à partir d'un nom de fichier
	 * 
	 * @param fileName
	 *            chemin d'accès au fichier contenant le certificat
	 * @param informDER
	 *            true si le format d'entrée est DER, sinon false (PEM)
	 * @return certificat
	 * @throws IOException
	 * @throws CertificateException
	 */
	public static Certificate getCertificate(String fileName, boolean informDER)
			throws IOException, CertificateException {
		File cert = new File(fileName);
		if (informDER) {
			byte[] content = FileHelper.load(cert.getAbsolutePath());
			return CertificateHelper.getCertificate(content);
		} else {
			return CertificateHelper.getPEMCertificate(cert);
		}
	}

	/**
	 * construit un objet Certificate à partir d'un fichier. Le fichier contient
	 * une représentation PEM d'un certificat. Il peut contenir ou non les
	 * délimteur "-----BEGIN/END CERTIFICATE-----".
	 * 
	 * @param file
	 *            fichier contenant le certificat
	 * @return certificat
	 * @throws IOException
	 *             dans le cas de problème de lecture du fichier
	 * @throws CertificateException
	 *             dans le cas d'un problème de parsing du certificat
	 */
	public static Certificate getPEMCertificate(File file) throws IOException,
			CertificateException {
		byte[] fileBytes = FileHelper.load(file.getAbsolutePath());
		String fileString = new String(fileBytes);
		if (!fileString.startsWith(CERTIFICATE_BEGIN)
				&& !fileString.endsWith(CERTIFICATE_END)) {
			return getCertificate(fileString);
		}
		InputStream fileInputStream = new FileInputStream(file);
		Certificate certificate = getCertificate(fileInputStream);
		fileInputStream.close();
		return certificate;
	}

	/**
	 * construit un objet Certificate à partir d'un fichier. Le fichier contient
	 * une représentation de certificat DER, ou PEM avec les délimiteurs
	 * "-----BEGIN/END CERTIFICATE-----"
	 * 
	 * @param file
	 *            fichier contenant le certificat
	 * @return certificat
	 * @throws IOException
	 *             dans le cas de problème de lecture du fichier
	 * @throws CertificateException
	 *             dans le cas d'un problème de parsing du certificat
	 */
	public static Certificate getCertificate(File file) throws IOException, CertificateException {
		InputStream fileInputStream = new FileInputStream(file);
		Certificate certificate = getCertificate(fileInputStream);
		fileInputStream.close();
		return certificate;
	}

	/**
	 * construit un objet Certificate à partir d'un stream. Utile pour la
	 * génération des certificats 'on the fly'.
	 * 
	 * @param inputStream
	 *            stream permettant de lire un certificat
	 * @return certificat
	 * @throws CertificateException
	 *             dans le cas d'un problème de parsing du certificat
	 * @throws IOException
	 *             dans le cas d'un problème de lecture du certificat
	 */
	private static Certificate getCertificate(InputStream inputStream)
			throws CertificateException, IOException {
		Certificate certificate = null;
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		//TODO Why do we keep on reading the input stream after parsing a certificate ?
		while (inputStream.available() > 0) {
			Certificate cert = cf.generateCertificate(inputStream);
			if (cert != null) {
				certificate = cert;
			}
		}
		if (certificate == null) {
			throw new CertificateException("Could not parse certificate");
		}
		return certificate;
	}

	/**
	 * calcule l'empreinte numérique d'un certificat
	 * 
	 * @param certificate
	 *            certificat dont on veut calculer l'empreinte
	 * @param algorithm
	 *            algorithme de hachage utilisé pour calculer l'empreinte
	 * @return tableau d'octet représentant empreinte numérique du certificat
	 * @throws CertificateException
	 *             en cad de problème d'encodage du certificat
	 * @throws NoSuchAlgorithmException
	 *             dans le cas où aucun provider n'est enregistré pour gérer
	 *             l'algorithme en entrée
	 */
	public static byte[] getFingerPrint(Certificate certificate,
			String algorithm) throws CertificateException,
			NoSuchAlgorithmException {
		return DigestHelper.getDigest(certificate.getEncoded(), algorithm);
	}

	/**
	 * finds key usage string from a java key usage array representation
	 * 
	 * @param keyUsageIndex
	 *            key usage java index
	 * @return key usage string
	 */
	public static String getKeyUsage(int keyUsageIndex) {
		try {
			return KEY_USAGE[keyUsageIndex];
		} catch (Exception e) {
			throw new IllegalArgumentException(
					"Cannot find key usage string representation", e);
		}
	}
	
	/**
	 * 
	 * @param certificate
	 * @param keyUsageIndex
	 * @return Returns true if certificate has the key usage corresponding 
	 * to given key usage index, false otherwise.
	 */
	public static boolean hasKeyUsage(X509Certificate certificate, int keyUsageIndex) {
		if (certificate == null) {
			throw new IllegalArgumentException("Argument certificate is null");
		}
		if (keyUsageIndex < 0) {
			throw new IllegalArgumentException("Argument keyUsageIndex is negative");
		}
		boolean[] usages = certificate.getKeyUsage();
		if (usages != null && usages.length > keyUsageIndex
				&& usages[keyUsageIndex])
			return true;
		else
			return false;
	}

	public static String getExtendedKeyUsageOID(String keyUsage) {
		return (String) EXTENDED_KEY_USAGE_TABLE.get(keyUsage);
	}

	public static String getExtendedKeyUsageName(String oid) {
		Enumeration k = EXTENDED_KEY_USAGE_TABLE.keys();
		while (k.hasMoreElements()) {
			String key = (String) k.nextElement();
			if (key.equals(oid)) {
				return EXTENDED_KEY_USAGE_TABLE.get(key);
			}
		}
		return null;
	}

	/**
	 * finds key usage java structure index from key usage string
	 * 
	 * @param keyUsageString
	 *            key usage string
	 * @return key usage index
	 */
	public static int getKeyUsageIndex(String keyUsageString) {
		for (int i = 0; i < KEY_USAGE.length; i++) {
			if (keyUsageString.equalsIgnoreCase(KEY_USAGE[i]))
				return i;
		}
		throw new IllegalArgumentException(keyUsageString
				+ " does not represent a valid key usage");

	}
	
	/**
	 * gets certificate key length
	 * 
	 * @param certificate
	 *            certificate for which the key length must be returned
	 * @return certificate key length
	 * @throws KeyException
	 */
	public static int getKeyLength(Certificate certificate) throws KeyException {
		if (certificate == null) {
			throw new IllegalArgumentException("certificate cannot be null");
		}
		return getKeyLength(certificate.getPublicKey());
	}

	/**
	 * gets public key length
	 * 
	 * @param publicKey
	 *            key for which the key length must be returned
	 * @return public key length
	 * @throws KeyException
	 */
	public static int getKeyLength(PublicKey publicKey) throws KeyException {
		if (publicKey == null) {
			throw new IllegalArgumentException("key cannot be null");
		}
		int keyLength = -1;
		if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
			keyLength = ((RSAPublicKey) publicKey).getModulus().bitLength();
		}
		if (publicKey instanceof java.security.interfaces.DSAPublicKey) {
			keyLength = ((DSAPublicKey) publicKey).getParams().getP()
					.bitLength();
		}
		if (publicKey instanceof javax.crypto.interfaces.DHPublicKey) {
			keyLength = ((DHPublicKey) publicKey).getParams().getP()
					.bitLength();
		}
		if (keyLength != -1) {
			return keyLength;
		}
		throw new KeyException("Cannot get key length");
	}

	public static String getRdnValueFromDN(String dn, String rdnType) {
		String result = null;
		if (dn == null) {
			throw new IllegalArgumentException("DN cannot be null");
		}
		if (rdnType == null) {
			throw new IllegalArgumentException("RDN type cannot be null");
		}
		try {
			LdapName ldapdn = new LdapName(dn);
			for (Rdn rdn : ldapdn.getRdns()) {
				if (rdn.getType().equalsIgnoreCase(rdnType)) {
					result = (String) rdn.getValue();
					break;
				}
			}
		} catch (InvalidNameException e) {
			throw new IllegalArgumentException("Cannot parse DN value " + dn
					+ ", " + e.getMessage());
		}
		return result;
	}

	public static String getCNFromDN(String dn) {
		return getRdnValueFromDN(dn, RDN_CN_TYPE);
	}

	public static String getLabel(X509Certificate certificate) {
		if (certificate == null) {
			return null;
		}
		String dn = certificate.getSubjectDN().getName();
		String cn = CertificateHelper.getCNFromDN(dn);
		if (StringUtils.isNotBlank(cn)) {
			return cn;
		}
		return dn;
	}

	public static List<Certificate> getCertificateFullPath(
			Certificate certificate, List<Certificate> certificateList, Date referenceDate)
			{
		CertStore certStore = null;
		try {
			certStore = CertStore.getInstance("Collection",
					new CollectionCertStoreParameters(certificateList));
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}

		return getCertificateFullPath(certificate, certStore, referenceDate);

	}

	public static List<Certificate> getCertificateFullPath(
			Certificate targetCertificate, CertStore certStore, Date referenceDate)
			{
		Collection<? extends Certificate> certificates = null;
		try {
			certificates = certStore.getCertificates(null);
		} catch (CertStoreException e) {
			ExceptionHandler.handle(e);
		}
		if (certificates == null || certificates.isEmpty()) {
			ExceptionHandler.handle(new CertPathBuilderException(
					"no certificates found to build certificate chain"));
		}
		HashSet<TrustAnchor> rootCertificates = new HashSet<TrustAnchor>();
		for (Certificate certificate : certificates) {
			String issuerDN = ((X509Certificate) certificate).getIssuerDN()
					.getName();
			String subjectDN = ((X509Certificate) certificate).getSubjectDN()
					.getName();
			if (issuerDN.equals(subjectDN)) {
				rootCertificates.add(new TrustAnchor(
						(X509Certificate) certificate, null));
			}
		}

		X509CertSelector targetConstraints = new X509CertSelector();

		targetConstraints.setCertificate((X509Certificate) targetCertificate);

		PKIXBuilderParameters params = null;
		try {
			params = new PKIXBuilderParameters(rootCertificates,
					targetConstraints);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		params.setRevocationEnabled(false);

		params.addCertStore(certStore);
		
		params.setDate(referenceDate);
		
		
		CertPathBuilder builder = null;
		try {
			builder = CertPathBuilder.getInstance("PKIX");
		} catch (NoSuchAlgorithmException e) {
			ExceptionHandler.handle(e);
		} 
//		catch (NoSuchProviderException e) {
//			ExceptionHandler.handle(e);
//		} 
		PKIXCertPathBuilderResult certPathBuilderResult = null;
		try {
			certPathBuilderResult = (PKIXCertPathBuilderResult) builder
					.build(params);
		} catch (Exception e) {
			String msg = null; 
			if (e.getCause()!=null) {
				if (e.getCause() instanceof CertificateExpiredException) {
					msg = "Certification path could not be validated because certificate is expired ["+e.getCause().getMessage()+"]";
				} else if (e.getCause().getCause()!=null && e.getCause().getCause() instanceof CertificateExpiredException) {
					msg = "Certification path could not be validated because certificate is expired ["+e.getCause().getCause().getMessage()+"]";
				} else if (e.getCause() instanceof CertificateNotYetValidException) {
					msg = "Certification path could not be validated because certificate is not yet valid ["+e.getCause().getMessage()+"]";
				} else if (e.getCause().getCause()!=null && e.getCause().getCause() instanceof CertificateNotYetValidException) {
					msg = "Certification path could not be validated because certificate is not yet valid ["+e.getCause().getCause().getMessage()+"]";
				}
			}
			ExceptionHandler.handle(e,msg);
		}
		// TODO optimizations ?
		List<? extends Certificate> certFullPath = certPathBuilderResult
				.getCertPath().getCertificates();
		ArrayList<Certificate> certFullPathArrayList = new ArrayList<Certificate>(
				certFullPath.size() + 1);
		certFullPathArrayList.addAll(certFullPath);
		certFullPathArrayList.add(certPathBuilderResult.getTrustAnchor()
				.getTrustedCert());
		return certFullPathArrayList;
	}
	
	public static Certificate getIssuerCertificate(
			Certificate certificate,
			CertStore... certificatesStores) {
		String issuerDN = ((X509Certificate) certificate).getIssuerDN()
				.getName();
		String issuerCN=getCNFromDN(issuerDN);
		Collection<Certificate> certificates = new ArrayList<Certificate>();
		if (certificatesStores!=null) {
			for (CertStore certificatesStore : certificatesStores) {
				if (certificatesStore!=null) {
					try {
						Collection<? extends Certificate> certToAdd = certificatesStore.getCertificates(null);
						if (certToAdd!=null) {
							certificates.addAll(certificatesStore.getCertificates(null));
						}
					} catch (CertStoreException e) {
						ExceptionHandler.handle(e);
					}
				}
			}
		}
		
		if (certificates == null || certificates.isEmpty()) {
			ExceptionHandler
					.handle(new CertPathBuilderException(
							"cannot find issuer certificate from empty certificate store"));
		}

		for (Certificate issuercertificate : certificates) {
			String subjectDN = ((X509Certificate) issuercertificate).getSubjectDN()
					.getName();
			String subjectCN = getCNFromDN(subjectDN);
			if (issuerCN.equals(subjectCN)) {
				try {
					certificate.verify(issuercertificate.getPublicKey());
					return issuercertificate;
				} catch (Exception e) {
					// skip to the next candidate
				}
			}
		}
		ExceptionHandler.handle(new CertPathBuilderException(
				"cannot find issuer certificate of "
						+ ((X509Certificate) certificate).getSubjectDN()
								.getName()
						+ " issued by "
						+ ((X509Certificate) certificate).getIssuerDN()
								.getName()));
		return null;
	}
	/**
	 * This methode convert a X509 Distinguished Name String into a normalized
	 * form, as is to say, the resulting string :
	 * <ul>
	 * <li>have the RelativeDN elements in an ascendant order "emailaddress,
	 * sn, cn, ou, o, c", the input dn must contains at least two different RDN
	 * elements from this list of wellknown elements</li>
	 * <li>RDN separator is ", "</li>
	 * <li>case, quoted char and escape char in each RDN are preserved in the
	 * output string</li>
	 * <li>RDN value special characters are recognized ( escape character,
	 * etc.)</li>
	 * <li>Input DN must use "," as RDN separator (with or without space)</li>
	 * <li>the rdn name is converted to emailaddress</li>
	 * </ul>
	 * <p>
	 * Tested successfully with the following sample :
	 * <ul>
	 * <li>cn=\"Joë, Martîn\", ou=Sales, ou=Company\\, The, o=workl, c=fr</li>
	 * <li>c=fr,o=workl,ou=Company\\, The,ou=Sales\\0Dbo,cn=Joe Martin</li>
	 * <li>EMAILADDRESS=fdsfsd@fr.fr, CN=Joe marting, BL=CT, C=fr</li>
	 * <li>SN=toto,EMAILADDRESS=fdsfsd@fr.fr, CN=Joe marting,BL=CT, C=fr</li>
	 * <li>foofoo=fr,o=workl,ou=Company\\, The,ou=Sales,cn=Joe Martin</li>
	 * </ul>
	 */
	public static String normalizeDN(String dn) {
		// First, split the dn into RDN elements, the X509NameTokenizer
		// recognize escape character
		X509NameTokenizerKeepChar rdnToken = new X509NameTokenizerKeepChar(dn);

		// Now guess the RDN elements order (from root to leaf or the contrary)
		// The guessing method consists in looking for wellknown RDN keys
		// and compares their absolute position in the string to determine if
		// the order is ascendant (emailaddress, sn, cn, ou, o, c)
		// or descendant (c, o, ou, cn, sn, emailaddress)
		String[] rdnName = { "emailaddress=", "sn=", "cn=", "ou=", "o=", "c=" };
		int orderIsUndefined = -1;
		int orderIsUnknown = 0;
		int orderIsAscendant = 1;
		int orderIsDescendant = 2;
		int presumedOrder = orderIsUnknown;
		String elt;
		int prevPosition = -1;
		ArrayList rdnArrayList = new ArrayList();
		while (rdnToken.hasMoreTokens()) {
			elt = rdnToken.nextToken();
			if (elt.startsWith("e=")) {
				elt = elt.replaceFirst("e=", "emailaddress=");
			} else if (elt.startsWith("E=")) {
				elt = elt.replaceFirst("E=", "EMAILADDRESS=");
			}
			rdnArrayList.add(elt);
		}
		int i = 0;
		while (i < rdnName.length && presumedOrder != orderIsUndefined) {
			for (int j = 0; j < rdnArrayList.size(); ++j) {
				elt = (String) rdnArrayList.get(j);
				if (elt.toLowerCase().startsWith(rdnName[i])) {
					if (prevPosition == -1) {
						prevPosition = j;
					} else if (prevPosition <= j) {
						if (presumedOrder == orderIsUnknown) {
							presumedOrder = orderIsAscendant;
						} else if (presumedOrder == orderIsDescendant) {
							presumedOrder = orderIsUndefined;
						}
					} else {
						if (presumedOrder == orderIsUnknown) {
							presumedOrder = orderIsDescendant;
						} else if (presumedOrder == orderIsAscendant) {
							presumedOrder = orderIsUndefined;
						}
					}
				}
			}
			++i;
		}
		StringBuffer outputDN = new StringBuffer(dn.length());
		if (presumedOrder != orderIsDescendant) {
			boolean isFirst = true;
			for (int k = 0; k < rdnArrayList.size(); ++k) {
				if (isFirst) {
					isFirst = false;
				} else {
					outputDN.append(", ");
				}
				outputDN.append((String) rdnArrayList.get(k));
			}
		} else {
			boolean isFirst = true;
			for (int k = rdnArrayList.size() - 1; k >= 0; --k) {
				if (isFirst) {
					isFirst = false;
				} else {
					outputDN.append(", ");
				}
				outputDN.append((String) rdnArrayList.get(k));
			}
		}
		return outputDN.toString();
	}
	/**
	 * class for breaking up an X500 Name into it's component tokens, ala
	 * java.util.StringTokenizer. We need this class as some of the lightweight
	 * Java environment don't support classes like StringTokenizer.
	 * <p>
	 * This modified version keeps escape and quote chars in output and suppress
	 * white space between rdn name and "="
	 */
	public static class X509NameTokenizerKeepChar {
		private String value;
		private int index;
		private char seperator;
		private StringBuffer buf = new StringBuffer();

		public X509NameTokenizerKeepChar(String oid) {
			this(oid, ',');
		}

		public X509NameTokenizerKeepChar(String oid, char seperator) {
			this.value = oid;
			this.index = -1;
			this.seperator = seperator;
		}

		public boolean hasMoreTokens() {
			return (index != value.length());
		}

		public String nextToken() {
			if (index == value.length()) {
				return null;
			}

			int end = index + 1;
			boolean quoted = false;
			boolean escaped = false;
			boolean namepart = true;
			boolean valuepart = false;

			buf.setLength(0);

			while (end != value.length()) {
				char c = value.charAt(end);

				if (c == '"') {
					if (!escaped) {
						quoted = !quoted;
					}
					buf.append(c);
					escaped = false;
				} else {
					if (escaped || quoted) {
						buf.append(c);
						escaped = false;
					} else if (c == '\\') {
						buf.append(c);
						escaped = true;
					} else if (c == seperator) {
						break;
					} else if (c == '=' && namepart) {
						buf.append(c);
						namepart = false;
						valuepart = true;
						end++;
						continue;
					} else if (c == ' ' || c == '\t') {
						if (!namepart && !valuepart) {
							buf.append(c);
						}
						end++;
						continue;
					} else {
						buf.append(c);
					}
				}
				if (valuepart) {
					valuepart = false;
				}
				end++;
			}

			index = end;
			return buf.toString().trim();
		}
	}
	
	public static boolean isAuthorityCertificate(Certificate certificate) {		
		return (((X509Certificate) certificate).getBasicConstraints()!=-1);
	}
	
	public static byte[] getSubjectKeyIdentifier(X509Certificate certificate) throws CertificateException {
		byte[] result = null;
		try {
			byte[] extvalue = certificate.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId());
			if (extvalue != null) {
				SubjectKeyIdentifier keyId = new SubjectKeyIdentifierStructure(extvalue);
				result = keyId.getKeyIdentifier();
			}
		} catch (IOException e) {
			throw new CertificateException("Error retrieving certificate subject key identifier for subject "
					+certificate.getSubjectX500Principal().getName(), e);
		}
		return result;
	}
	
	public static byte[] getAuthorityKeyIdentifier(X509Certificate certificate) throws CertificateException {
		byte[] result = null;
		try {
			byte[] extvalue = certificate.getExtensionValue(X509Extensions.AuthorityKeyIdentifier.getId());
			if (extvalue != null) {
				AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifierStructure(extvalue);
				result = keyId.getKeyIdentifier();
			}
		} catch (IOException e) {
			throw new CertificateException("Error retrieving certificate authority key identifier for subject "
					+certificate.getSubjectX500Principal().getName(), e);
		}
		return result;
	}
}