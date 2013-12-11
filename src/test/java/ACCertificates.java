import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.keynectis.sequoia.ca.crypto.truststore.CertificateEntry;
import com.keynectis.sequoia.ca.crypto.truststore.RevocationInformationSource;
import com.keynectis.sequoia.ca.crypto.truststore.Trust;
import com.keynectis.sequoia.ca.crypto.truststore.Truststore;
import com.keynectis.sequoia.ca.crypto.truststore.RevocationInformationSource.CertificateStatus;
import com.keynectis.sequoia.ca.crypto.truststore.RevocationInformationSource.Token;
import com.keynectis.sequoia.ca.crypto.truststore.Truststore.ValidationResult;


public class ACCertificates {
	static CertificateFactory certFactory;
	
	static X509Certificate racine;
	static X509Certificate fille1;
	static X509Certificate fille11;
	static
	{
		try {
			certFactory = CertificateFactory.getInstance("X.509", "BC");
			racine = loadCertificate("ACRTEST.cer");
			fille1 = loadCertificate("ACFTEST1.cer");
			fille11 = loadCertificate("ACFTEST11.cer");
			
		} catch (Exception e) {
			throw new ExceptionInInitializerError(e);
		}
	}
	
	public static Truststore getDefaultTrustore() throws Exception
	{
		Truststore truststore = new Truststore();
    	Token token = new Token();
    	token.status = CertificateStatus.good;
		RevocationInformationSource alwaysGoodSource = new RevocationInformationSource.None(token);
		
		addCertificate(truststore, racine, alwaysGoodSource);
		/*
		addCertificate(truststore, fille1, alwaysGoodSource);
		addCertificate(truststore, fille11, alwaysGoodSource);
		*/
		return truststore;
	}
	private static void addCertificate(Truststore truststore, X509Certificate cert, RevocationInformationSource alwaysGoodSource)
			throws CertificateEncodingException, NoSuchAlgorithmException {
		CertificateEntry entry = new CertificateEntry(cert);
		entry.setTrust(Trust.provided);
		entry.setIssuedCertificatesRevocationInformationSource(alwaysGoodSource);
		truststore.addTrustedEntry(entry);
	}
	
	private static X509Certificate loadCertificate(String fileName) throws CertificateException {
		InputStream is = ACCertificates.class.getResourceAsStream("/ac-test/" + fileName);
		X509Certificate cert = (X509Certificate) certFactory.generateCertificate(is);
		return cert;
	}
}
