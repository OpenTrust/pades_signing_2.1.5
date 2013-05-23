import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import com.keynectis.sequoia.ca.crypto.keyid.KeyIdFactory;
import com.keynectis.sequoia.ca.crypto.utils.PKCS12File;
import com.keynectis.sequoia.crypto.store.SoftRSAStoreSigner;
import com.keynectis.sequoia.security.clients.interfaces.IOCSPClient;
import com.keynectis.sequoia.security.clients.interfaces.ITspClient;
import com.keynectis.sequoia.security.ocsp.StandaloneOCSP;
import com.keynectis.sequoia.security.provider.impl.KSignature;
import com.keynectis.sequoia.security.provider.impl.KeynectisProvider;
import com.keynectis.sequoia.security.provider.impl.RSAHardKey;
import com.keynectis.sequoia.security.signeddocument.Document;
import com.keynectis.sequoia.security.tsp.StandaloneTSP;
import com.opentrust.pdfsign.PdfSigner;
import com.opentrust.spi.logger.PrintStreamLogger;
import com.opentrust.spi.logger.SPILogger;
import com.opentrust.spi.pdf.PDFEnvelopedSignature;
import com.opentrust.spi.pdf.PDFSign;
import com.opentrust.spi.pdf.PDFVerifSignature;
import com.opentrust.spi.pdf.PdfSignParameters;
import com.opentrust.spi.pdf.PDFSign.SignReturn;
import com.spilowagie.text.pdf.PdfReader;


public class SignerTest {
	private static File tmpFolder = new File("target/tmp");

	static PKCS12File defaultSigner;
	static PKCS12File tspSigner;
	static ITspClient defaultTspClient;
	static IOCSPClient defaultOcspClient;
	
	static KeynectisProvider ksProvider;
	static SoftRSAStoreSigner rsaSigner;
	static RSAHardKey remoteKey;
	static {
		try {
			Security.addProvider(new BouncyCastleProvider());
			// CryptoManager.setPreferredProvider(new BouncyCastleProvider());
			// deprecated due to JVM bug: #3294108
			
			tmpFolder.mkdirs();
			defaultSigner = new PKCS12File("src/test/resources/charles-queremma.p12", "password");
			
			tspSigner = new PKCS12File("src/test/resources/tsp3.p12", "keynectis");
			StandaloneTSP standaloneTSP = new StandaloneTSP(tspSigner.mCertificate, tspSigner.mPrivateKey, "1.2.3.4");
			ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
			certList.add(tspSigner.mCertificate);
			standaloneTSP.setCertificateChain(certList);
			defaultTspClient = standaloneTSP;
			defaultOcspClient = new StandaloneOCSP(defaultSigner.mCertificate, defaultSigner.mPrivateKey);

			rsaSigner = new SoftRSAStoreSigner();
			String keyId = KeyIdFactory.GetKeyId(defaultSigner.mCertificate);
			rsaSigner.importClearKey(keyId, defaultSigner.mPrivateKey.getEncoded());
			remoteKey = new RSAHardKey(keyId);

			KSignature.setDefaultRsaSigner(rsaSigner);
			ksProvider = new KeynectisProvider();
			ksProvider.addSignatureAlgorithm();
			
			Security.insertProviderAt(ksProvider, 1);
			
			SPILogger.setDefaultLogger(new PrintStreamLogger(System.out));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testSign() {
		try {

			PdfSignParameters parameters = PdfSignParameters.getParametersForSign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "CERTIFIED_NO_CHANGES_ALLOWED" // certifLevel
					, false // signatureAlreadyExists
					, "mysig nat&é'(-è_çà" // signatureName
					, true // createNewRevision
					, false // keepPDFACompliance
					, false // allocateTSContainer
					, 0 // TSSize
					, 0 // SigSize
					, "SHA1" // dataHashAlgo
					, new GregorianCalendar());

			SignReturn newPDF = PDFSign.sign(null, new FileInputStream("src/test/resources/minipdf.pdf"),
					new FileOutputStream("target/testSign.pdf"), "src/test/resources/charles-queremma.p12", "password",
					null, null, parameters);
			assertNotNull(newPDF);


		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test 
	public void testSigner() throws Exception
	{
		PDFSign.setPRODUCED_BY("Pikachu PDF");
		
		PdfSigner signer = new PdfSigner();
		signer.setSigningCertificate(defaultSigner.mCertificate, remoteKey);
		signer.setHashAlgorithm("Sha-256");
		
		/*
		signer.setSigningCertificateTrustChain(defaultSigner.getChain());
		signer.setLocation("Paris");
		signer.setReason("Pikachu reason");
		signer.setContact("118.218");
		
		*/
		signer.setTspClient(defaultTspClient);
		signer.setOcspClient(defaultOcspClient);
		
		FileInputStream fis = new FileInputStream("src/test/resources/test_signStream.pdf");
		Document doc = signer.parseDocument(fis);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		signer.sign(doc, baos);
		
		PdfReader reader = new PdfReader(baos.toByteArray());
		List<PDFEnvelopedSignature> verify = PDFVerifSignature.verify(reader, false);
		
		assert (verify.size() == 1);

		PDFSignTest.verif(verify, true);
		System.out.println("Fini");
	}
	
	
}
