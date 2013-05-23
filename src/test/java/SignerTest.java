import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import com.keynectis.sequoia.ca.crypto.utils.PKCS12File;
import com.keynectis.sequoia.security.clients.interfaces.IOCSPClient;
import com.keynectis.sequoia.security.clients.interfaces.ITspClient;
import com.keynectis.sequoia.security.ocsp.StandaloneOCSP;
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

			SPILogger.setDefaultLogger(new PrintStreamLogger(System.out));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	@Test 
	public void testSigner() throws Exception
	{
		PdfSigner signer = new PdfSigner();
		signer.setSigningCertificate(defaultSigner.mCertificate);
		signer.setSigningKey(defaultSigner.mPrivateKey);
		signer.setLocation("Paris");
		signer.setReason("Pikachu reason");
		signer.setContact("118.218");
		
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
