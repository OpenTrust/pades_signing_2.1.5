import java.io.IOException;
import java.io.InputStream;

import org.junit.Test;

import com.keynectis.sequoia.ca.crypto.truststore.Truststore;
import com.opentrust.pdfsign.PdfDocument;
import com.opentrust.pdfsign.PdfVerifier;


public class VerifierTest {
	@Test
	public void revokedWithOcsp() throws Exception
	{
		Truststore truststore = new Truststore();
		
		PdfDocument doc = loadPdf("pdfWithTimestampGoodOCSPRevokedCertificate.pdf");
		PdfVerifier verifier = new PdfVerifier();
		verifier.setSigningCertTrustPointValidationParams(truststore);
		
		verifier.verify(doc, "pikachu");
	}

	public static PdfDocument loadPdf(String fileName) throws IOException {
		InputStream is = VerifierTest.class.getResourceAsStream("/qualif/" + fileName);
		return new PdfDocument(is);
	}
}
