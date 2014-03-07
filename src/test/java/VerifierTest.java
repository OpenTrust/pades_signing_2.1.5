import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.junit.Ignore;

import com.keynectis.sequoia.ca.crypto.truststore.Truststore;
import com.opentrust.pdfsign.PdfDocument;
import com.opentrust.pdfsign.PdfVerifier;
import com.opentrust.pdfsign.PdfVerifier.PdfValidationResult;

@Ignore("test fails because certificate does NOT contain a CRLDP")
public class VerifierTest {
	static
	{
		Security.addProvider(new BouncyCastleProvider());
	}
	@Test
	public void revokedWithOcsp() throws Exception
	{
		Truststore truststore = ACCertificates.getDefaultTrustore();
		
		PdfDocument doc = loadPdf("pdfWithTimestampGoodOCSPRevokedCertificate.pdf");
		PdfVerifier verifier = new PdfVerifier();
		verifier.setSigningCertTrustPointValidationParams(truststore);
		verifier.setAcceptedCACertificates(new X509Certificate[] {ACCertificates.fille11});
		
		List<PdfValidationResult> verifyAll = verifier.verify(doc);
		for (PdfValidationResult result : verifyAll)
		{
			Assert.assertTrue(result.isValid());
		}
		
		List<PdfValidationResult> oneverify = verifier.verify(doc, "Signature1");
		for (PdfValidationResult result : oneverify)
		{
			Assert.assertTrue(result.getSignatureName().equals("Signature1"));
			Assert.assertTrue(result.isValid());
		}
		List<PdfValidationResult> missingverify = verifier.verify(doc, "Signature1234");
		Assert.assertTrue(missingverify.size() == 0);

		
	}

	public static PdfDocument loadPdf(String fileName) throws IOException {
		InputStream is = VerifierTest.class.getResourceAsStream("/qualif/" + fileName);
		return new PdfDocument(is);
	}
}
