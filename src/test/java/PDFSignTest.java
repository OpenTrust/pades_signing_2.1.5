
import java.awt.Color;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.CommitmentTypeIdentifier;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.x509.X509AttributeCertificate;
import org.bouncycastle.x509.X509StreamParser;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.*;

import com.keynectis.sequoia.ca.crypto.utils.PKCS12File;
import com.keynectis.sequoia.core.io.FileUtil;
import com.keynectis.sequoia.security.clients.interfaces.IOCSPClient;
import com.keynectis.sequoia.security.clients.interfaces.ITspClient;
import com.keynectis.sequoia.security.ocsp.StandaloneOCSP;
import com.keynectis.sequoia.security.tsp.StandaloneTSP;
import com.opentrust.spi.cms.CMSForPAdESBasicGenerator;
import com.opentrust.spi.cms.helpers.OCSPResponse;
import com.opentrust.spi.cms.helpers.SignatureHelper;
import com.opentrust.spi.crypto.CRLHelper;
import com.opentrust.spi.crypto.CertificateHelper;
import com.opentrust.spi.crypto.CryptoConstants.AlgorithmID;

import com.opentrust.spi.logger.PrintStreamLogger;
import com.opentrust.spi.logger.SPILogger;
import com.opentrust.spi.pdf.PAdESHelper;
import com.opentrust.spi.pdf.PDFEnvelopedSignature;
import com.opentrust.spi.pdf.PDFSign;
import com.opentrust.spi.pdf.PDFSign.PresignReturn;
import com.opentrust.spi.pdf.PDFSign.PresignReturnForRawSignature;
import com.opentrust.spi.pdf.PDFSign.SignResult;
import com.opentrust.spi.pdf.PDFSign.SignReturn;
import com.opentrust.spi.pdf.PDFSign.VRIData;
import com.opentrust.spi.pdf.PDFSign.ValidationData;
import com.opentrust.spi.pdf.PDFVerifSignature;
import com.opentrust.spi.pdf.PdfSignParameters;
import com.opentrust.spi.pdf.PdfSignParameters.OCSPParameters;
import com.opentrust.spi.pdf.PdfSignParameters.PAdESParameters;
import com.opentrust.spi.pdf.PdfSignParameters.SignatureLayoutParameters;
import com.opentrust.spi.pdf.PdfSignParameters.TimestampingParameters;
import com.opentrust.spi.tsp.TimestampToken;
import com.spilowagie.text.Chunk;
import com.spilowagie.text.Document;
import com.spilowagie.text.Font;
import com.spilowagie.text.PageSize;
import com.spilowagie.text.Paragraph;
import com.spilowagie.text.pdf.AcroFields;
import com.spilowagie.text.pdf.BaseFont;
import com.spilowagie.text.pdf.PdfContentByte;
import com.spilowagie.text.pdf.PdfCopyFields;
import com.spilowagie.text.pdf.PdfImportedPage;
import com.spilowagie.text.pdf.PdfPKCS7;
import com.spilowagie.text.pdf.PdfReader;
import com.spilowagie.text.pdf.PdfWriter;
import com.spilowagie.text.pdf.RandomAccessFileOrArray;
import com.spilowagie.text.pdf.codec.GifImage;

public class PDFSignTest {
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
			validateCertificate(tspSigner.mCertificate);
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
	public static void validateCertificate(X509Certificate paramX509Certificate)
		    throws TSPValidationException
		  {
		    if (paramX509Certificate.getVersion() != 3)
		      throw new IllegalArgumentException("Certificate must have an ExtendedKeyUsage extension.");
		    byte[] arrayOfByte = paramX509Certificate.getExtensionValue(X509Extensions.ExtendedKeyUsage.getId());
		    if (arrayOfByte == null)
		      throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension.");
		    if (!(paramX509Certificate.getCriticalExtensionOIDs().contains(X509Extensions.ExtendedKeyUsage.getId())))
		      throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension marked as critical.");
		    ASN1InputStream localASN1InputStream = new ASN1InputStream(new ByteArrayInputStream(arrayOfByte));
		    try
		    {
		      localASN1InputStream = new ASN1InputStream(new ByteArrayInputStream(((ASN1OctetString)localASN1InputStream.readObject()).getOctets()));
		      ExtendedKeyUsage localExtendedKeyUsage = ExtendedKeyUsage.getInstance(localASN1InputStream.readObject());
		      if ((!(localExtendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping))) || (localExtendedKeyUsage.size() != 1))
		        throw new TSPValidationException("ExtendedKeyUsage not solely time stamping.");
		    }
		    catch (IOException localIOException)
		    {
		      throw new TSPValidationException("cannot process ExtendedKeyUsage extension");
		    }
		  }

	// Create large document outside target directory so as to not delete it at
	// each build
	private static String largePDFName = "input/largePDF.pdf";

	protected void buildLargePDF() {
		try {
			new File("input").mkdirs();
			File largePDF = new File(largePDFName);
			if (largePDF.length() < 90000000) {
				System.out.println("Building large PDF. Can take a few minutes.");
				// Building large PDF if needed
				Document document = new Document(PageSize.A4, 50, 50, 50, 50);
				PdfWriter.getInstance(document, new FileOutputStream(largePDFName));
				document.open();
				Paragraph par = new Paragraph("Teeeeeeeeeeeeeeeeeeeeeeext");
				for (int i = 0; i < 10000000; i++) {
					document.add(par);
				}
				document.close();
			}
			System.out.println("File length is " + largePDF.length() + " bytes");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	protected void buildLargePDF2() {
		try {
			new File("input").mkdirs();
			File largePDF = new File(largePDFName);
			if (largePDF.length() < 90000000) {
				System.out.println("Building large PDF. Can take a few minutes.");
				// Building large PDF if needed
				Document document = new Document(PageSize.A4, 50, 50, 50, 50);
				PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(largePDFName));
				document.open();
				PdfContentByte cb = writer.getDirectContent();
				PdfReader pdfReader = new PdfReader("src/test/resources/movie.pdf");
				List<PdfImportedPage> pages = new ArrayList<PdfImportedPage>();
				for (int j = 1; j < 2; j++) {
					PdfImportedPage page = writer.getImportedPage(pdfReader, j);
					pages.add(page);
				}
				for (int i = 0; i < 400; i++) {
					for (PdfImportedPage page : pages) {
						document.newPage();
						document.add(new Paragraph("Teeeeeeeeeeeeeeeeeeeeeeext"));
						document.add(new GifImage("src/test/resources/300.gif").getImage(1));
						cb.addTemplate(page, 0, 0);
					}
				}
				document.close();
			}
			System.out.println("File length is " + largePDF.length() + " bytes");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testSignLargePDF() {
		try {
			buildLargePDF2();
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

			Date d = new Date();
			SignReturn newPDF = PDFSign.sign(null, largePDFName, new FileOutputStream("target/testSignLargePDF.pdf"),
					tmpFolder, "src/test/resources/charles-queremma.p12", "password", null, null, parameters);
			System.out.println("SignLargePDF in " + (new Date().getTime() - d.getTime()));
			assertNotNull(newPDF);

			d = new Date();
			verif("target/testSignLargePDF.pdf", true);
			System.out.println("VerifLargePDF in " + (new Date().getTime() - d.getTime()));

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSignLargePDFTimestamp() {
		try {
			buildLargePDF();
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
			parameters.setTimeStampParams(new TimestampingParameters("http://172.19.0.52:318/TSS/HttpTspServer", null,
					null, "SHA1", true, "1.3.6.1.4.1.601.10.3.1"));

			Date d = new Date();
			SignReturn newPDF = PDFSign.sign(null, largePDFName, new FileOutputStream("target/testSignLargePDFTS.pdf"),
					tmpFolder, "src/test/resources/charles-queremma.p12", "password", null, null, parameters);
			System.out.println("SignLargePDFTimestamp in " + (new Date().getTime() - d.getTime()));
			assertNotNull(newPDF);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSignStream() throws Exception {

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

			FileOutputStream out = new FileOutputStream("target/testSignStream.pdf");
			
			SignReturn newPDF = PDFSign.sign(null, "src/test/resources/test_signStream.pdf", out, 
					tmpFolder, "src/test/resources/charles-queremma.p12", "password",
					null, null, parameters);
			assertNotNull(newPDF);

			// Verifying that there is one signature to the document :
			List<PDFEnvelopedSignature> verifResults = PDFVerifSignature.verify("target/testSignStream.pdf");
			assert (verifResults.size() == 1);

			verif(verifResults, true);

	}

	@Test
	public void testSignStreamPAdESBES() throws Exception {
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
			parameters.setPadesParameters(PAdESParameters.getPAdESBESParameters());

			FileOutputStream out = new FileOutputStream("target/test_signStreamPAdESBES.pdf");
			SignReturn newPDF = PDFSign.sign(null, "src/test/resources/test_signStream.pdf", out, tmpFolder,
					"src/test/resources/charles-queremma.p12", "password", null, null, parameters);
			assertNotNull(newPDF);

			// Verifying that there is one signature to the document :
			List<PDFEnvelopedSignature> verifResults = PDFVerifSignature.verify("target/test_signStreamPAdESBES.pdf");
			assert (verifResults.size() == 1);

			verif(verifResults, true);
			testPAdESBES(verifResults);
	}

	@Test
	public void testSignStreamPAdESBESWithSignerAttribute1() throws Exception {

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
			List<String> claimedRoles = new ArrayList<String>();
			claimedRoles.add("toto");
			claimedRoles.add("titi");
			PAdESParameters padesParameters = PAdESParameters.getPAdESBESParameters();
			padesParameters.setClaimedAttributes("1.2.3.4.5", claimedRoles);
			parameters.setPadesParameters(padesParameters);

			SignReturn newPDF = PDFSign.sign(null, "src/test/resources/test_signStream.pdf", new FileOutputStream(
					"target/test_signStreamPAdESBESWithSignerAttribute1.pdf"), tmpFolder,
					"src/test/resources/charles-queremma.p12", "password", null, null, parameters);
			assertNotNull(newPDF);

			// Verifying that there is one signature to the document :
			List<PDFEnvelopedSignature> verifResults = PDFVerifSignature
					.verify("target/test_signStreamPAdESBESWithSignerAttribute1.pdf");
			assert (verifResults.size() == 1);

			verif(verifResults, true);
			testPAdESBES(verifResults);

			// Verifying that claimed roles have been added to the 1st (and
			// only) signature
			for (PDFEnvelopedSignature sigResult : verifResults) {
				ASN1Sequence claimedAttrs = sigResult.getSignerAttributesAttribute().getClaimedAttributes();
				Attribute attr = Attribute.getInstance(claimedAttrs.getObjectAt(0));
				assertEquals(2, attr.getAttrValues().size());
				assertEquals("1.2.3.4.5", attr.getAttrType().getId());
				System.out.println(attr.getAttrValues().toString());
				break;
			}

	}

	@Test
	public void testSignStreamPAdESBESWithSignerAttribute2() {
		try {
			// sample certificateattribute (found in BC tests)
			byte[] attrCert = Base64.decode("MIIHQDCCBqkCAQEwgZChgY2kgYowgYcxHDAaBgkqhkiG9w0BCQEWDW1sb3JjaEB2"
					+ "dC5lZHUxHjAcBgNVBAMTFU1hcmt1cyBMb3JjaCAobWxvcmNoKTEbMBkGA1UECxMS"
					+ "VmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAyMQswCQYDVQQKEwJ2"
					+ "dDELMAkGA1UEBhMCVVMwgYmkgYYwgYMxGzAZBgkqhkiG9w0BCQEWDHNzaGFoQHZ0"
					+ "LmVkdTEbMBkGA1UEAxMSU3VtaXQgU2hhaCAoc3NoYWgpMRswGQYDVQQLExJWaXJn"
					+ "aW5pYSBUZWNoIFVzZXIxEDAOBgNVBAsTB0NsYXNzIDExCzAJBgNVBAoTAnZ0MQsw"
					+ "CQYDVQQGEwJVUzANBgkqhkiG9w0BAQQFAAIBBTAiGA8yMDAzMDcxODE2MDgwMloY"
					+ "DzIwMDMwNzI1MTYwODAyWjCCBU0wggVJBgorBgEEAbRoCAEBMYIFORaCBTU8UnVs"
					+ "ZSBSdWxlSWQ9IkZpbGUtUHJpdmlsZWdlLVJ1bGUiIEVmZmVjdD0iUGVybWl0Ij4K"
					+ "IDxUYXJnZXQ+CiAgPFN1YmplY3RzPgogICA8U3ViamVjdD4KICAgIDxTdWJqZWN0"
					+ "TWF0Y2ggTWF0Y2hJZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5j"
					+ "dGlvbjpzdHJpbmctZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlw"
					+ "ZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjc3RyaW5nIj4KICAg"
					+ "ICAgIENOPU1hcmt1cyBMb3JjaDwvQXR0cmlidXRlVmFsdWU+CiAgICAgPFN1Ympl"
					+ "Y3RBdHRyaWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFt"
					+ "ZXM6dGM6eGFjbWw6MS4wOnN1YmplY3Q6c3ViamVjdC1pZCIgRGF0YVR5cGU9Imh0"
					+ "dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hI3N0cmluZyIgLz4gCiAgICA8"
					+ "L1N1YmplY3RNYXRjaD4KICAgPC9TdWJqZWN0PgogIDwvU3ViamVjdHM+CiAgPFJl"
					+ "c291cmNlcz4KICAgPFJlc291cmNlPgogICAgPFJlc291cmNlTWF0Y2ggTWF0Y2hJ"
					+ "ZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5jdGlvbjpzdHJpbmct"
					+ "ZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlwZT0iaHR0cDovL3d3"
					+ "dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIj4KICAgICAgaHR0cDovL3p1"
					+ "bmkuY3MudnQuZWR1PC9BdHRyaWJ1dGVWYWx1ZT4KICAgICA8UmVzb3VyY2VBdHRy"
					+ "aWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6"
					+ "eGFjbWw6MS4wOnJlc291cmNlOnJlc291cmNlLWlkIiBEYXRhVHlwZT0iaHR0cDov"
					+ "L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIiAvPiAKICAgIDwvUmVz"
					+ "b3VyY2VNYXRjaD4KICAgPC9SZXNvdXJjZT4KICA8L1Jlc291cmNlcz4KICA8QWN0"
					+ "aW9ucz4KICAgPEFjdGlvbj4KICAgIDxBY3Rpb25NYXRjaCBNYXRjaElkPSJ1cm46"
					+ "b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmZ1bmN0aW9uOnN0cmluZy1lcXVhbCI+"
					+ "CiAgICAgPEF0dHJpYnV0ZVZhbHVlIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9y"
					+ "Zy8yMDAxL1hNTFNjaGVtYSNzdHJpbmciPgpEZWxlZ2F0ZSBBY2Nlc3MgICAgIDwv"
					+ "QXR0cmlidXRlVmFsdWU+CgkgIDxBY3Rpb25BdHRyaWJ1dGVEZXNpZ25hdG9yIEF0"
					+ "dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmFjdGlvbjph"
					+ "Y3Rpb24taWQiIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj"
					+ "aGVtYSNzdHJpbmciIC8+IAogICAgPC9BY3Rpb25NYXRjaD4KICAgPC9BY3Rpb24+"
					+ "CiAgPC9BY3Rpb25zPgogPC9UYXJnZXQ+CjwvUnVsZT4KMA0GCSqGSIb3DQEBBAUA"
					+ "A4GBAGiJSM48XsY90HlYxGmGVSmNR6ZW2As+bot3KAfiCIkUIOAqhcphBS23egTr"
					+ "6asYwy151HshbPNYz+Cgeqs45KkVzh7bL/0e1r8sDVIaaGIkjHK3CqBABnfSayr3"
					+ "Rd1yBoDdEv8Qb+3eEPH6ab9021AsLEnJ6LWTmybbOpMNZ3tv");

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

			X509StreamParser parser = X509StreamParser.getInstance("AttributeCertificate", "BC");
			parser.init(attrCert);
			X509AttributeCertificate certifiedAttribute = (X509AttributeCertificate) parser.read();
			PAdESParameters padesParameters = PAdESParameters.getPAdESBESParameters();
			padesParameters.setCertifiedAttribute(certifiedAttribute);
			parameters.setPadesParameters(padesParameters);

			SignReturn newPDF = PDFSign.sign(null, "src/test/resources/test_signStream.pdf", new FileOutputStream(
					"target/test_signStreamPAdESBESWithSignerAttribute2.pdf"), tmpFolder,
					"src/test/resources/charles-queremma.p12", "password", null, null, parameters);
			assertNotNull(newPDF);

			// Verifying that there is one signature to the document :
			List<PDFEnvelopedSignature> verifResults = PDFVerifSignature
					.verify("target/test_signStreamPAdESBESWithSignerAttribute2.pdf");
			assert (verifResults.size() == 1);

			verif(verifResults, true);
			testPAdESBES(verifResults);

			// Verifying that certificate attribute has been added to the 1st
			// (and only) signature
			for (PDFEnvelopedSignature sigResult : verifResults) {
				AttributeCertificate attrCertificate = sigResult.getSignerAttributesAttribute()
						.getCertifiedAttributes();
				assertNotNull(attrCertificate);
				System.out.println(attrCertificate.getSignatureAlgorithm().getAlgorithm());
				break;
			}

		} catch (Throwable e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSignStreamPAdESBESWithContentTimeStampAttribute() {
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
					, true // allocateTSContainer
					, 0 // TSSize
					, 0 // SigSize
					, "SHA1" // dataHashAlgo
					, new GregorianCalendar());
			PAdESParameters padesParameters = PAdESParameters.getPAdESBESParameters();
			padesParameters.setContentTimeStampParams(new TimestampingParameters(defaultTspClient, "SHA1"));
			parameters.setPadesParameters(padesParameters);

			SignReturn newPDF = PDFSign.sign(null, "src/test/resources/test_signStream.pdf", new FileOutputStream(
					"target/test_signStreamPAdESBEWithContentTimeStampAttribute.pdf"), tmpFolder,
					"src/test/resources/charles-queremma.p12", "password", null, null, parameters);
			assertNotNull(newPDF);

			// Verifying that there is one signature to the document :
			List<PDFEnvelopedSignature> verifResults = PDFVerifSignature
					.verify("target/test_signStreamPAdESBEWithContentTimeStampAttribute.pdf");

			assert (verifResults.size() == 1);

			verif(verifResults, true);
			testPAdESBES(verifResults);

			// Verifying that ContentTimeStamp has been added to the 1st (and
			// only) signature
			for (PDFEnvelopedSignature sigResult : verifResults) {
				TimestampToken tsp = sigResult.getContentTimestamp();
				assertNotNull(tsp);
				System.out.println(tsp.getDateTime());
				// Verifying that timestamp is valid
				assertEquals(true, tsp.verifySignature());
				assertEquals(true, tsp.verifyImprint(sigResult.getContentTimestampDigest()));
				break;
			}

		} catch (Throwable e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSignStreamPAdESEPES() {
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
			parameters.setPadesParameters(PAdESParameters.getPAdESEPESParameters("1.2.3.4", "titi".getBytes(),
					AlgorithmID.DIGEST_SHA1.getOID()));

			SignReturn newPDF = PDFSign.sign(null, "src/test/resources/test_signStream.pdf", new FileOutputStream(
					"target/test_signStreamPAdESEPES.pdf"), tmpFolder, "src/test/resources/charles-queremma.p12",
					"password", null, null, parameters);
			assertNotNull(newPDF);

			// Verifying that there is one signature to the document :
			List<PDFEnvelopedSignature> verifResults = PDFVerifSignature.verify("target/test_signStreamPAdESEPES.pdf");
			assert (verifResults.size() == 1);

			verif(verifResults, true);
			testPAdESEPES(verifResults);
		} catch (Throwable e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSignStreamPAdESEPESWithCommitmentType() {
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
			PAdESParameters pAdESParameters = PAdESParameters.getPAdESEPESParameters("1.2.3.4", "titi".getBytes(),
					AlgorithmID.DIGEST_SHA1.getOID());
			pAdESParameters.setCommitmentTypeId(CommitmentTypeIdentifier.proofOfApproval.getId());
			parameters.setPadesParameters(pAdESParameters);

			SignReturn newPDF = PDFSign.sign(null, "src/test/resources/test_signStream.pdf", new FileOutputStream(
					"target/test_signStreamPAdESEPESWithCommitmentType.pdf"), tmpFolder,
					"src/test/resources/charles-queremma.p12", "password", null, null, parameters);
			assertNotNull(newPDF);

			// Verifying that there is one signature to the document :
			List<PDFEnvelopedSignature> verifResults = PDFVerifSignature
					.verify("target/test_signStreamPAdESEPESWithCommitmentType.pdf");
			assert (verifResults.size() == 1);

			verif(verifResults, true);
			testPAdESEPES(verifResults);

			// Verifying that CommitmentTypeIndication has been added to the 1st
			// (and only) signature
			for (PDFEnvelopedSignature sigResult : verifResults) {
				CommitmentTypeIndication cti = sigResult.getCommitmentTypeIndicationAttribute();
				assertNotNull(cti);
				break;
			}

		} catch (Throwable e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSignStreamVisible() throws Exception {
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

			byte[] bgImage = FileUtils.readFileToByteArray(new File("src/test/resources/bgimage.JPG"));
			byte[] signatureImage = FileUtils.readFileToByteArray(new File("src/test/resources/signature_grande.JPG"));
			SignatureLayoutParameters signatureLayoutParameters = SignatureLayoutParameters
					.getLayoutParametersForNewSign(10, 10, 100, 100, 1, null/* "cou\ncou" */, bgImage, -100, 3, 0,
							signatureImage, 0, 0, 0, null);
			parameters.setSignatureLayoutParameters(signatureLayoutParameters);

			SignReturn newPDF = PDFSign.sign(null, "src/test/resources/minipdf.pdf", new FileOutputStream(
					"target/testSignStreamVisible.pdf"), tmpFolder, "src/test/resources/charles-queremma.p12",
					"password", null, null, parameters);
			assertNotNull(newPDF);

			verif("target/testSignStreamVisible.pdf", true);

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

			verif("target/testSign.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testAddLTVTimestamp() {
		try {
			SignReturn newPDF = PDFSign.addLTVTimestamp(new FileInputStream("src/test/resources/minipdf.pdf"),
					new FileOutputStream("target/testAddLTVTimestamp.pdf"), new TimestampingParameters(defaultTspClient, "SHA1"));
			assertNotNull(newPDF);

			// Verif
			List<PDFEnvelopedSignature> verifResults = PDFVerifSignature.verify("target/testAddLTVTimestamp.pdf", true);
			verif(verifResults, true);
			boolean docTSfound = false;
			for (PDFEnvelopedSignature verifResult : verifResults) {
				TimestampToken tsToken = verifResult.getDocTimeStampValue();
				if (tsToken != null) {
					docTSfound = true;
					System.out.println(tsToken.getDateTime());
				}
			}
			assertEquals(true, docTSfound);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testAddLTVTimestampOnAlreadySigned() throws Exception{
			SignReturn newPDF = PDFSign.addLTVTimestamp(new FileInputStream(
					"src/test/resources/authorsigned_minipdf.pdf"), new FileOutputStream(
					"target/testAddLTVTimestampOnAlreadySigned.pdf"), new TimestampingParameters(defaultTspClient, "SHA1"));
			assertNotNull(newPDF);

			// Verif
			List<PDFEnvelopedSignature> verifResults = PDFVerifSignature.verify(
					"target/testAddLTVTimestampOnAlreadySigned.pdf", true);
			verif(verifResults, true);
			boolean docTSfound = false;
			for (PDFEnvelopedSignature verifResult : verifResults) {
				TimestampToken tsToken = verifResult.getDocTimeStampValue();
				if (tsToken != null) {
					docTSfound = true;
					System.out.println(tsToken.getDateTime());
				}
			}
			assertEquals(true, docTSfound);

	}

	@Test
	public void testAddLTVDSSOnAlreadySigned() {
		try {
			List<Certificate> certs = new ArrayList<Certificate>(1);
			certs.add(CertificateHelper.getCertificate(new File(
					"src/test/resources/OpenTrustSPICertificationAuthority1.cer")));
			List<CRL> crls = new ArrayList<CRL>(1);
			crls.add(CRLHelper.getCRL(new File("src/test/resources/OpenTrustSPICertificationAuthority30-11-2007.crl")));
			List<OCSPResponse> ocsps = null;
			PDFSign.addLTVDSS(new FileInputStream("src/test/resources/signed_beforeLTV.pdf"), new FileOutputStream(
					"target/testAddLTVDSSOnAlreadySigned.pdf"), certs, crls, ocsps);

			verif("target/testAddLTVDSSOnAlreadySigned.pdf", true);

			ValidationData validationData = PDFVerifSignature.verifyDSS("target/testAddLTVDSSOnAlreadySigned.pdf");
			assertEquals(1, validationData.getCertsList().size());
			assertEquals(1, validationData.getCrlsList().size());

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testAddLTVDSSWithVRIOnAlreadySigned() {
		try {
			List<Certificate> certs = new ArrayList<Certificate>(1);
			certs.add(CertificateHelper.getCertificate(new File(
					"src/test/resources/OpenTrustSPICertificationAuthority1.cer")));
			List<CRL> crls = new ArrayList<CRL>(1);
			crls.add(CRLHelper.getCRL(new File("src/test/resources/OpenTrustSPICertificationAuthority30-11-2007.crl")));
			List<OCSPResponse> ocsps = null;
			List<VRIData> vriDatas = new ArrayList<VRIData>();
			vriDatas.add(new VRIData("mysignat", certs, crls, ocsps));
			PDFSign.addLTVDSSWithVRI(new FileInputStream("src/test/resources/signed_beforeLTV.pdf"),
					new FileOutputStream("target/testAddLTVDSSWithVRIOnAlreadySigned.pdf"), null, null, null, vriDatas);

			ValidationData validationData = PDFVerifSignature
					.verifyDSS("target/testAddLTVDSSWithVRIOnAlreadySigned.pdf");

			// Verifying that there is one signature to the document :
			List<PDFEnvelopedSignature> verifResults = PDFVerifSignature
					.verify("target/testAddLTVDSSWithVRIOnAlreadySigned.pdf");
			verif(verifResults, true);

			// Verifying that claimed roles have been added to the 1st (and
			// only) signature
			for (PDFEnvelopedSignature sigResult : verifResults) {
				assertEquals(1, validationData.getVriData(sigResult).getCertsList().size());
				assertEquals(1, validationData.getVriData(sigResult).getCrlsList().size());
			}

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSignPAdESBES() {
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
			parameters.setPadesParameters(PAdESParameters.getPAdESBESParameters());

			SignReturn newPDF = PDFSign.sign(null, new FileInputStream("src/test/resources/minipdf.pdf"),
					new FileOutputStream("target/testSignPAdESBES.pdf"), "src/test/resources/charles-queremma.p12",
					"password", null, null, parameters);
			assertNotNull(newPDF);

			verif("target/testSignPAdESBES.pdf", true);

			testPAdESBES("target/testSignPAdESBES.pdf");

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testDoubleSignPAdESBES() {
		try {

			PdfSignParameters parameters = PdfSignParameters.getParametersForSign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, false // signatureAlreadyExists
					, null // signatureName
					, true // createNewRevision
					, false // keepPDFACompliance
					, false // allocateTSContainer
					, 0 // TSSize
					, 0 // SigSize
					, "SHA1" // dataHashAlgo
					, new GregorianCalendar());
			parameters.setPadesParameters(PAdESParameters.getPAdESBESParameters());

			SignReturn newPDF = PDFSign.sign(null, new FileInputStream("src/test/resources/minipdf.pdf"),
					new FileOutputStream("target/testDoubleSignPAdESBES0.pdf"),
					"src/test/resources/charles-queremma.p12", "password", null, null, parameters);
			assertNotNull(newPDF);

			newPDF = PDFSign.sign(null, new FileInputStream("target/testDoubleSignPAdESBES0.pdf"),
					new FileOutputStream("target/testDoubleSignPAdESBES.pdf"),
					"src/test/resources/charles-queremma.p12", "password", null, null, parameters);
			assertNotNull(newPDF);

			verif("target/testDoubleSignPAdESBES.pdf", true);

			testPAdESBES("target/testDoubleSignPAdESBES.pdf");
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSignSignPAdESBES() {
		try {

			PdfSignParameters parameters = PdfSignParameters.getParametersForSign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, false // signatureAlreadyExists
					, null // signatureName
					, true // createNewRevision
					, false // keepPDFACompliance
					, false // allocateTSContainer
					, 0 // TSSize
					, 0 // SigSize
					, "SHA1" // dataHashAlgo
					, new GregorianCalendar());

			SignReturn newPDF = PDFSign.sign(null, new FileInputStream("src/test/resources/minipdf.pdf"),
					new FileOutputStream("target/testSignSignPAdESBES0.pdf"),
					"src/test/resources/charles-queremma.p12", "password", null, null, parameters);
			assertNotNull(newPDF);

			parameters.setPadesParameters(PAdESParameters.getPAdESBESParameters());

			newPDF = PDFSign.sign(null, new FileInputStream("target/testSignSignPAdESBES0.pdf"), new FileOutputStream(
					"target/testSignSignPAdESBES.pdf"), "src/test/resources/charles-queremma.p12", "password", null,
					null, parameters);
			assertNotNull(newPDF);

			verif("target/testSignSignPAdESBES.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSign2() {
		try {

			PdfSignParameters parameters = PdfSignParameters.getParametersForSign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, false // signatureAlreadyExists
					, "premieresign" // signatureName
					, true // createNewRevision
					, false // keepPDFACompliance
					, true // allocateTSContainer
					, 0 // TSSize
					, 0 // SigSize
					, "SHA1" // dataHashAlgo
					, new GregorianCalendar());

			SignReturn newPDF = PDFSign.sign(null, new FileInputStream("src/test/resources/minipdf.pdf"),
					new FileOutputStream("target/testSign2.pdf"), "src/test/resources/charles-queremma.p12",
					"password", null, null, parameters);
			assertNotNull(newPDF);

			verif("target/testSign2.pdf", true);

			parameters = PdfSignParameters.getParametersForSign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, false // signatureAlreadyExists
					, null // signatureName
					, true // createNewRevision
					, false // keepPDFACompliance
					, true // allocateTSContainer
					, 0 // TSSize
					, 0 // SigSize
					, "SHA1" // dataHashAlgo
					, new GregorianCalendar());

			SignReturn newPDF2 = PDFSign.sign(null, new FileInputStream("target/testSign2.pdf"), new FileOutputStream(
					"target/testSignSign.pdf"), "src/test/resources/charles-queremma.p12", "password", null, null,
					parameters);
			assertNotNull(newPDF2);

			verif("target/testSignSign.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSignInvalidXMLMetadata() {
		// See #1017, signature of a pdf with corrupted XML metadata shoulf also
		// work despite error "Invalid byte 1 of 1-byte UTF-8 sequence" in XMl
		// parser logs
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

			SignReturn newPDF = PDFSign.sign(null, new FileInputStream("src/test/resources/corrupted_xmlmetadata.pdf"),
					new FileOutputStream("target/testSignCorruptedXmlMetadata.pdf"),
					"src/test/resources/charles-queremma.p12", "password", null, null, parameters);
			assertNotNull(newPDF);

			verif("target/testSignCorruptedXmlMetadata.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSignOcsp() {
		try {

			String ocspUrl = "http://spi-pki-4.dev.opentrust.com/ocsp";
			IOCSPClient ocspClient = defaultOcspClient;
			/*
			OCSPResponderConfig config = new OCSPResponderConfig("pki-interne", ocspUrl, null);
			config.setAcceptanceDelay(100000);
			config.setExpirationDelay(60 * 24 * 60);
			config.setIgnoreCheck(true);
			config.setProxy("proxy.int.opentrust.com", 3128);
			OCSPResponderManager.getInstance().addOCSPResponder(config);
			*/

			PdfSignParameters parameters = PdfSignParameters.getParametersForSign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "CERTIFIED_NO_CHANGES_ALLOWED" // certifLevel
					, false // signatureAlreadyExists
					, "mysig nat&é'(-è_çà" // signatureName
					, true // createNewRevision
					, false // keepPDFACompliance
					, true // allocateTSContainer
					, 0 // TSSize
					, 0 // SigSize
					, "SHA1" // dataHashAlgol
					, new GregorianCalendar());

			parameters.setTimeStampParams(new TimestampingParameters(defaultTspClient, "SHA1"));
			/*
			parameters.addOCSPParams(new OCSPParameters("pki-interne", CertificateHelper.getCertificate(new File(
					"src/test/resources/David_demo2.crt")), CertificateHelper.getCertificate(new File(
					"src/test/resources/issuerPKIDemo.cer"))));
			*/
			parameters.ocspClient = ocspClient;

			CRL[] crls = null;// new CRL[] {CRLHelper.getCRL(new
								// File("src/test/resources/OpenTrust_PKI_Demo_Root_CA.crl"))};

			SignReturn newPDF = PDFSign.sign(null, new FileInputStream("src/test/resources/minipdf.pdf"),
					new FileOutputStream("target/testSignOcsp.pdf"), "src/test/resources/david_demo2.p12", "opentrust",
					crls, null, parameters);
			assertNotNull(newPDF);

			verif("target/testSignOcsp.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSignPregeneratedOcsp() {
		try {
			System.out.println("Test sign PDF with pregenerated OCSP");

			String ocspUrl = "http://spi-pki-4.dev.opentrust.com/ocsp";
			IOCSPClient ocspClient = defaultOcspClient;

			X509Certificate certToVerify = (X509Certificate) CertificateHelper.getCertificate(new File(
					"src/test/resources/David_demo2.crt"));
			X509Certificate issuerCertificate = (X509Certificate) CertificateHelper.getCertificate(new File(
					"src/test/resources/issuerPKIDemo.cer"));
			/*
			OCSPParameters ocspParams = new OCSPParameters("pki-interne", certToVerify, issuerCertificate);

			OCSPResponderConfig config = new OCSPResponderConfig("pki-interne", ocspUrl, null);
			config.setAcceptanceDelay(100000);
			config.setExpirationDelay(60 * 24 * 60);
			config.setIgnoreCheck(true);
			config.setProxy("proxy.int.opentrust.com", 3128);
			OCSPResponderManager.getInstance().addOCSPResponder(config);


			OCSPResponderManager ocspResponderManager = OCSPResponderManager.getInstance();
			OCSPResponder Responder = ocspResponderManager.getOCSPResponder(ocspParams.getOcspResponderId());
			OCSPResponse responseFresh = Responder.getOCSPResponse(ocspParams.getTargetCertificate(),
					ocspParams.getIssuerCertificate());
			*/
			BasicOCSPResp status = ocspClient.getStatus(certToVerify, issuerCertificate);
			OCSPResponse freshResponse = new OCSPResponse(status);

			OCSPResponse[] ocsp = new OCSPResponse[] { freshResponse };
			assertNotNull(ocsp);

			PdfSignParameters parameters = PdfSignParameters.getParametersForSign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "CERTIFIED_NO_CHANGES_ALLOWED" // certifLevel
					, false // signatureAlreadyExists
					, "mysig nat&é'(-è_çà" // signatureName
					, true // createNewRevision
					, false // keepPDFACompliance
					, true // allocateTSContainer
					, 0 // TSSize
					, 0 // SigSize
					, "SHA1" // dataHashAlgo
					, new GregorianCalendar());

			CRL[] crls = null;// new CRL[] {CRLHelper.getCRL(new
								// File("src/test/resources/OpenTrust_PKI_Demo_Root_CA.crl"))};

			SignReturn newPDF = PDFSign.sign(null, new FileInputStream("src/test/resources/minipdf.pdf"),
					new FileOutputStream("target/testSignPregeneratedOcsp.pdf"), "src/test/resources/david_demo2.p12",
					"opentrust", crls, ocsp, parameters);
			assertNotNull(newPDF);

			verif("target/testSignPregeneratedOcsp.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSignExistingSignature() {
		try {

			PdfSignParameters parameters = PdfSignParameters.getParametersForSign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, true // signatureAlreadyExists
					// , "formulaire1[0].#subform[0].Signature1[0]"
					// //signatureName
					, "formulaire1[0].#subform[0].Footer[0].AuthorizedBy[0]" // signatureName
					, true // createNewRevision
					, false // keepPDFACompliance
					, false // allocateTSContainer
					, 0 // TSSize
					, 0 // SigSize
					, "SHA1" // dataHashAlgo
					, new GregorianCalendar());
			parameters.setSignatureLayoutParameters(SignatureLayoutParameters
					.getLayoutParametersForAlreadyExistingSign("c'est signé !", null, 0, 0, 0, null, -1, -1, -1,
							new Color(0)));

			SignReturn newPDF = PDFSign.sign(null, new FileInputStream("src/test/resources/readytoSign.pdf"),
					new FileOutputStream("target/testSignExistingSignature.pdf"),
					"src/test/resources/charles-queremma.p12", "password", null, null, parameters);
			assertNotNull(newPDF);
			verif("target/testSignExistingSignature.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testSignVisible() throws Exception  {

			PdfSignParameters parameters = PdfSignParameters.getParametersForSign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "CERTIFIED_NO_CHANGES_ALLOWED" // certifLevel
					, false // signatureAlreadyExists
					, "mysignat" // signatureName
					, true // createNewRevision
					, true // keepPDFACompliance
					, false // allocateTSContainer
					, 0 // TSSize
					, 0 // SigSize
					, "SHA1" // dataHashAlgo
					, new GregorianCalendar());
			
			byte[] bgImage = FileUtils.readFileToByteArray(new File("src/test/resources/bgimage.JPG"));
			byte[] signatureImage = FileUtils.readFileToByteArray(new File("src/test/resources/signature_grande.JPG"));
			SignatureLayoutParameters signatureLayoutParameters = SignatureLayoutParameters
					.getLayoutParametersForNewSign(10, 10, 100, 100, 1, "cou\ncou", bgImage, -100, 3, 2,
							signatureImage, 0, 0, 0, null);
			parameters.setSignatureLayoutParameters(signatureLayoutParameters);

			SignReturn newPDF = PDFSign.sign(null, new FileInputStream("src/test/resources/minipdf.pdf"),
					new FileOutputStream("target/testSignVisible.pdf"), "src/test/resources/charles-queremma.p12",
					"password", null, null, parameters);
			assertNotNull(newPDF);

			verif("target/testSignVisible.pdf", true);
	}

	@Test
	public void testSignTimestamp() {
		try {

			PdfSignParameters parameters = PdfSignParameters.getParametersForSign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, false // signatureAlreadyExists
					, "mysignat" // signatureName
					, true // createNewRevision
					, true // keepPDFACompliance
					, false // allocateTSContainer
					, 0 // TSSize
					, 0 // SigSize
					, "SHA1" // dataHashAlgorithm
					, new GregorianCalendar());
			parameters.setTimeStampParams(new TimestampingParameters("http://172.19.0.52:318/TSS/HttpTspServer", null,
					null, "SHA1", true, "1.3.6.1.4.1.601.10.3.1"));

			SignReturn newPDF = PDFSign.sign(null, new FileInputStream("src/test/resources/minipdf.pdf"),
					new FileOutputStream("target/testSignTS.pdf"), "src/test/resources/charles-queremma.p12",
					"password", null, null, parameters);
			assertNotNull(newPDF);

			verif("target/testSignTS.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testPreSignSignCRL() {
		try {

			PdfSignParameters parameters = PdfSignParameters.getParametersForPresign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, false // signatureAlreadyExists
					, "mysignat" // signatureName
					, true // createNewRevision
					, false // allocateTimeStampContainer
					, 0 // TSSize
					, 0 // SigSize
					, false // keepPDFACompliance
					, new GregorianCalendar());
			PresignReturn presignRet = PDFSign.preSign(new FileInputStream("src/test/resources/minipdf.pdf"),
					parameters);
			assertNotNull(presignRet);

			String dataHashAlgo = "SHA1";
			PKCS12File p12 = new PKCS12File("src/test/resources/charles-queremma.p12", "password");
			Certificate[] chain = p12.getChain();
			PrivateKey privateKey = p12.mPrivateKey;

			CRL[] crls = new CRL[] { CRLHelper.getCRL(new File(
					"src/test/resources/OpenTrustSPICertificationAuthority30-11-2007.crl")) };

			byte[] encodedPkcs7 = CMSForPAdESBasicGenerator.signContent(BouncyCastleProvider.PROVIDER_NAME, presignRet
					.getDataToSign(), chain[0], privateKey, Arrays.asList(chain),
					parameters.getSigningTime().getTime(), dataHashAlgo, Arrays.asList(crls), null, false);

			SignReturn newPDF = PDFSign.signAfterPresignWithEncodedP7(new FileInputStream(
					"src/test/resources/minipdf.pdf"), new FileOutputStream("target/testPreSignSignCRL.pdf"),
					encodedPkcs7, chain[0], null, null, parameters);

			verif("target/testPreSignSignCRL.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	protected void testPAdESBES(String file) throws Exception {
		List<PDFEnvelopedSignature> verifResults = PDFVerifSignature.verify(file);
		testPAdESBES(verifResults);
	}

	protected void testPAdESBES(List<PDFEnvelopedSignature> verifResults) throws Exception {
		List<String> nonConformity = new ArrayList<String>();
		for (PDFEnvelopedSignature verifResult : verifResults) {
			List<String> nonConf = PAdESHelper.isPAdESBESConformant(verifResult, false);
			System.out.println(nonConf);
			nonConformity.addAll(nonConf);
		}
		if (!nonConformity.isEmpty())
			fail();
	}

	protected void testPAdESEPES(String file) throws Exception {
		List<PDFEnvelopedSignature> verifResults = PDFVerifSignature.verify(file);
		testPAdESEPES(verifResults);
	}

	protected void testPAdESEPES(List<PDFEnvelopedSignature> verifResults) throws Exception {
		List<String> nonConformity = new ArrayList<String>();
		for (PDFEnvelopedSignature verifResult : verifResults) {
			List<String> nonConf = PAdESHelper.isPAdESEPESConformant(verifResult, false);
			System.out.println(nonConf);
			nonConformity.addAll(nonConf);
		}
		if (!nonConformity.isEmpty())
			fail();
	}

	protected boolean verif(List<PDFEnvelopedSignature> verifResults, boolean failIfKO) throws Exception {
		// FIXME : verif for LTV data (DTS & DSS) (partly done for DTS)
		boolean pdfok = true;
		for (PDFEnvelopedSignature verifResult : verifResults) {
			pdfok = pdfok && verifResult.verify();
		}
		if (failIfKO && !pdfok)
			fail();
		return pdfok;
	}

	protected boolean verif(String file, boolean failIfKO) throws Exception {
		System.out.println("verification of " + file.substring(file.lastIndexOf("/")));
		List<PDFEnvelopedSignature> verifResults = PDFVerifSignature.verify(file);
		boolean pdfok = verif(verifResults, false);
		System.out.println("verification of " + file.substring(file.lastIndexOf("/")) + " : " + pdfok);
		if (failIfKO && !pdfok)
			fail();
		return pdfok;
	}

	public static void main(String[] args) {
		try {
			long before = System.currentTimeMillis();
			// new PDFSignTest().testPreSignSignLargePDF();

			// new PDFSignTest().testPreSignSignDigest();
			// new PDFSignTest().testAddTimestamp3();

			/*
			 * PdfReader reader2 = new PdfReader(new
			 * FileInputStream("target/testPreSignSignDigest.pdf-ADDED_TS.pdf"
			 * ));
			 * //src/test/resources/CDS_OCSP_Services.pdf"));"target/testSignOcsp
			 * .pdf" AcroFields af = reader2.getAcroFields();
			 * 
			 * ArrayList names = af.getSignatureNames(); for (int k = 0; k <
			 * names.size(); ++k) { String name = (String)names.get(k); PdfPKCS7
			 * pk = af.verifySignature(name); //
			 * pk.getOcspResponse().verifyOCSPResponseSignature
			 * (CertificateHelper.getCertificate(new
			 * File("src/test/resources/Adobe_ocsp_pem.cer"))); //
			 * System.out.println("signature "+name+" is ocsp-valid"); }
			 */
			System.out.println(System.currentTimeMillis() - before);

			PdfReader reader1 = new PdfReader("target/testSignVisible.pdf");
			PdfReader reader2 = new PdfReader("src/test/resources/MyPDF.pdf");
			PdfCopyFields copy = new PdfCopyFields(new FileOutputStream("target/concatenatedPDF.pdf"));
			copy.addDocument(reader1);
			copy.addDocument(reader2);
			copy.close();

			// PdfReader reader = new PdfReader("target/testSignTS.pdf");
			// PdfStamper stp = new PdfStamper(reader, new
			// FileOutputStream("target/concatenatedPDF.pdf"), '\0', true);
			// int pageNbr = reader.getNumberOfPages();
			// System.out.println(pageNbr);
			// stp.insertPage(1, PageSize.A4);
			//
			// PdfReader reader2 = new
			// PdfReader("src/test/resources/MyPDF.pdf");
			// PdfContentByte cb = stp.getOverContent(1);
			// cb.addTemplate(stp.getImportedPage(reader2, 1), 0,0);
			// stp.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	@Test
	public void testPreSignPreSign() throws Exception {
			String incomingFile = "src/test/resources/MyPDF.pdf";

			GregorianCalendar gc = new GregorianCalendar();
			PdfSignParameters parameters = PdfSignParameters.getParametersForPresign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, false // signatureAlreadyExists
					, "mysignat" // signatureName
					, true // createNewRevision
					, false // allocateTimeStampContainer
					, 0 // TSSize
					, 0 // SigSize
					, false // keepPDFACompliance
					, gc);

			parameters.setDataHashAlgorithm("SHA1");

			PresignReturn presignRet1 = PDFSign
					.preSign(new FileInputStream(incomingFile), null, null, null, parameters);
			PresignReturn presignRet2 = PDFSign
					.preSign(new FileInputStream(incomingFile), null, null, null, parameters);
			System.out.println("PRESIGNPRESIGN1=" + new String(Hex.encode(presignRet1.getHashToSign())));
			System.out.println("PRESIGNPRESIGN2=" + new String(Hex.encode(presignRet2.getHashToSign())));
			assertTrue(Arrays.equals(presignRet1.getHashToSign(), presignRet2.getHashToSign()));
			//assertEquals(HexHelper.encode(presignRet1.getHashToSign()), HexHelper.encode(presignRet2.getHashToSign()));


	}

	@Test
	public void testPreSignSign() {
		try {
			String incomingFile = "src/test/resources/MyPDF.pdf";

			PdfSignParameters parameters = PdfSignParameters.getParametersForPresign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, false // signatureAlreadyExists
					, "mysignat" // signatureName
					, true // createNewRevision
					, true // allocateTimeStampContainer
					, 0 // TSSize
					, 0 // SigSize
					, false // keepPDFACompliance
					, new GregorianCalendar());
			PresignReturn presignRet = PDFSign.preSign(new FileInputStream(incomingFile), parameters);
			assertNotNull(presignRet);

			parameters.setDataHashAlgorithm("SHA1");
			byte[] encodedPkcs7 = PDFSign.cms_sign(presignRet.getDataToSign(),
					"src/test/resources/charles-queremma.p12", "password", parameters, null, null).getEncodedPkcs7();

			FileOutputStream cmsBytes = new FileOutputStream("target/dumpCMSBytes2.eml");
			cmsBytes.write(encodedPkcs7);
			cmsBytes.close();

			PKCS12File p12 = new PKCS12File("src/test/resources/charles-queremma.p12", "password");
			Certificate[] chain = p12.getChain();
			PrivateKey privateKey = p12.mPrivateKey;
			SignReturn newPDF = PDFSign.signAfterPresignWithEncodedP7(new FileInputStream(incomingFile),
					new FileOutputStream("target/testPreSignSign.pdf"), encodedPkcs7, chain[0], null, null, parameters);

			verif("target/testPreSignSign.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testPreSignSignStream() {
		try {
			String incomingFile = "src/test/resources/MyPDF.pdf";

			PdfSignParameters parameters = PdfSignParameters.getParametersForPresign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, false // signatureAlreadyExists
					, "mysignat" // signatureName
					, true // createNewRevision
					, true // allocateTimeStampContainer
					, 0 // TSSize
					, 0 // SigSize
					, false // keepPDFACompliance
					, new GregorianCalendar());
			PresignReturn presignRet = PDFSign.preSign(new FileInputStream(incomingFile), parameters);
			assertNotNull(presignRet);

			parameters.setDataHashAlgorithm("SHA1");
			byte[] encodedPkcs7 = PDFSign.cms_sign(presignRet.getDataToSign(),
					"src/test/resources/charles-queremma.p12", "password", parameters, null, null).getEncodedPkcs7();

			FileOutputStream cmsBytes = new FileOutputStream("target/dumpCMSBytes2.eml");
			cmsBytes.write(encodedPkcs7);
			cmsBytes.close();

			PKCS12File p12 = new PKCS12File("src/test/resources/charles-queremma.p12", "password");
			Certificate[] chain = p12.getChain();
			PrivateKey privateKey = p12.mPrivateKey;
			SignReturn newPDF = PDFSign.signAfterPresignWithEncodedP7(incomingFile, new FileOutputStream(
					"target/testPreSignSignStream.pdf"), null, encodedPkcs7, chain[0], null, null, parameters);

			verif("target/testPreSignSignStream.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testPreSignSignLargePDF() {
		try {
			buildLargePDF();
			PdfSignParameters parameters = PdfSignParameters.getParametersForPresign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, false // signatureAlreadyExists
					, "mysignat" // signatureName
					, true // createNewRevision
					, true // allocateTimeStampContainer
					, 0 // TSSize
					, 0 // SigSize
					, false // keepPDFACompliance
					, new GregorianCalendar());

			parameters.setDataHashAlgorithm("SHA1");
			Date d = new Date();
			PresignReturn presignRet = PDFSign.preSign(largePDFName, tmpFolder, parameters);
			assertNotNull(presignRet);

			byte[] encodedPkcs7 = PDFSign.cms_sign(presignRet.getHashToSign(),
					"src/test/resources/charles-queremma.p12", "password", parameters, null, null).getEncodedPkcs7();

			// TODO : Remove tmp file (and close streams ?)

			PKCS12File p12 = new PKCS12File("src/test/resources/charles-queremma.p12", "password");
			Certificate[] chain = p12.getChain();

			SignReturn newPDF = PDFSign.signAfterPresignWithEncodedP7(largePDFName, new FileOutputStream(
					"target/testPreSignSignLargePDF.pdf"), tmpFolder, encodedPkcs7, chain[0], null, null, parameters);
			System.out.println("PreSignSignLargePDF in " + (new Date().getTime() - d.getTime()));
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testPreSignSignDigest() {
		try {
			String incomingFile = "src/test/resources/MyPDF.pdf";

			PdfSignParameters parameters = PdfSignParameters.getParametersForPresign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, false // signatureAlreadyExists
					, "mysignat" // signatureName
					, true // createNewRevision
					, true // allocateTimeStampContainer
					, 0 // TSSize
					, 0 // SigSize
					, false // keepPDFACompliance
					, new GregorianCalendar());

			parameters.setDataHashAlgorithm("SHA1");
			PresignReturn presignRet = PDFSign.preSign(new FileInputStream(incomingFile), null, null, null, parameters);
			assertNotNull(presignRet);

			PKCS12File p12 = new PKCS12File("src/test/resources/charles-queremma.p12", "password");
			Certificate[] chain = p12.getChain();
			PrivateKey privateKey = p12.mPrivateKey;

			byte[] encodedPkcs7 = PDFSign.cms_sign(presignRet.getHashToSign(), privateKey, chain, parameters, null,
					null).getEncodedPkcs7();

			FileOutputStream cmsBytes = new FileOutputStream("target/dumpCMSBytes1.eml");
			cmsBytes.write(encodedPkcs7);
			cmsBytes.close();

			SignReturn newPDF = PDFSign.signAfterPresignWithEncodedP7(new FileInputStream(incomingFile),
					new FileOutputStream("target/testPreSignSignDigest.pdf"), encodedPkcs7, chain[0], null, null,
					parameters);

			verif("target/testPreSignSignDigest.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testPreSignSignVisible() {
		try {
			String incomingFile = "src/test/resources/MyPDF.pdf";

			PdfSignParameters parameters = PdfSignParameters.getParametersForPresign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, false // signatureAlreadyExists
					, "mysignat" // signatureName
					, true // createNewRevision
					, false // allocateTimeStampContainer
					, 0 // TSSize
					, 0 // SigSize
					, true // keepPDFACompliance
					, new GregorianCalendar());
			SignatureLayoutParameters signatureLayoutParameters = SignatureLayoutParameters
					.getLayoutParametersForNewSign(10, 10, 100, 100, 1, "coucou", null, 0, 0, 0, null, 0, 0, 0, null);
			parameters.setSignatureLayoutParameters(signatureLayoutParameters);

			PresignReturn presignRet = PDFSign.preSign(new FileInputStream(incomingFile), parameters);
			assertNotNull(presignRet);

			PKCS12File p12 = new PKCS12File("src/test/resources/charles-queremma.p12", "password");
			Certificate[] chain = p12.getChain();
			PrivateKey privateKey = p12.mPrivateKey;

			parameters.setDataHashAlgorithm("SHA1");
			byte[] encodedPkcs7 = PDFSign.cms_sign(presignRet.getDataToSign(),
					"src/test/resources/charles-queremma.p12", "password", parameters, null, null).getEncodedPkcs7();

			SignReturn newPDF = PDFSign.signAfterPresignWithEncodedP7(new FileInputStream(incomingFile),
					new FileOutputStream("target/testPreSignSignVisible.pdf"), encodedPkcs7, chain[0], null, null,
					parameters);

			verif("target/testPreSignSignVisible.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	// @Test
	public void testSignDateRounding() throws Exception {
		for (int i = 0; i < 5000; i++) {
			testPreSignSignWithRawSignature(Math.random());
		}
	}

	public void testPreSignSignWithRawSignature(double rand) throws Exception {
		PdfSignParameters parameters = PdfSignParameters.getParametersForPresign("ppkms" // mode
				, "I am the signer" // reason
				, "Paris(France)" // location
				, "118.218" // contact
				, "NOT_CERTIFIED" // certifLevel
				, false // signatureAlreadyExists
				, "mysignat" // signatureName
				, true // createNewRevision
				, true // allocateTimeStampContainer
				, 0 // TSSize
				, 0 // SigSize
				, false // keepPDFACompliance
				, new GregorianCalendar());

		String digestHashAlgo = "SHA1";
		parameters.setDataHashAlgorithm(digestHashAlgo); // needed to call
															// preSignForRawSignature

		PKCS12File p12 = new PKCS12File("src/test/resources/charles-queremma.p12", "password");
		Certificate[] chain = p12.getChain();
		PrivateKey privateKey = p12.mPrivateKey;

		PresignReturnForRawSignature presignRet = PDFSign.preSignForRawSignature(new FileInputStream(
				"src/test/resources/MyPDF.pdf"), chain, null, null, parameters);
		assertNotNull(presignRet);

		String algo = privateKey.getAlgorithm();
		Signature sig = Signature.getInstance(SignatureHelper
				.getSignatureAlgoFromDigestAndKeyAlgo(digestHashAlgo, algo));
		sig.initSign(privateKey);
		sig.update(presignRet.getHashToSign());

		byte[] rawSignature = sig.sign();

		SignReturn newPDF = PDFSign.signAfterPresignWithRawSignature(
				new FileInputStream("src/test/resources/MyPDF.pdf"), new FileOutputStream(
						"target/testPreSignSignWithRawSignature" + rand + ".pdf"), rawSignature, presignRet
						.getEncodedPkcs7WithoutSignature(), chain[0], parameters);

		verif("target/testPreSignSignWithRawSignature" + rand + ".pdf", true);
	}

	@Test
	public void testPreSignSignWithRawSignature() throws Exception {

			testPreSignSignWithRawSignature(0);

	}

	@Test
	public void testAddTimestamp1() throws Exception {
		testAddTimestamp("target/testPreSignSignDigest.pdf", false, true);
	}

	@Test
	public void testAddTimestamp2() throws Exception {
		testAddTimestamp("target/testPreSignSign.pdf", false, true);
	}

	@Test
	public void testAddTimestamp3() {
		// skipped because takes too long to parse 250000 pages (in
		// AcroFields.fill called from reader2.getAcroFields();
		// testAddTimestamp("target/testPreSignSignLargePDF.pdf", true, true);
	}

	@Test
	public void testAddTimestamp4() throws Exception {
		testAddTimestamp("target/testSignOcsp.pdf", false, true);
	}

	@Test
	public void testAddTimestamp5() throws Exception {
		// Verification should be KO because timestamping on signature1
		// invalidates signature2
		// (as long as signature2 covers doc + signature1)
		assertEquals(false, testAddTimestamp("target/testSignSign.pdf", false, false));
	}

	@Test
	public void testAddTimestamp6() throws Exception {
		// addition of TS raises exception because not enough space was
		// allocated at signing time
		assertEquals(false, testAddTimestamp("target/testPreSignSignCRL.pdf", false, false));
	}

	private boolean testAddTimestamp(String file, boolean big, boolean verif) throws Exception {
		try {
			String workingFile = "target/addTSWorkingFile.pdf";
			//FileHelper.bufferedCopyFile(file, workingFile + 0);
			File dst = new File(workingFile + 0);
			File src = new File(file);			
			FileUtils.copyFile(src, dst);
			
			PdfReader reader2 = null;
			if (big)
				reader2 = new PdfReader(new RandomAccessFileOrArray(file), null);
			else
				reader2 = new PdfReader(new FileInputStream(file));

			AcroFields af = reader2.getAcroFields();

			ArrayList names = af.getSignatureNames(false);
			System.out.println("Signatures found : " + names);
			int k;
			for (k = 0; k < names.size(); ++k) {
				String name = (String) names.get(k);
				System.out.println("Dealing with signature " + name + " out of " + af.getSignatureNames());
				PdfPKCS7 pk = af.verifySignature(name);
				System.out.println("testAddTimestamp.verify=" + pk.verify());
				pk.setTimeStampDigestAlgo("SHA1");
				/*
				pk.setServerTimestamp("http://172.19.0.52:318/TSS/HttpTspServer");
				pk.setTimeStampPolicyId("1.3.6.1.4.1.601.10.3.1");
				*/
				pk.setTspClient(defaultTspClient);

				byte[] newSignatureBytes = pk.getUpdatedEncodedPKCS7WithAddedTS();

				FileOutputStream cmsBytes = new FileOutputStream("target/dumpCMSBytesWithTS.eml");
				cmsBytes.write(newSignatureBytes);
				cmsBytes.close();

				int[] byteRange = pk.getByteRange();
				int signaturePosition = byteRange[1];
				int signaturePositionEnd = byteRange[2];
				int lastChunkSize = byteRange[3]; // only used if timestamping
													// last signature

				byte out4[] = new byte[((signaturePositionEnd - signaturePosition) - 2) / 2];
				System.out.println("new signature length=" + newSignatureBytes.length);
				System.out.println("allocated signature length=" + out4.length);
				// byte out4[] = new byte[0x5000 / 2];
				System.arraycopy(newSignatureBytes, 0, out4, 0, newSignatureBytes.length);
				// TODO : verify that 'bytes' size is not bigger than
				// signaturePositionEnd-signaturePosition
				// If not, exception "not enough space to insert signature data
				// TODO : improve that by trying to enlarge dynamically
				// 'CONTENTS' size

				String buff = "<" + HexHelper.encode(out4) + ">";

				byte[] bf = buff.getBytes();

				FileOutputStream newOS = new FileOutputStream(workingFile + (k + 1));
				InputStream oldPDFStream = new FileInputStream(workingFile + k);
				// copy the first bytes of the pdf
				copy(newOS, oldPDFStream, signaturePosition);

				// skip the bytes containing the signature, and insert the new
				// signature bytes
				byte[] skip = new byte[bf.length];
				oldPDFStream.read(skip);
				newOS.write(bf, 0, bf.length);

				// copy the last bytes of the pdf
				if (names.size() == k - 1)
					copy(newOS, oldPDFStream, lastChunkSize);
				else
					copy(newOS, oldPDFStream);

				newOS.flush();
			}

			//FileHelper.bufferedCopyFile(workingFile + k, file + "-ADDED_TS.pdf");
			FileUtils.copyFile(new File(workingFile + k), 
					new File(file + "-ADDED_TS.pdf"));

			PdfReader reader3 = new PdfReader(new RandomAccessFileOrArray(file + "-ADDED_TS.pdf"), null);
			AcroFields af2 = reader3.getAcroFields();

			ArrayList names2 = af2.getSignatureNames();
			for (k = 0; k < names2.size(); ++k) {
				String name = (String) names2.get(k);
				PdfPKCS7 pk = af2.verifySignature(name);
				System.out.println("digest for sign in addedTS is : " + HexHelper.encode(pk.getSignatureValue()));
				System.out.println("verify=" + pk.verify());
			}
			return verif(file + "-ADDED_TS.pdf", verif);

		} catch (Exception e) {
			e.printStackTrace();
			if (verif)
				throw e;
			else
				return false;
		}
	}

	private void copy(OutputStream out, InputStream in, long length) throws IOException {
		long total = 0;
		while (total < length) {
			int read = (int) Math.min(1024, length - total);
			byte[] buffer = new byte[read];
			in.read(buffer);
			out.write(buffer);
			total += read;
		}

	}

	private void copy(OutputStream out, InputStream in) throws IOException {
		int read = 1024;
		while (read > 0) {
			byte[] buffer = new byte[1024];
			read = in.read(buffer);
			if (read > 0)
				out.write(buffer, 0, read);
		}

	}

	@Test
	public void testPreSignSignTimestamp() {
		try {
			PdfSignParameters parameters = PdfSignParameters.getParametersForPresign("ppkms" // mode
					, "I am the signer" // reason
					, "Paris(France)" // location
					, "118.218" // contact
					, "NOT_CERTIFIED" // certifLevel
					, false // signatureAlreadyExists
					, "mysignat" // signatureName
					, true // createNewRevision
					, true // allocateTimeStampContainer
					, 0 // TSSize
					, 0 // SigSize
					, false // keepPDFACompliance
					, new GregorianCalendar());
			PresignReturn presignRet = PDFSign.preSign(new FileInputStream("src/test/resources/MyPDF.pdf"), parameters);
			assertNotNull(presignRet);

			PKCS12File p12 = new PKCS12File("src/test/resources/charles-queremma.p12", "password");
			Certificate [] chain = p12.getChain();
			/*
			KeyStore keyStore = KeyStoreHelper.load("src/test/resources/charles-queremma.p12", "password");
			String alias = KeyStoreHelper.getDefaultAlias(keyStore);
			Certificate[] chain = (Certificate[]) keyStore.getCertificateChain(alias);
			*/
			

			parameters.setTimeStampParams(new TimestampingParameters("http://172.19.0.52:318/TSS/HttpTspServer", null,
					null, "SHA1", true, "1.3.6.1.4.1.601.10.3.1"));
			parameters.setDataHashAlgorithm("SHA1");
			SignResult sr = PDFSign.cms_sign(presignRet.getDataToSign(), "src/test/resources/charles-queremma.p12",
					"password", parameters, null, null);

			byte[] encodedPkcs7 = sr.getEncodedPkcs7();
			SignReturn newPDF = PDFSign.signAfterPresignWithEncodedP7(new FileInputStream(
					"src/test/resources/MyPDF.pdf"), new FileOutputStream("target/testPreSignSignTimestamp.pdf"),
					encodedPkcs7, chain[0], null, null, parameters);

			verif("target/testPreSignSignTimestamp.pdf", true);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testEmbedFont() {
		try {
			Document document = new Document();

			// step 2: creation of the writer
			PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream("target/testEmbedFont.pdf"));
			// writer.setPDFXConformance(PdfWriter.PDFA1A);

			// step 3: we open the document
			document.open();

			// step 4: we add content to the document
			BaseFont helvetica = BaseFont.createFont("c:/windows/fonts/arialbd.ttf", "Cp1252", BaseFont.EMBEDDED);// BaseFont.createFont("Helvetica",
																													// BaseFont.CP1252,
																													// BaseFont.EMBEDDED);
			// Font font = FontFactory.getFont("Arial", BaseFont.CP1252,
			// BaseFont.EMBEDDED);
			Font font = new Font(helvetica, 12, Font.NORMAL);
			// BaseFont arial = BaseFont.createFont("arial.ttf",
			// BaseFont.WINANSI, BaseFont.EMBEDDED);
			// Font font = new Font(arial, 12);

			Chunk chunk = new Chunk(
					"Sponsor this example and send me 1\u20ac. These are some special characters: \u0152\u0153\u0160\u0161\u0178\u017D\u0192\u02DC\u2020\u2021\u2030",
					font);
			document.add(chunk);

			// step 5: we close the document
			document.close();

		} catch (Exception de) {
			de.printStackTrace();
		}

	}

	@Test
	public void testExtractRevision() {
		try {
			PdfReader reader = new PdfReader("src/test/resources/signed_signed_minipdf.pdf");
			AcroFields af = reader.getAcroFields();
			ArrayList names = af.getSignatureNames();
			for (int k = 0; k < names.size(); ++k) {
				String name = (String) names.get(k);
				System.out.println("Signature name: " + name);
				System.out.println("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
				System.out.println("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());
				// Start revision extraction
				FileOutputStream out = new FileOutputStream("target/testExtractRevision_" + af.getRevision(name)
						+ ".pdf");
				byte bb[] = new byte[8192];
				InputStream ip = af.extractRevision(name);
				int n = 0;
				while ((n = ip.read(bb)) > 0)
					out.write(bb, 0, n);
				out.close();
				ip.close();
				// End revision extraction
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testVerifSign() {
		try {
			System.out.println("verifying MySignedPDF.pdf");
			boolean pdfok = verif("src/test/resources/MySignedPDF.pdf", false); // signed
																				// with
																				// PKCS#1
																				// RSA-SHA1
			System.out.println("verification : " + pdfok);
			assertEquals(pdfok, true);

			pdfok = verif("src/test/resources/authorsigned_minipdf.pdf", false);
			System.out.println("verification : " + pdfok);
			assertEquals(pdfok, true);

			pdfok = verif("src/test/resources/PKCS1_signed_SHA256.pdf", false);
			System.out.println("verification : " + pdfok);
			assertEquals(pdfok, true);

			pdfok = verif("src/test/resources/signed_p7_detached_without_signedAttr.pdf", false);
			System.out.println("verification : " + pdfok);
			assertEquals(pdfok, true);

			pdfok = verif("src/test/resources/weirdAlgoIdentifier.pdf", false);
			System.out.println("verification : " + pdfok);
			assertEquals(pdfok, true);

			boolean pdfnok = verif("src/test/resources/MySignedPDFInvalid.pdf", false); // signed
																						// with
																						// PKCS#1
																						// RSA-SHA256
			System.out.println("verification : " + pdfnok);
			assertEquals(pdfnok, false);

			try {
				verif("src/test/resources/Signature-P-PK7N-5-1-3.pdf", false); // invalid
																				// byterange
																				// :
																				// goes
																				// beyond
																				// the
																				// actual
																				// size
																				// of
																				// the
																				// document
				fail();
			} catch (Exception e) {
				System.out.println("verification : " + e);
			}

			pdfnok = verif("src/test/resources/invalid_signature.pdf", false); // adbe.pkcs7.detached
																				// with
																				// OK
																				// hash
																				// but
																				// KO
																				// RSA
																				// sig
			System.out.println("verification : " + pdfnok);
			assertEquals(pdfnok, false);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
}