package com.opentrust.pdfsign;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.util.io.Streams;

import com.keynectis.sequoia.security.signeddocument.Document;
import com.keynectis.sequoia.security.signeddocument.DocumentSignResult;
import com.opentrust.spi.cms.CMSSignedDataWrapper;
import com.opentrust.spi.pdf.PDFSign;
import com.opentrust.spi.tsp.TimestampToken;

public class PdfHashSigner extends PdfSigner {
	@Override
	public Document parseDocument(InputStream is) throws IOException {
		byte[] hash = Streams.readAll(is);
		return new PdfHash(hash);
	}
	
	@Override
	protected Class[] getSupportedDocumentTypeList() {
		return new Class [] {PdfHash.class};
	}
	
	@Override
	public DocumentSignResult sign(Document doc, OutputStream os) throws Exception {
		checkSupportedType(doc);
		
		PdfHash pdf = (PdfHash) doc;
		
		CMSSignedDataWrapper cms_sign = PDFSign.cms_sign(getHashAlgorithm(), pdf.hash, (PrivateKey) getSigningKey(),
				getSigningChainArray(), getSignatureParameters(), getCrls(), getOcspResponses());
		os.write(cms_sign.getEncoded());

		DocumentSignResult result = new DocumentSignResult();
		result.setSigningCertificate(getSigningCertificate());
		
		List<TimestampToken> signatureTimestamps = cms_sign.getSignatureTimestamps();
		if (signatureTimestamps != null && !signatureTimestamps.isEmpty()) {
		    //Use the first time stamp in the list, implement a better algorithm if needed
		    TimestampToken timestampToken = signatureTimestamps.get(0);
		    
		    if (timestampToken != null) {
		        result.setSignatureTimestampDate(timestampToken.getDateTime());
	            Certificate timestampSigner = timestampToken.getSignerCertificate();
	            if (timestampSigner != null) {
	                result.setSignatureTimestampSignerCertificate((X509Certificate) timestampSigner);
	            }
		    }
		}
		
		return result;
	}
}
