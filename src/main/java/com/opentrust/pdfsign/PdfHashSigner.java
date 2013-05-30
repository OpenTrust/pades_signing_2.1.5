package com.opentrust.pdfsign;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;

import org.bouncycastle.util.io.Streams;

import com.keynectis.sequoia.security.signeddocument.Document;
import com.opentrust.spi.cms.CMSSignedDataWrapper;
import com.opentrust.spi.pdf.PDFSign;

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
	public void sign(Document doc, OutputStream os) throws Exception {
		checkSupportedType(doc);
		
		PdfHash pdf = (PdfHash) doc;
		
		CMSSignedDataWrapper cms_sign = PDFSign.cms_sign(getHashAlgorithm(), pdf.hash, (PrivateKey) getSigningKey(),
				getSigningChainArray(), getSignatureParameters(), getCrls(), getOcspResponses());
		os.write(cms_sign.getEncoded());
	}
}
