package com.opentrust.pdfsign;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.List;

import com.keynectis.sequoia.security.signeddocument.Document;
import com.spilowagie.text.pdf.PdfReader;

public class PdfDocument implements Document {

    PdfReader reader;
    OutputStream signedStream;
    private List<String> docSignedFieldNames;
    
    public PdfDocument(InputStream is) throws IOException {
		super();
		this.reader = new PdfReader(is);
		this.docSignedFieldNames = null;
	}


	
	@Override
	public void save(OutputStream os) throws IOException {
		throw new UnsupportedOperationException();		
	}
	
	public Collection<String> getSignatureIdList() {
	    return docSignedFieldNames;
	}
}
