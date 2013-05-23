package com.opentrust.pdfsign;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.keynectis.sequoia.security.signeddocument.Document;
import com.spilowagie.text.pdf.PdfReader;

public class PdfDocument implements Document {
	public PdfDocument(InputStream is) throws IOException {
		super();
		this.reader = new PdfReader(is);
	}

	PdfReader reader;
	OutputStream signedStream;
	@Override
	public void save(OutputStream os) throws IOException {
		throw new UnsupportedOperationException();		
	}
	
	
}
