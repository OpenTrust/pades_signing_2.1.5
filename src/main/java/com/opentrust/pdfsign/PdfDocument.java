package com.opentrust.pdfsign;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;

import com.keynectis.sequoia.security.signeddocument.Document;
import com.spilowagie.text.pdf.AcroFields;
import com.spilowagie.text.pdf.PdfReader;

public class PdfDocument implements Document {

    PdfReader reader;
    AcroFields af;
    OutputStream signedStream;
    private ArrayList<String> docSignedFieldNames;
    
    @SuppressWarnings("unchecked")
    public PdfDocument(InputStream is) throws IOException {
		super();
		this.reader = new PdfReader(is);
		this.af = reader.getAcroFields();
		boolean withDocTS = false;
        this.docSignedFieldNames = (ArrayList<String>) af.getSignatureNames(withDocTS );
	}
	
    protected PdfReader getReader() {
        return reader;
    }
    
    protected AcroFields getAcroFields() {
        return af;
    }
    
    public Collection<String> getSignatureIdList() {
        return docSignedFieldNames;
    }
    
	@Override
	public void save(OutputStream os) throws IOException {
		throw new UnsupportedOperationException();		
	}
	
}
