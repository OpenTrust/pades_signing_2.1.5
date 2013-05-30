package com.opentrust.pdfsign;

import java.io.OutputStream;

import com.keynectis.sequoia.security.signeddocument.Document;

public class PdfHash implements Document{
	public byte [] hash;

	public PdfHash(byte[] hash) {
		super();
		this.hash = hash;
	}
	public byte [] signature;
	@Override
	public void save(OutputStream os) throws Exception {
		os.write(signature);		
	}
}
