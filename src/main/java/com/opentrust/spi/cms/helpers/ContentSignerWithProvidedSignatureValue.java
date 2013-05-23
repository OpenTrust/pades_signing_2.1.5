package com.opentrust.spi.cms.helpers;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

public class ContentSignerWithProvidedSignatureValue implements ContentSigner {
	private byte[] signature;
	private String digestEncryptionAlgorithm;
	
	public ContentSignerWithProvidedSignatureValue(byte signature[],String digestEncryptionAlgorithm) {
		this.signature = signature;
		this.digestEncryptionAlgorithm = digestEncryptionAlgorithm;
	}
	public byte[] getSignature() {
		return this.signature;
	}
	
	public OutputStream getOutputStream() {
		return new OutputStream() {
			@Override
			public void write(int i) throws IOException {
				// do nothing
			}
		};
	}
	
	public AlgorithmIdentifier getAlgorithmIdentifier() {
		return new AlgorithmIdentifier(digestEncryptionAlgorithm);
	}	
	public String getAlgorithm() {
		return digestEncryptionAlgorithm;
	}	
}
