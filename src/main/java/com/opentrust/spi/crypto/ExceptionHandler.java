package com.opentrust.spi.crypto;

import java.security.SignatureException;

import com.keynectis.sequoia.security.signeddocument.IllegalDataSignatureException;
import com.opentrust.spi.pdf.SPIException;
import com.opentrust.spi.pdf.SPIIllegalDataException;

public class ExceptionHandler {

	public static void handle(Exception e) {
	    if (e instanceof SPIIllegalDataException)
	        throw new IllegalDataSignatureException(e.getMessage(), e); 
		if (e instanceof RuntimeException)
			throw (RuntimeException) e;
		
		throw new RuntimeException(e);		
	}

	public static void handle(Exception e, String msg) {
		throw new RuntimeException(msg, e);				
	}
	
	public static void handleNoThrow(Exception e, String string) {
		// TODO Auto-generated method stub
		
	}	

}
