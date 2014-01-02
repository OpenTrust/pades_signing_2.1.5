package com.opentrust.spi.crypto;

import com.keynectis.sequoia.security.signeddocument.IllegalDataSignatureException;
import com.opentrust.spi.pdf.SPIIllegalDataException;

public class ExceptionHandler {

	public static void handle(Exception e) {
	    if (e instanceof SPIIllegalDataException) {
	        // Check sequoia security package dependency as SPI PDF jar can be used in standalone mode
	        // on client side for pdf delegating signature.
	        try {
	            Class.forName(IllegalDataSignatureException.class.getName());
	        } catch(ClassNotFoundException e1) {
	            throw new IllegalArgumentException(e.getMessage(), e);
	        }
	        throw new IllegalDataSignatureException(e.getMessage(), e);
	    }
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
