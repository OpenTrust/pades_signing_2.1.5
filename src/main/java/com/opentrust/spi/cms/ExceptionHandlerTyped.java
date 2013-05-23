package com.opentrust.spi.cms;

import java.security.SignatureException;

public class ExceptionHandlerTyped {

	public static <T> void handle(Class class1, Exception e) {
		throw new RuntimeException(e);		
	}

	public static <T> void handle(Class class1, Exception e, String string) {
		throw new RuntimeException(string, e);				
	}

}
