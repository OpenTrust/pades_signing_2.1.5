package com.opentrust.spi.crypto;

public class ExceptionHandler {

	public static void handle(Exception e) {
		if (e instanceof RuntimeException)
			throw (RuntimeException) e;
		
		throw new RuntimeException(e);		
	}

	public static void handle(Exception e, String msg) {
		if (e instanceof RuntimeException)
			throw (RuntimeException) e;
		
		throw new RuntimeException(msg, e);				
	}
	
	public static void handleNoThrow(Exception e, String string) {
		// TODO Auto-generated method stub
		
	}	

}
