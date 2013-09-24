package com.opentrust.spi.pdf;

public class SPIIllegalDataException extends SPIException {

	/**
     * 
     */
    private static final long serialVersionUID = 1L;

    public SPIIllegalDataException(String string, Object... objects) {
		super(string, objects);
	}
    
    public SPIIllegalDataException(Throwable cause, String string, Object... objects) {
        super(cause, string, objects);
    }

}
