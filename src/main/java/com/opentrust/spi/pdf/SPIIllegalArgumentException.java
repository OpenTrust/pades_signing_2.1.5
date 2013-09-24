package com.opentrust.spi.pdf;

public class SPIIllegalArgumentException extends SPIException {

	/**
     * 
     */
    private static final long serialVersionUID = 1L;

    public SPIIllegalArgumentException(String string, Object... objects) {
		super(string, objects);
	}

    public SPIIllegalArgumentException(Throwable cause, String string, Object... objects) {
        super(cause, string, objects);
    }
}
