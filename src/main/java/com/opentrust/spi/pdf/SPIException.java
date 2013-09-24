package com.opentrust.spi.pdf;

public class SPIException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = -623540694252659027L;
	String format;
	Object [] objects;
	public SPIException(String string, Object...objects) {
		this.format = string;
		this.objects = objects;
	}
	public SPIException(Throwable cause, String string, Object...objects) {
	    super(cause);
        this.format = string;
        this.objects = objects;
    }
	@Override
	public String getMessage() {
		return String.format(format, objects);
	}

}
