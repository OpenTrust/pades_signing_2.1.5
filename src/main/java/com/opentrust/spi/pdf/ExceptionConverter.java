package com.opentrust.spi.pdf;

/**
 * The ExceptionConverter changes a checked exception into an unchecked exception.
 */
public class ExceptionConverter extends RuntimeException {
	private static final long serialVersionUID = 8657630363395849399L;

	/** we keep a handle to the wrapped exception */
	private Exception ex;

	/** prefix for the exception */
	private String prefix;

	/**
	 * Construct a RuntimeException based on another Exception
	 * 
	 * @param ex
	 *            the exception that has to be turned into a RuntimeException
	 */
	public ExceptionConverter(Exception ex) {
		this.ex = ex;
		prefix = (ex instanceof RuntimeException) ? "" : "ExceptionConverter: ";
	}

	/**
	 * and allow the user of ExceptionConverter to get a handle to it.
	 * 
	 * @return the original exception
	 */
	public Exception getException() {
		return ex;
	}

	/**
	 * We print the message of the checked exception
	 * 
	 * @return message of the original exception
	 */
	public String getMessage() {
		return ex.getMessage();
	}

	/**
	 * and make sure we also produce a localized version
	 * 
	 * @return localized version of the message
	 */
	public String getLocalizedMessage() {
		return ex.getLocalizedMessage();
	}

	/**
	 * The toString() is changed to be prefixed with ExceptionConverter
	 * 
	 * @return Stringversion of the exception
	 */
	public String toString() {
		return prefix + ex;
	}

	/** we have to override this as well */
	public void printStackTrace() {
		printStackTrace(System.err);
	}

	/**
	 * here we prefix, with s.print(), not s.println(), the stack trace with "ExceptionConverter:"
	 * 
	 * @param s
	 */
	public void printStackTrace(java.io.PrintStream s) {
		synchronized (s) {
			s.print(prefix);
			ex.printStackTrace(s);
		}
	}

	/**
	 * Again, we prefix the stack trace with "ExceptionConverter:"
	 * 
	 * @param s
	 */
	public void printStackTrace(java.io.PrintWriter s) {
		synchronized (s) {
			s.print(prefix);
			ex.printStackTrace(s);
		}
	}

	/**
	 * requests to fill in the stack trace we will have to ignore. We can't throw an exception here, because this method
	 * is called by the constructor of Throwable
	 * 
	 * @return a Throwable
	 */
	public Throwable fillInStackTrace() {
		return this;
	}
}