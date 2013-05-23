package com.opentrust.spi.logger;

public class SPILogger {
	static SPILogger doNothingLogger = new SPILogger();
	public static SPILogger defaultLogger = doNothingLogger;
	public static SPILogger getDefaultLogger() {
		return defaultLogger;
	}

	public static void setDefaultLogger(SPILogger defaultLogger) {
		SPILogger.defaultLogger = defaultLogger;
	}


	public static interface ILoggerFactory
	{
		SPILogger getLogger(String loggerId);
	}
	static ILoggerFactory loggerFactory = new ILoggerFactory() {		
		public SPILogger getLogger(String loggerId) {
			return defaultLogger;
		}
	};
	
	public static void setLoggerFactory(ILoggerFactory factory)
	{
		loggerFactory = factory;
	}
	
	public static SPILogger getLogger(String loggerId)
	{
		return loggerFactory.getLogger(loggerId);
	}
	
	public void log(String log)
	{
		// do nothing
	}

	public void debug(String channel, String formatString, Object...strings ) {
		String msg = String.format(formatString, strings);
		log("DEBUG : " + msg);
	}

	public void error(String channel, String formatString, Object...strings ) {
		String msg = String.format(formatString, strings);
		log("ERROR : " + msg);
	}

	public void info(String channel, String formatString, Object...strings ) {
		String msg = String.format(formatString, strings);		
		log("INFO : " + msg);
	}
	

	public boolean isDebugEnabled(String tech) {
		return false;
	}
}
