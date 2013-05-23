package com.opentrust.spi.logger;

import java.io.PrintStream;

public class PrintStreamLogger extends SPILogger{

	PrintStream ps;
	public PrintStreamLogger(PrintStream ps)
	{
		this.ps = ps;
	}
	
	@Override
	public void log(String log) {
		ps.println(log);
	}

}
