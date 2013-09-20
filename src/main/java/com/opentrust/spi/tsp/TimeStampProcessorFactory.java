package com.opentrust.spi.tsp;

import com.opentrust.spi.logger.Channel;
import com.opentrust.spi.logger.SPILogger;


public class TimeStampProcessorFactory {
	private final static SPILogger logger = SPILogger.getLogger("TSP");

	private static final TimeStampProcessorFactory _self = new TimeStampProcessorFactory();

	public static TimeStampProcessorFactory getInstance() {
		return _self;
	}

	
}
