package com.opentrust.spi.helpers;

import java.security.AccessController;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import sun.security.action.GetPropertyAction;

public class DateHelper {
	
	public final static SimpleTimeZone GMT_TIMEZONE = new SimpleTimeZone(0, "GMT");
	public final static TimeZone LOCAL_TIMEZONE = getSystemTimeZone();
	
	public static enum DateFormatType {
		ISO8601("ISO8601","yyyy-MM-ddTHH:mm:ssZ", "yyyy-MM-dd'T'HH:mm:ss'Z'", GMT_TIMEZONE),
		ISO8601_LONG("ISO8601_LONG","yyyy-MM-ddTHH:mm:ss.SSSZ", "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", GMT_TIMEZONE),
		ISO8601_TZ("ISO8601_TZ","yyyy-MM-ddTHH:mm:ss+hh:mm", "yyyy-MM-dd'T'HH:mm:ssz", LOCAL_TIMEZONE),
		ISO8601_TZ_LONG("ISO8601_TZ_LONG","yyyy-MM-ddTHH:mm:ss.SSS+hh:mm", "yyyy-MM-dd'T'HH:mm:ss.SSSz", LOCAL_TIMEZONE),
		SIMPLE("SIMPLE","yyyy/MM/dd HH:mm", "yyyy/MM/dd HH:mm", LOCAL_TIMEZONE),
		SIMPLE_LONG("SIMPLE","yyyy/MM/dd HH:mm:ss", "yyyy/MM/dd HH:mm:ss", LOCAL_TIMEZONE),
		DOTISO8601("DOTISO8601","yyyy.MM.ddTHH:mm:ssZ", "yyyy.MM.dd'T'HH:mm:ss'Z'", GMT_TIMEZONE),
		CONCAT("CONCAT","yyyyMMddHHmmss", "yyyyMMddHHmmss", GMT_TIMEZONE),
		HALFDAYFORMAT("HALFDAYFORMAT","yyyy/MM/dd a","yyyy/MM/dd a", LOCAL_TIMEZONE)
		;
		private final String tag;
		private final String help;
		private final String formatString;
		private TimeZone timeZone;
		private DateFormatType(String tag, String help, String format, TimeZone timezone) {
			this.tag = tag ; this.help = help; this.formatString = format;
			if (timezone != null)
				this.timeZone = timezone;
			
		}
		public final String getTag (){return this.tag;}
		public final String getHelp (){return this.help;}
		public final String getFormatString (){return this.formatString;}
		public final DateFormat getFormat (){
			DateFormat format = new SimpleDateFormat(this.formatString);
			format.setTimeZone(this.timeZone);
			return format;
		}
		
		public  Date parse(String value) throws ParseException {
			DateFormat format = new SimpleDateFormat (this.formatString);
			format.setTimeZone(this.timeZone);
			return format.parse(value);
		}
		
		public static final DateFormatType valueOfTag(String s){
			DateFormatType result = null;
			for (DateFormatType t : DateFormatType.values()){
				if (t.tag.equals(s)) { result = t; break; }
			}
			return result;
		}
	}
	
//	@Deprecated
//	public final static String ISO8601_DATETIME_FORMAT_TEMPLATE = "yyyy-MM-ddTHH:mm:ssZ";
//	@Deprecated
//	private final static DateFormat ISO8601_DATETIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
//	
//	@Deprecated
//	public final static String SIMPLE_DATETIME_FORMAT_TEMPLATE = "yyyy-MM-dd HH:mm";
//	@Deprecated
//	private final static DateFormat SIMPLE_DATETIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm");
//	
//	static {
//		ISO8601_DATETIME_FORMAT.setTimeZone(GMT_TIMEZONE);
//	}
	
	/**
	 * Tries to retrieve system original timezone even if the default timezone ( TimeZone.getDefault() ) 
	 * has been altered
	 * @return System timezone
	 */
	private static TimeZone getSystemTimeZone() {
		TimeZone tz = TimeZone.getDefault();
		if (tz.getID().equals("GMT")) {
			// Default time zone has been set to GMT, maybe it is not the real local time zone
			// get the time zone ID from the system properties
			String zoneID = (String) AccessController.doPrivileged(
					new GetPropertyAction("user.timezone"));
			
			// Get the time zone for zoneID
			if (zoneID != null && zoneID.length()>0) {
				tz = TimeZone.getTimeZone(zoneID);
			}
		}

		assert tz != null;
		return tz;
	}
	
	public static String toDateString(DateFormatType format, Date date) {
		return format.getFormat().format(date);
	}
	
	public static Date parseDateString(DateFormatType format, String value) throws ParseException {
		Date result = null;
		try {
			result = format.parse(value);
		}
		catch (ParseException e) {
			// re throw a new ParseException with extended message rather than SPIException to simplified returned stack trace
			StringBuffer buf = new StringBuffer(80);
			buf.append(e.toString()).append(", not ").append(format.getTag()).append(" format ");
			buf.append(format.getHelp());
			throw new ParseException(buf.toString(), e.getErrorOffset());
		}
		catch (Exception e) {
			StringBuffer buf = new StringBuffer(96);
			buf.append("Failed parsing ").append(value).append(", ");
			buf.append(e.toString()).append(", not ").append(format.getTag()).append(" format ");
			buf.append(format.getHelp());
			throw new ParseException(buf.toString(), 0);
		}
		return result;
	}
	
	public static String toISO8601String(Date date) {
		return DateFormatType.ISO8601.getFormat().format(date);
	}
	
	public static Date parseISO8601String(String value) throws ParseException {
		Date result = null;
		try {
			result = DateFormatType.ISO8601.parse(value);
		}
		catch (ParseException e) {
			// re throw a new ParseException with extended message rather than SPIException to simplified returned stack trace
			StringBuffer buf = new StringBuffer(80);
			buf.append(e.toString()).append(", not ISO8601 format ").append(DateFormatType.ISO8601.getHelp());
			throw new ParseException(buf.toString(), e.getErrorOffset());
		}
		catch (Exception e) {
			StringBuffer buf = new StringBuffer(96);
			buf.append("Failed parsing '").append(value).append("', ");
			buf.append(e.toString()).append(", not ISO8601 format ").append(DateFormatType.ISO8601.getHelp());
			throw new ParseException(buf.toString(), 0);
		}
		return result;
	}
	
	/**
	 * Parse multiple forms of ISO8601 extended (ie with separator) date string 
	 * (with or without timezone suffix, milliseconds).
	 *  
	 * Supported formats are :
	 *  - UTC short : yyyy-MM-ddTHH:mm:ssZ
	 *  - UTC long : yyyy-MM-ddTHH:mm:ss.SSSZ
	 *  - TZ short : yyyy-MM-ddTHH:mm:ss+hh:mm
	 *  - TZ long : yyyy-MM-ddTHH:mm:ss.SSS+hh:mm
	 *  
	 * @param value date string in ISO to parse
	 * @return Date object
	 * @throws ParseException
	 */
	public static Date parseISO8601StringEx(String value) throws ParseException {
		Date result = null;
		//Separates common base part from suffix part
		final Pattern isoPartsPattern = Pattern.compile("^(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.+)");
		Matcher isoParts = isoPartsPattern.matcher(value);
		if (!isoParts.matches()) {
			StringBuffer buf = new StringBuffer(80);
			buf.append("Not ISO8601 format date, '");
			buf.append(value);
			buf.append("' not of the form 'yyyy-MM-ddTHH:mm:ss(.+)'");
			throw new ParseException(buf.toString(), 0);
		}
		String base = isoParts.group(1);
		String suffix = isoParts.group(2);
		
		//Determine the right date parser format type
		final Pattern utcPattern = Pattern.compile("Z");
		final Pattern utcLongPattern = Pattern.compile("\\.\\d{1,3}Z");
		final Pattern tzPattern = Pattern.compile("[+-]\\d{2}:\\d{2}");
		final Pattern tzLongPattern = Pattern.compile("\\.\\d{1,3}[+-]\\d{2}:\\d{2}");
		
		DateFormatType format;
		String formattedValue = value;
		if (utcPattern.matcher(suffix).matches()) {
			format = DateFormatType.ISO8601;
		}
		else if (utcLongPattern.matcher(suffix).matches()) {
			format = DateFormatType.ISO8601_LONG;
		}
		else if (tzPattern.matcher(suffix).matches()) {
			format = DateFormatType.ISO8601_TZ;
			//Hack: Java SimpleDateFormat parser cannot parse time zone of the form +01:00 without
			//GMT string prefix
			formattedValue = base + suffix.replaceFirst("([\\+\\-])", "GMT$1");
		}
		else if (tzLongPattern.matcher(suffix).matches()) {
			format = DateFormatType.ISO8601_TZ_LONG;
			formattedValue = base + suffix.replaceFirst("([\\+\\-])", "GMT$1");
		}
		else {
			StringBuffer buf = new StringBuffer(80);
			buf.append("Not ISO8601 format date, '");
			buf.append(value);
			buf.append("' suffix not of supported form (ex: 'Z', '.123Z', '+02:00', '.123+02:00')");
			throw new ParseException(buf.toString(), 19);
		}
		
		try {
			result = format.parse(formattedValue);
		}
		catch (ParseException e) {
			// re throw a new ParseException with extended message rather than SPIException to simplified returned stack trace
			StringBuffer buf = new StringBuffer(80);
			buf.append(e.getMessage()).append(", not ISO8601 format ").append(format.getHelp());
			throw new ParseException(buf.toString(), e.getErrorOffset());
		}
		catch (Exception e) {
			StringBuffer buf = new StringBuffer(96);
			buf.append("Failed parsing '").append(value).append("', ");
			buf.append(e.getMessage()).append(", not ISO8601 format ").append(format.getHelp());
			throw new ParseException(buf.toString(), 0);
		}
		return result;
	}
	
	public static String toSimpleString(Date date) {
		return DateFormatType.SIMPLE.getFormat().format(date);
	}
	
	public static Date parseSimpleString(String value) throws ParseException {
		Date result = null;
		try {
			result = DateFormatType.SIMPLE.parse(value);
		}
		catch (ParseException e) {
			// re throw a new ParseException with extended message rather than SPIException to simplified returned stack trace
			StringBuffer buf = new StringBuffer(80);
			buf.append(e.toString()).append(", not simple format ").append(DateFormatType.SIMPLE.getHelp());
			throw new ParseException(buf.toString(), e.getErrorOffset());
		}
		catch (Exception e) {
			StringBuffer buf = new StringBuffer(96);
			buf.append("Failed parsing '").append(value).append("', ");
			buf.append(e.toString()).append(", not simple format ").append(DateFormatType.SIMPLE.getHelp());
			throw new ParseException(buf.toString(), 0);
		}
		return result;
	}
	
	public static String toSimpleLongString(Date date) {
		return DateFormatType.SIMPLE_LONG.getFormat().format(date);
	}
	
	public static Date parseSimpleLongString(String value) throws ParseException {
		Date result = null;
		try {
			result = DateFormatType.SIMPLE_LONG.parse(value);
		}
		catch (ParseException e) {
			// re throw a new ParseException with extended message rather than SPIException to simplified returned stack trace
			StringBuffer buf = new StringBuffer(80);
			buf.append(e.toString()).append(", not simple long format ").append(DateFormatType.SIMPLE_LONG.getHelp());
			throw new ParseException(buf.toString(), e.getErrorOffset());
		}
		catch (Exception e) {
			StringBuffer buf = new StringBuffer(96);
			buf.append("Failed parsing '").append(value).append("', ");
			buf.append(e.toString()).append(", not simple long format ").append(DateFormatType.SIMPLE_LONG.getHelp());
			throw new ParseException(buf.toString(), 0);
		}
		return result;
	}
	
	public static Date toDate(Timestamp timestamp) {
		long milliseconds = timestamp.getTime() + timestamp.getNanos()/1000000;
		return new Date(milliseconds);
	}
	
}
