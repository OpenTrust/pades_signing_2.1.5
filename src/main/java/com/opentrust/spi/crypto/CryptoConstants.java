package com.opentrust.spi.crypto;

public class CryptoConstants {
	
	public static enum AlgorithmType {
		DIGEST,
		SIGNATURE,
		CIPHER,
		KEY,
		;
	}
	
	public static enum AlgorithmID {
		DIGEST_MD5(AlgorithmType.DIGEST,"MD5","http://www.w3.org/2001/04/xmldsig-more#md5","1.2.840.113549.2.5"),
		DIGEST_RIPEMD160(AlgorithmType.DIGEST,"RIPEMD160","http://www.w3.org/2001/04/xmlenc#ripemd160","1.3.36.3.2.1"),
		DIGEST_SHA1(AlgorithmType.DIGEST,"SHA1","http://www.w3.org/2000/09/xmldsig#sha1","1.3.14.3.2.26", "SHA-1"),
		DIGEST_SHA256(AlgorithmType.DIGEST,"SHA-256","http://www.w3.org/2001/04/xmlenc#sha256","2.16.840.1.101.3.4.2.1"),
		DIGEST_SHA384(AlgorithmType.DIGEST,"SHA-384","http://www.w3.org/2001/04/xmldsig-more#sha384","2.16.840.1.101.3.4.2.2"),
		DIGEST_SHA512(AlgorithmType.DIGEST,"SHA-512","http://www.w3.org/2001/04/xmlenc#sha512","2.16.840.1.101.3.4.2.3"),
		SIGNATURE_DSA_SHA1(AlgorithmType.SIGNATURE,"SHA1WithDSA","http://www.w3.org/2000/09/xmldsig#dsa-sha1","1.2.840.10040.4.3"),
		SIGNATURE_RSA_MD5(AlgorithmType.SIGNATURE,"MD5WithRSA","http://www.w3.org/2001/04/xmldsig-more#rsa-md5","1.2.840.113549.1.1.4"),
		SIGNATURE_RSA_RIPEMD160(AlgorithmType.SIGNATURE,"RIPEMD160WithRSA","http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160","1.3.36.3.3.1.2"),
		SIGNATURE_RSA_SHA1(AlgorithmType.SIGNATURE,"SHA1WithRSA","http://www.w3.org/2000/09/xmldsig#rsa-sha1","1.2.840.113549.1.1.5"),
		SIGNATURE_RSA_SHA256(AlgorithmType.SIGNATURE,"SHA256WithRSA","http://www.w3.org/2001/04/xmldsig-more#rsa-sha256","1.2.840.113549.1.1.11"),
		SIGNATURE_RSA_SHA384(AlgorithmType.SIGNATURE,"SHA384WithRSA","http://www.w3.org/2001/04/xmldsig-more#rsa-sha384","1.2.840.113549.1.1.12"),
		SIGNATURE_RSA_SHA512(AlgorithmType.SIGNATURE,"SHA512WithRSA","http://www.w3.org/2001/04/xmldsig-more#rsa-sha512","1.2.840.113549.1.1.13"),
		//TODO confirm URL and OID values
		KEY_RSA(AlgorithmType.KEY,"RSA","http://www.w3.org/2001/04/xmlenc#rsa-1_5","1.2.840.113549.1.1.1"),
	 	 
		;
		private final String tag;
		private final String uri;
		private final String oid;
		private final AlgorithmType type;
		private final String [] otherNames;

		private AlgorithmID(AlgorithmType type, String tag, String uri, String oid, String... othernames) {
			this.tag = tag;
			this.uri = uri;
			this.oid = oid;
			this.type = type;
			this.otherNames = othernames;
		}
		
		
		protected boolean matchName(String name)
		{
			if (name.equalsIgnoreCase(tag))
				return true;
			
			for (String otherName : otherNames)
			{
				if (otherName.equalsIgnoreCase(name))
					return true;
			}
			return false;			
		}
		
		public final AlgorithmType getType() {
			return this.type;
		}

		public final String getTag() {
			return this.tag;
		}

		public static final AlgorithmID valueOfTag(String s) {
			for (AlgorithmID t : AlgorithmID.values()) {
				if (t.matchName(s))
					return t;
			}
			return null;
		}

		public final String getURI() {
			return this.uri;
		}

		public static final AlgorithmID valueOfURI(String s) {
			AlgorithmID result = null;
			for (AlgorithmID t : AlgorithmID.values()) {
				if (t.uri.equals(s)) {
					result = t;
					break;
				}
			}
			return result;
		}

		public final String getOID() {
			return this.oid;
		}

		public static final AlgorithmID valueOfOID(String s) {
			AlgorithmID result = null;
			for (AlgorithmID t : AlgorithmID.values()) {
				if (t.oid.equals(s)) {
					result = t;
					break;
				}
			}
			return result;
		}

		public static final AlgorithmID valueOfTagOrOID(String s) {
			AlgorithmID result = valueOfTag(s);
			if (result == null)
				result = valueOfOID(s);
			return result;
		}
	}
}
