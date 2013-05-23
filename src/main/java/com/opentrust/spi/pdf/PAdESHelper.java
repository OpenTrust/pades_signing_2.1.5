package com.opentrust.spi.pdf;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import com.opentrust.spi.helpers.logging.SPILogger;
import com.opentrust.spi.logging.Channel;

public class PAdESHelper {
	private static SPILogger log = SPILogger.getLogger("PDFSIGN");

	/**
	 * Checks whether this PDF signature conforms to ISO 32000-1
	 * return a list of error messages, or empty list when no error
	 */
	public static List<String> isISO32000_1Conformant(PDFEnvelopedSignature pdfSignature, boolean fastFail, boolean excludePAdESV3Overrides) {
		List<String> conformanceReport = new ArrayList<String>();
		//FIXME : implement. For now, mainly covered in the building process of PDFEnvelopedSignature object, 
		// which would fail with bouncycastle.CMSException if signature was not ISO 32000-1 compliant

		
		//ISO32000_1, 12.8.1, Signature dictionary 'Cert' entry:
		// If SubFilter is adbe.pkcs7.detached or adbe.pkcs7.sha1, this entry shall not be used, and the certificate chain shall be put in the PKCS#7 envelope in Contents.
		String subFilter = pdfSignature.getSubFilter();
		if((PDFEnvelopedSignature.SF_ADBE_PKCS7_DETACHED.equals(subFilter) || PDFEnvelopedSignature.SF_ADBE_PKCS7_SHA1.equals(subFilter))
				&& pdfSignature.getDictionaryCert()!=null) {
			addErrorToReport(conformanceReport, "Signature dictionay 'Cert' entry should not be used with subFilter '%1$s'", subFilter);
			if(fastFail) return conformanceReport;
		}
		
		return conformanceReport;
	}

	/**
	 * Checks whether this PDF signature conforms to PAdES 'v2' (or 'basic' or 'cms')
	 * Refers to ETSI TS 102 778-2
	 */
	public static List<String> isPAdESBasicConformant(PDFEnvelopedSignature pdfSignature, boolean fastFail) {
		// 5.1.a - PAdES basic comes on top of ISO 32000
		List<String> conformanceReport = isISO32000_1Conformant(pdfSignature, fastFail, false);
		if(fastFail && !conformanceReport.isEmpty()) return conformanceReport;
		
		// 5.1.b - ByteRange shall be the entire file, excluding the PDF signature
		// (other 5.1.b requirements are covered by parsing performed in iText AcroFields class)
		if(pdfSignature.getByteRange()[0]!=0 || pdfSignature.getRevisionLength()!=(pdfSignature.getByteRange()[2]+pdfSignature.getByteRange()[3])) {
			addErrorToReport(conformanceReport, "Signature does not cover the whole document");
			if(fastFail) return conformanceReport;
		}

		// 5.1.c - PDF signature is PKCS#7
		// (other 5.1.c requirements are covered by parsing performed in iText AcroFields class)
		if(pdfSignature.getSubFilter()==null || PDFEnvelopedSignature.SF_ADBE_X509_RSA_SHA1.equals(pdfSignature.getSubFilter())) {
			addErrorToReport(conformanceReport, "Signature not a PKCS#7 (subFilter '%1$s')", pdfSignature.getSubFilter());
			if(fastFail) return conformanceReport;
		}		

		// (5.1.d - PKCS#7 conforms to RFC 2315 : covered by spi-cms module)
		// 5.1.d - PKCS#7 shall include signing certificate
		if(pdfSignature.getSigningCertificate()==null) {
			addErrorToReport(conformanceReport, "PKCS#7 does not contain signer Certificate");
			if(fastFail) return conformanceReport;
		}
		
		// 5.1.e - Timestamping and revocation information should be included in the PDF signature
		//TODO : log warning if no TS & revocation info are found (revocation info for the chain)
		
		// 5.1.f - Any revocation information shall be a signed attribute
		//FIXME : see if we should consider the signature invalid, or only log a warning, when revocation info is found as unsigned property ?
		
		// 5.1.g - Use of RFC 3281 attribute certificates is not recommended
		//TODO : log warning if such attribute certificates are found
		
		// 5.1.h - The shall only be one SignerInfo : already covered in PDFEnvelopedSignature constructor)		
		
		// 5.2.a - ?

		// 5.2.b - Only two values supported for SubFilter
		if(!PDFEnvelopedSignature.SF_ADBE_PKCS7_DETACHED.equals(pdfSignature.getSubFilter()) && !!PDFEnvelopedSignature.SF_ADBE_PKCS7_SHA1.equals(pdfSignature.getSubFilter())) {
			addErrorToReport(conformanceReport, "Signature subFilter '%1$s' not supported", pdfSignature.getSubFilter());
			if(fastFail) return conformanceReport;
		}
		
		
		// 5.3.a - Verify that the document digest matches that in the signature : dealt with outside this module (spi-dssl for instance, by calling pdfSignature.verify())
		
		// 5.3.b - Validate the path of certificates... : dealt with outside this module (spi-dssl for instance)
		
		// 5.4 & 5.5 & 5.6 : dealt with outside this module (not yet for 5.6)
		
		
		return conformanceReport;
	}
	
	/**
	 * Checks whether this PDF signature conforms to PAdES 'v3' BES
	 * Refers to ETSI TS 102 778-3
	 */
	public static List<String> isPAdESBESConformant(PDFEnvelopedSignature pdfSignature, boolean fastFail) {
		return isPAdESBESConformant(pdfSignature, fastFail, false);
	}
	
	/**
	 * Checks whether this PDF signature conforms to PAdES 'v3' BES
	 * Refers to ETSI TS 102 778-3
	 */
	private static List<String> isPAdESBESConformant(PDFEnvelopedSignature pdfSignature, boolean fastFail, boolean isForEPES) {
		// 4.2.a - ISO 32000-1 except where overridden by PAdES v3
		List<String> conformanceReport = isISO32000_1Conformant(pdfSignature, fastFail, true);
		
		// 4.2.b - DER-encoded CMS SignedData object in the key Content of the signature dictionary : covered by parsing performed in iText AcroFields class + 4.2.e
		
		// 4.2.c - ByteRange shall be the entire file, excluding the PDF signature
		if(pdfSignature.getByteRange()[0]!=0 || pdfSignature.getRevisionLength()!=(pdfSignature.getByteRange()[2]+pdfSignature.getByteRange()[3])) {
			addErrorToReport(conformanceReport, "Signature does not cover the whole document");
			if(fastFail) return conformanceReport;
		}

		// 4.2.d - ISO 32000-1, 12.8.3.2 & 12.8.3.3 do not apply

		// 4.2.e - SubFilter shall be ETSI.CAdES.detached
		if(!PDFEnvelopedSignature.SF_ETSI_CADES_DETACHED.equals(pdfSignature.getSubFilter())) {
			addErrorToReport(conformanceReport, "Signature subFilter '%1$s' not supported", pdfSignature.getSubFilter());
			if(fastFail) return conformanceReport;
		}
		
		// 4.2.f - ?
		
		// 4.2.g - signature dictionary shall not contain Cert entry
		if(pdfSignature.getDictionaryCert()!=null) {
			addErrorToReport(conformanceReport, "Signature shall not contain Cert entry");
			if(fastFail) return conformanceReport;
		}
		
		// 4.2.h - Unsigned signature attributes may be ignored : OK...
		
		// 4.2.i - A timestamp should be applied immediately after the signature is created : OK...
		
		// 4.3 - only a single SignerInfo : already covered in PDFEnvelopedSignature constructor
		
		// 4.4.1 - content-type attribute mandatory with value "id-data"
		// content-type attribute presence and equality to eContentInfo.contentype already a requirement of CMS RFC : covered by CMSSignature class
		if(!PKCSObjectIdentifiers.data.equals(pdfSignature.getContentTypeAttribute())) {
			addErrorToReport(conformanceReport, "content-type attribute should be '%1$s' but is '%2$s'", PKCSObjectIdentifiers.data, pdfSignature.getCmsContentType());
			if(fastFail) return conformanceReport;
		}

		// 4.4.2 - message-digest attribute shall be used
		if(pdfSignature.getDigest()==null) {
			addErrorToReport(conformanceReport, "message-digest attribute is missing");
			if(fastFail) return conformanceReport;
		}
		
		// 4.4.3 - signing-certificate (when SHA-1 is used) or signing-certificate-v2 (when any other than SHA-1 is used) shall be used
		if(pdfSignature.getSigningCertificateAttribute()==null && pdfSignature.getSigningCertificateV2Attribute()==null) {
			addErrorToReport(conformanceReport, "both signing-certificate and signing-certificate-v2 attributes are missing");
			if(fastFail) return conformanceReport;
		} else if(pdfSignature.getSigningCertificateAttribute()!=null && !"SHA1".equals(pdfSignature.getDataDigestAlgorithm())){
			addErrorToReport(conformanceReport, "signing-certificate should not be used with "+pdfSignature.getDataDigestAlgorithm());
			if(fastFail) return conformanceReport;
		} else if(pdfSignature.getSigningCertificateV2Attribute()!=null && "SHA1".equals(pdfSignature.getDataDigestAlgorithm())){
			addErrorToReport(conformanceReport, "signing-certificate-v2 should not be used with SHA1");
			if(fastFail) return conformanceReport;
		}
		
		// 4.5.1 - (see EPES validation)
		
		// 4.5.2 - signature-time-stamp should be present
		//TODO : log warning if no TS ?
		
		// 4.5.3 - signing-time attribute shall not be used
		if(pdfSignature.getCmsSignDate()!=null) {
			addErrorToReport(conformanceReport, "signing-time CMS attribute shall not be used");
			if(fastFail) return conformanceReport;
		}

		// 4.5.4 - counter-signature attribute shall not be used
		if(pdfSignature.getCounterSignatures()!=null && pdfSignature.getCounterSignatures().size()!=0) {
			addErrorToReport(conformanceReport, "counter-signature CMS attribute shall not be used");
			if(fastFail) return conformanceReport;
		}

		// 4.5.5 - content-reference attribute shall not be used
		if(pdfSignature.getContentReferenceAttribute()!=null) {
			addErrorToReport(conformanceReport, "content-reference CMS attribute shall not be used");
			if(fastFail) return conformanceReport;
		}

		// 4.5.6 - content-identifier attribute shall not be used
		if(pdfSignature.getContentIdentifierAttribute()!=null) {
			addErrorToReport(conformanceReport, "content-identifier CMS attribute shall not be used");
			if(fastFail) return conformanceReport;
		}
		
		// 4.5.7 - content-hints attribute shall not be used
		if(pdfSignature.getContentHintsAttribute()!=null) {
			addErrorToReport(conformanceReport, "content-hints CMS attribute shall not be used");
			if(fastFail) return conformanceReport;
		}
		
		// 4.5.8 - commitment-type-indication may be present for EPES. Shall not be present for BES
		if(!isForEPES && pdfSignature.getCommitmentTypeIndicationAttribute()!=null) {
			addErrorToReport(conformanceReport, "commitment-type-indication CMS attribute shall not be used");
			if(fastFail) return conformanceReport;
		}

		// 4.5.9 - signer-location attribute shall not be present
		if(pdfSignature.getSignerLocationAttribute()!=null) {
			addErrorToReport(conformanceReport, "signer-location CMS attribute shall not be used");
			if(fastFail) return conformanceReport;
		}

		//4.7 - extensions dictionary
		//FIXME : check extensions dictionary contains ESIC/1.7/3
		
		return conformanceReport;
	}
	
	/**
	 * Checks whether this PDF signature conforms to PAdES 'v3' EPES
	 * Refers to ETSI TS 102 778-3
	 */
	public static List<String> isPAdESEPESConformant(PDFEnvelopedSignature pdfSignature, boolean fastFail) {
		List<String> conformanceReport = isPAdESBESConformant(pdfSignature, fastFail, true);

		// 4.5.1 - signature-policy-identifier attribute shall be present
		if(pdfSignature.getSignaturePolicyIdentifierAttribute()==null) {
			addErrorToReport(conformanceReport, "signature-policy-identifier attribute is missing");
			if(fastFail) return conformanceReport;
		}
		
		return conformanceReport;
	}

	private static void addErrorToReport(List<String> conformanceReport, String error, Object... params) {
		String formattedString = String.format(error, params);
		log.debug(Channel.TECH, formattedString);
		conformanceReport.add(formattedString);
	}
}
