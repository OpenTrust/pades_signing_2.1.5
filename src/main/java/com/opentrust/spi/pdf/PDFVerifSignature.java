package com.opentrust.spi.pdf;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PRStream;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfIndirectReference;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfStream;
import com.lowagie.text.pdf.RandomAccessFileOrArray;
import com.opentrust.spi.helpers.exceptions.ExceptionHandler;
import com.opentrust.spi.helpers.exceptions.SPIException;
import com.opentrust.spi.helpers.logging.SPILogger;
import com.opentrust.spi.logging.Channel;
import com.opentrust.spi.pdf.PDFSign.CRLWithRevisionFactory;
import com.opentrust.spi.pdf.PDFSign.CertificateWithRevisionFactory;
import com.opentrust.spi.pdf.PDFSign.OCSPResponseWithRevisionFactory;
import com.opentrust.spi.pdf.PDFSign.ObjectWithRevision;
import com.opentrust.spi.pdf.PDFSign.ObjectWithRevisionAbstractFactory;
import com.opentrust.spi.pdf.PDFSign.VRIValidationData;
import com.opentrust.spi.pdf.PDFSign.ValidationData;

public class PDFVerifSignature {

	private static SPILogger log = SPILogger.getLogger("PDFSIGN");

	public static PDFEnvelopedSignature verify(InputStream pdf_file, String signatureName) throws SPIException {
		PDFEnvelopedSignature verifResult = null;
		try {
			PdfReader reader = new PdfReader(pdf_file, null);
			AcroFields af = reader.getAcroFields();
			verifResult = af.verifySignature(signatureName);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return verifResult;
	}

	public static PDFEnvelopedSignature verify(File file, String signatureName) throws SPIException {
		PDFEnvelopedSignature verifResult = null;
		try {
			PdfReader reader = new PdfReader(new FileInputStream(file));
			verifResult = verify(reader, signatureName);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return verifResult;
	}

	// use for large files
	public static PDFEnvelopedSignature verify(String fileName, String signatureName) throws SPIException {
		PDFEnvelopedSignature verifResult = null;
		try {
			PdfReader reader = new PdfReader(new RandomAccessFileOrArray(fileName), null);
			verifResult = verify(reader, signatureName);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return verifResult;
	}

	public static List<PDFEnvelopedSignature> verify(InputStream pdf_file) throws SPIException {
		return verify(pdf_file, false);
	}
	public static List<PDFEnvelopedSignature> verify(InputStream pdf_file, boolean withDocTS) throws SPIException {
		List<PDFEnvelopedSignature> verifResult = null;
		try {
			PdfReader reader = new PdfReader(pdf_file, null);
			verifResult = verify(reader, withDocTS);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return verifResult;
	}

	public static List<PDFEnvelopedSignature> verify(File file) throws SPIException {
		return verify(file, false);
	}
	public static List<PDFEnvelopedSignature> verify(File file, boolean withDocTS) throws SPIException {
		List<PDFEnvelopedSignature> verifResult = null;
		try {
			PdfReader reader = new PdfReader(new FileInputStream(file));
			verifResult = verify(reader, withDocTS);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return verifResult;
	}

	// use for large files
	public static List<PDFEnvelopedSignature> verify(String fileName) throws SPIException {
		return verify(fileName, false);
	}
	public static List<PDFEnvelopedSignature> verify(String fileName, boolean withDocTS) throws SPIException {
		List<PDFEnvelopedSignature> verifResult = null;
		try {
			PdfReader reader = new PdfReader(new RandomAccessFileOrArray(fileName), null);
			verifResult = verify(reader, withDocTS);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return verifResult;
	}

	protected static List<PDFEnvelopedSignature> verify(PdfReader reader) throws SPIException {
		return verify(reader, false);
	}
	protected static List<PDFEnvelopedSignature> verify(PdfReader reader, boolean withDocTS) throws SPIException {
		List<PDFEnvelopedSignature> verifResult = new ArrayList<PDFEnvelopedSignature>();
		try {
			AcroFields af = reader.getAcroFields();
			ArrayList names = af.getSignatureNames(withDocTS);
			log.debug(Channel.TECH,  "%1$s signatures were found", names.size());
			for (int k = 0; k < names.size(); ++k) {
				String name = (String) names.get(k);
				//FIXME : also perform document-wide verifications, for instance those involving reader.getCertificationLevel
				verifResult.add(af.verifySignature(name));
			}
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return verifResult;
	}

	protected static PDFEnvelopedSignature verify(PdfReader reader, String name) throws SPIException {
		PDFEnvelopedSignature verifResult = null;
		try {
			AcroFields af = reader.getAcroFields();
			verifResult = af.verifySignature(name);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return verifResult;
	}
	
	public static ValidationData verifyDSS(InputStream pdf_file) throws SPIException {
		ValidationData verifResult = null;
		try {
			PdfReader reader = new PdfReader(pdf_file, null);
			verifResult = verifyDSS(reader);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return verifResult;
	}

	public static ValidationData verifyDSS(File file) throws SPIException {
		ValidationData verifResult = null;
		try {
			PdfReader reader = new PdfReader(new FileInputStream(file));
			verifResult = verifyDSS(reader);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return verifResult;
	}

	// use for large files
	public static ValidationData verifyDSS(String fileName) throws SPIException {
		ValidationData verifResult = null;
		try {
			PdfReader reader = new PdfReader(new RandomAccessFileOrArray(fileName), null);
			verifResult = verifyDSS(reader);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return verifResult;
	}
	
	protected static ValidationData verifyDSS(PdfReader reader) throws SPIException {
		ValidationData validationData = new ValidationData();
		try {
	        PdfDictionary catalog = reader.getCatalog();
	        PdfDictionary dssDico = catalog.getAsDict(PDFSign.DSS);
	        if(dssDico!=null) {
		        PdfArray ocsps = dssDico.getAsArray(PDFSign.OCSPS);
		        PdfArray crls = dssDico.getAsArray(PDFSign.CRLS);
		        PdfArray certs = dssDico.getAsArray(PDFSign.CERTS);
		        PdfDictionary vri = dssDico.getAsDict(PDFSign.VRI);
		        
		        log.debug(Channel.TECH, "Looking for certs, crls and ocsp responses in DSS dictionary");
		        validationData.setCertificates(getObjectsFromDSS(reader, certs, new CertificateWithRevisionFactory()));
		        validationData.setCRLs(getObjectsFromDSS(reader, crls, new CRLWithRevisionFactory()));
		        validationData.setOCSPs(getObjectsFromDSS(reader, ocsps, new OCSPResponseWithRevisionFactory()));
		        
		        if (vri != null) {
		            for (Object sigName : vri.getKeys()) {
	                    PdfDictionary sigVri = vri.getAsDict((PdfName)sigName);
	                    if (sigVri != null) {
	                    	VRIValidationData vriData = new VRIValidationData(((PdfName)sigName));
	            	        PdfArray vriCerts = sigVri.getAsArray(PdfName.CERT);
	            	        PdfArray vriCrls = sigVri.getAsArray(PDFSign.CRL);
	            	        PdfArray vriOcsps = sigVri.getAsArray(PDFSign.OCSP);
	
	            	        log.debug(Channel.TECH, "Looking for certs, crls and ocsp responses in VRI dictionary for key '%1$s'", sigName);
	            	        vriData.setCertificates(getObjectsFromDSS(reader, vriCerts, new CertificateWithRevisionFactory()));
	            	        vriData.setCRLs(getObjectsFromDSS(reader, vriCrls, new CRLWithRevisionFactory()));
	            	        vriData.setOCSPs(getObjectsFromDSS(reader, vriOcsps, new OCSPResponseWithRevisionFactory()));
	
	            	        validationData.addVRI(vriData);
	                    }
		            }
		        }
	        }
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return validationData;
	}
	
	private static <ConcreteObjectWithRevision extends ObjectWithRevision> List<ConcreteObjectWithRevision> getObjectsFromDSS(PdfReader reader, PdfArray objects, ObjectWithRevisionAbstractFactory<ConcreteObjectWithRevision> factory) {
		List<ConcreteObjectWithRevision> list = new ArrayList<ConcreteObjectWithRevision>();
        if(objects!=null) {
        	int readerReverseRevisionNbr = reader.getReverseRevisionNbr();
	        for(int i=0;i<objects.size();i++) {
	        	PdfIndirectReference pdfIR = objects.getAsIndirectObject(i);
	        	if(pdfIR!=null) {
		        	PdfObject object = reader.getPdfObject(pdfIR.getNumber());
		        	if(object!=null && object.isStream()) {
			        	PdfStream stream = (PdfStream) object;
			        	if(stream instanceof PRStream) {
			        		try {
					        	byte[] objectBytes = PdfReader.getStreamBytes((PRStream)stream);
					        	if(objectBytes!=null)
				        			list.add(factory.createObjectWithRevision(objectBytes, readerReverseRevisionNbr-object.getReverseRevision()));
					        	else log.debug(Channel.TECH, "objectBytes null");
			        		} catch(Exception e) {
			        			ExceptionHandler.handleNoThrow(e, "Found invalid bytes in DSS or VRI dictionary. Skipping it");
			        		}
			        	} else log.debug(Channel.TECH, "stream not a PRStream");
		        	} else log.debug(Channel.TECH, "object null or not a stream : %1$s", object);
	        	} else log.debug(Channel.TECH, "pdfIR null");
	        }
        }
        return list;
	}

}