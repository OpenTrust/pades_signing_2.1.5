package com.opentrust.pdfsign;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.ocsp.OCSPResp;

import com.keynectis.sequoia.security.signeddocument.Document;
import com.keynectis.sequoia.security.signeddocument.DocumentSignResult;
import com.keynectis.sequoia.security.signeddocument.DocumentSigner;
import com.opentrust.spi.cms.helpers.OCSPResponse;
import com.opentrust.spi.pdf.PDFSign;
import com.opentrust.spi.pdf.PDFSign.SignReturn;
import com.opentrust.spi.pdf.PdfSignParameters;
import com.opentrust.spi.pdf.PdfSignParameters.PAdESParameters;
import com.opentrust.spi.pdf.PdfSignParameters.SignatureLayoutParameters;
import com.opentrust.spi.pdf.PdfSignParameters.TimestampingParameters;
import com.opentrust.spi.tsp.TimestampToken;

public class PdfSigner extends DocumentSigner {
	
	String mode = "ppkms";
	String certificationLevel = "CERTIFIED_NO_CHANGES_ALLOWED";
	String contact;
	String signatureName = "signature";
	boolean createNewRevision = true;
	boolean keepPDFACompliance = false;
	boolean allocateTSContainer = false;
	int tsSize = 0;
	int sigSize = 0;
	
	PAdESParameters padesParams;
    SignatureLayoutParameters signatureLayoutParameters;
    boolean signatureAlreadyExists;
    boolean isVisible;
	
    @Override
	public Document parseDocument(InputStream is) throws IOException {
		return new PdfDocument(is);
	}

	public String getMode() {
		return mode;
	}
	/**
	 * @param mode ppkms, ppklite or ppkvs, default : ppkms
	 */
	public void setMode(String mode) {
		this.mode = mode;
	}
	
	public String getCertificationLevel() {
		return certificationLevel;
	}

	/**
	 * @param certifLevel
	 *            can be NOT_CERTIFIED, CERTIFIED_NO_CHANGES_ALLOWED, CERTIFIED_FORM_FILLING or
	 *            CERTIFIED_FORM_FILLING_AND_ANNOTATIONS
	 *            default : CERTIFIED_NO_CHANGES_ALLOWED
	 */
	public void setCertificationLevel(String certificationLevel) {
		this.certificationLevel = certificationLevel;
	}

	public String getContact() {
		return contact;
	}

	public void setContact(String contact) {
		this.contact = contact;
	}

	public String getSignatureName() {
		return signatureName;
	}

	public void setSignatureName(String signatureName) {
		this.signatureName = signatureName;
	}

	public boolean isCreateNewRevision() {
		return createNewRevision;
	}

	/**
	 * 	 * @param createNewRevision
	 *            when false, this signature possibly invalidates signatures that already exist in the document when
	 *            true, the signature covers a newly made revision. All existing signatures remain valid, with only a
	 *            little warning saying that they cover another revision. default : true
	 */
	public void setCreateNewRevision(boolean createNewRevision) {
		this.createNewRevision = createNewRevision;
	}

	public boolean isKeepPDFACompliance() {
		return keepPDFACompliance;
	}

	public void setKeepPDFACompliance(boolean keepPDFACompliance) {
		this.keepPDFACompliance = keepPDFACompliance;
	}

	public boolean isAllocateTSContainer() {
		return allocateTSContainer;
	}

	public void setAllocateTSContainer(boolean allocateTSContainer) {
		this.allocateTSContainer = allocateTSContainer;
	}
	
	PdfSignParameters signatureParameters;
	public void setSignatureParameters(PdfSignParameters params)
	{
		signatureParameters = params;
	}
	
	public PdfSignParameters getSignatureParameters()
	{
		if (signatureParameters == null)
			signatureParameters = buildSignatureParameters();
		
		return signatureParameters;
	}
	
	public PdfSignParameters buildSignatureParameters()
	{
		PdfSignParameters parameters = PdfSignParameters.getParametersForSign(mode // mode
				, getReason() // reason
				, getLocation() // location
				, contact // contact
				, certificationLevel // certifLevel
				, signatureAlreadyExists // signatureAlreadyExists
				, signatureName // signatureName
				, createNewRevision // createNewRevision
				, keepPDFACompliance // keepPDFACompliance
				, allocateTSContainer // allocateTSContainer
				, tsSize // TSSize
				, sigSize // SigSize
				, getHashAlgorithm() // dataHashAlgo
				, getDate()); // signingTime
		
		if (tspClient != null)
			parameters.setTimeStampParams(new TimestampingParameters(tspClient, getHashAlgorithm()));
		
		if (ocspClient != null)
			parameters.ocspClient = ocspClient;
		
		if (padesParams != null)
			parameters.setPadesParameters(padesParams);

		if (signatureLayoutParameters != null)
			parameters.setSignatureLayoutParameters(signatureLayoutParameters);
		
		return parameters;
				
	}
	

	public int getTsSize() {
		return tsSize;
	}

	public void setTsSize(int tsSize) {
		this.tsSize = tsSize;
	}

	public int getSigSize() {
		return sigSize;
	}

	public void setSigSize(int sigSize) {
		this.sigSize = sigSize;
	}

	protected OCSPResponse [] getOcspResponses() throws IOException
	{
		OCSPResp[] ocspList2 = getRawOcspList();
		if (ocspList2 == null)
			return null;
		
		OCSPResponse [] ret = new OCSPResponse[ocspList2.length];
		
		int i=0;
		for (OCSPResp bOcsp : ocspList2)
			ret[i++] = new OCSPResponse(bOcsp.getEncoded());
		
		return ret;
	}
	
   public PAdESParameters getPadesParams() {
        return padesParams;
    }

    public void setPadesParams(PAdESParameters padesParams) {
        this.padesParams = padesParams;
    }
	
	public SignatureLayoutParameters getSignatureLayoutParameters() {
        return signatureLayoutParameters;
    }

    public void setSignatureLayoutParameters(SignatureLayoutParameters signatureLayoutParameters) {
        this.signatureLayoutParameters = signatureLayoutParameters;
    }

    public boolean isSignatureAlreadyExists() {
        return signatureAlreadyExists;
    }

    public void setSignatureAlreadyExists(boolean signatureAlreadyExists) {
        this.signatureAlreadyExists = signatureAlreadyExists;
    }

    @Override
	public DocumentSignResult sign(Document doc, OutputStream os) throws Exception {
		checkSupportedType(doc);
		
		PdfDocument pdf = (PdfDocument) doc;
		
		SignReturn newPDF = PDFSign.sign(null, pdf.reader, os, 
				null, (PrivateKey) getSigningKey(), getSigningChainArray(),
				getCrls(), getOcspResponses(), getSignatureParameters());
		
		if (newPDF == null)
		    return null;
		
		DocumentSignResult result = new DocumentSignResult();
		result.setSignatureId(newPDF.getSignatureName());
		result.setSigningCertificate(getSigningCertificate());
		TimestampToken timestampToken = newPDF.getTimestampToken();
		if (timestampToken != null) {
		    result.setSignatureTimestampDate(timestampToken.getDateTime());
		    Certificate timestampSigner = timestampToken.getSignerCertificate();
		    if (timestampSigner != null) {
		        result.setSignatureTimestampSignerCertificate((X509Certificate) timestampSigner);
		    }
		}
		
		return result;
	}
	
	@Override
	protected Class[] getSupportedDocumentTypeList() {
		return new Class [] {PdfDocument.class};
	}

}
