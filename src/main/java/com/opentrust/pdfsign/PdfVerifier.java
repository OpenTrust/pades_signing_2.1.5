package com.opentrust.pdfsign;

import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.keynectis.sequoia.ca.crypto.truststore.Truststore.ValidationResult;
import com.keynectis.sequoia.security.signeddocument.DocumentVerifier;
import com.keynectis.sequoia.security.xml.dsig.SignatureAlgorithm;
import com.opentrust.spi.cms.helpers.OCSPResponse;
import com.opentrust.spi.pdf.PDFEnvelopedSignature;
import com.opentrust.spi.pdf.PDFVerifSignature;
import com.opentrust.spi.pdf.PdfSignParameters.PAdESParameters.PadesLevel;
import com.opentrust.spi.tsp.TimestampToken;

public class PdfVerifier extends DocumentVerifier {
    
	public static class PdfValidationResult
	{
		public PDFEnvelopedSignature signature;
		public ValidationResult validation;
	}
	
    private List<SignatureAlgorithm> acceptableSignatureAlgorithms = null;
    private PadesLevel padesConformanceLevel = PadesLevel.PADES_NONE;
    private String signatureType;
    
    public void setSignatureValidationParams(List<SignatureAlgorithm> acceptableSignatureAlgorithms) {
        this.acceptableSignatureAlgorithms = acceptableSignatureAlgorithms;
    }
    
    public void setPadesConformanceLevel(PadesLevel level) {
        this.padesConformanceLevel = level;
    }

    
    public List<PdfValidationResult> verify(PdfDocument document, String signatureName) throws SignatureException {
        //FIXME
        signatureType = "PADES-BASIC";
        ArrayList<PdfValidationResult> result = new ArrayList<PdfValidationResult>();
        List<PDFEnvelopedSignature> verifResults = PDFVerifSignature.verify(document.reader);
        for (PDFEnvelopedSignature signature : verifResults)
        {
        	PdfValidationResult current = new PdfValidationResult();
        	current.signature = signature;
			X509Certificate [] list = null;
        	Certificate[] includedCerts = signature.getCertificates();
        	if (includedCerts != null && includedCerts.length > 0)
			{
        		list = new X509Certificate[includedCerts.length];
			}
        	try {
        		Collection<OCSPResponse> ocspResponses = signature.getOcspResponses();
        		Collection crLs = signature.getCRLs();
        		TimestampToken timestampToken = signature.getTimestampToken();
        		
        		current.validation = signingCertificateTruststore.validate(signature.getSigningCertificate(), list);
			} catch (Exception e) {
				throw new SignatureException("Failed signature validation", e);
			}
        }
        return result;
    }
    
    
    @Override
    protected String getSignatureType() {
        return signatureType;
    }
    
}
