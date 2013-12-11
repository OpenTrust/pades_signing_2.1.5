package com.opentrust.pdfsign;

import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPResp;

import com.keynectis.sequoia.ca.crypto.truststore.LongTermValidationInfos;
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
		public boolean pdfValidation;
		public PDFEnvelopedSignature signature;
		public ValidationResult trustValidationResult;
		
		public boolean isValid()
		{
			return pdfValidation && trustValidationResult.valid;
		}
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

    
    public List<PdfValidationResult> verify(PdfDocument document) throws Exception {
        //FIXME
        signatureType = "PADES-BASIC";
        ArrayList<PdfValidationResult> result = new ArrayList<PdfValidationResult>();
        List<PDFEnvelopedSignature> verifResults = PDFVerifSignature.verify(document.reader);
        for (PDFEnvelopedSignature signatureVerifResult : verifResults)
        {
        	PdfValidationResult current = new PdfValidationResult();
        	result.add(current);
        	current.signature = signatureVerifResult;
        	current.pdfValidation = signatureVerifResult.verify();
        	
			X509Certificate [] list = null;
        	Certificate[] includedCerts = signatureVerifResult.getCertificates();
        	if (includedCerts != null && includedCerts.length > 0)
			{
        		list = new X509Certificate[includedCerts.length];
        		for (int i=0 ; i<includedCerts.length ; i++)
        			list[i] = (X509Certificate) includedCerts[i];
			}

        		TimestampToken timestampToken = signatureVerifResult.getTimestampToken();
        		LongTermValidationInfos ltvInfos = null;
        		if (timestampToken != null)
        		{
        			ltvInfos = new LongTermValidationInfos();
        			ltvInfos.timeStampDate = timestampToken.getDateTime();
        			ltvInfos.tspCertificate = (X509Certificate) timestampToken.getSignerCertificate();
        			
            		Collection<OCSPResponse> ocspResponses = signatureVerifResult.getOcspResponses();
            		ArrayList<BasicOCSPResp> ocspList = new ArrayList<BasicOCSPResp>();
            		for (OCSPResponse resp : ocspResponses)
            		{
            			 OCSPResp bcResp = new OCSPResp(resp.getEncoded());
            			 BasicOCSPResp basicResp = (BasicOCSPResp) bcResp.getResponseObject();
            			 ocspList.add(basicResp);
            		}
            		ltvInfos.ocspResponse = ocspList.toArray(new BasicOCSPResp[] {});

            		Collection<X509CRL> crLs = signatureVerifResult.getCRLs();
            		ArrayList<X509CRL> crlList = new ArrayList<X509CRL>();
            		for (X509CRL crl : crLs)
            		{
            			crlList.add(crl);
            		}
            		ltvInfos.crls = crlList.toArray(new X509CRL[] {});
        		}
        		
        		current.trustValidationResult = signingCertificateTruststore.validate(signatureVerifResult.getSigningCertificate(), ltvInfos, list);

        }
        return result;
    }
    
    
    @Override
    protected String getSignatureType() {
        return signatureType;
    }
    
}
