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
		public boolean containsRequiredAC = true;
		public String missingCa;
		
		public boolean isValid()
		{
			return pdfValidation && trustValidationResult.valid && containsRequiredAC;
		}
		
		public String getSignatureName()
		{
			return signature.getSignatureFieldName();
		}
		
		public X509Certificate getSignatureCertificate()
		{
			return trustValidationResult.tree.finalNode.entry.cert;
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

    /**
     * Verify the validity of the pdf document
     * - the format
     * - the validity of the signature certificate
     * @param document
     * @param signatureNames : the list of signatures to verify, if null, all the signatures are verified
     * @return
     * @throws Exception
     */
    public List<PdfValidationResult> verify(PdfDocument document, String ...signatureNames) throws Exception {
        //FIXME
    	ArrayList<String> signatureNameList = null;
    	if (signatureNames != null && signatureNames.length > 0)
    	{
    		signatureNameList= new ArrayList<String>();
        	for (String signatureName : signatureNames)
        		signatureNameList.add(signatureName);
        }
    	
        signatureType = "PADES-BASIC";
        ArrayList<PdfValidationResult> result = new ArrayList<PdfValidationResult>();
        List<PDFEnvelopedSignature> verifResults = PDFVerifSignature.verify(document.reader);
        for (PDFEnvelopedSignature signatureVerifResult : verifResults)
        {
        	String signatureFieldName = signatureVerifResult.getSignatureFieldName();
        	if (signatureNameList != null && !signatureNameList.contains(signatureFieldName))
        		continue;
        		
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
    		X509Certificate []requiredCa = getAcceptedCACertificates();
    		if (requiredCa != null)
    		{
    			List<X509Certificate> missingCA = current.trustValidationResult.treeContains(requiredCa);
    			current.containsRequiredAC = (missingCA.size() == 0);
    			StringBuilder sb = new StringBuilder();
    			for (X509Certificate missingCert : missingCA)
    				sb.append(missingCert.getSubjectX500Principal().toString()+";");
    			current.missingCa = sb.toString();
    		}
    		
        }
        return result;
    }
    
    
    @Override
    protected String getSignatureType() {
        return signatureType;
    }
    
}
