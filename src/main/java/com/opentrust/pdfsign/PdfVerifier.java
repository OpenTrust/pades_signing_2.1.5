package com.opentrust.pdfsign;

import java.io.InputStream;
import java.util.List;

import com.keynectis.sequoia.security.signeddocument.DocumentVerifier;
import com.keynectis.sequoia.security.xml.dsig.SignatureAlgorithm;

public class PdfVerifier extends DocumentVerifier {
    
    private List<SignatureAlgorithm> acceptableSignatureAlgorithms;
    
    public void setSignatureValidationParams(List<SignatureAlgorithm> acceptableSignatureAlgorithms) {
        this.acceptableSignatureAlgorithms = acceptableSignatureAlgorithms;
    }

    PdfDocument parseDocumentSignatures(InputStream pdfIn) {
        return null;
    }
    
    boolean verify(PdfDocument document, String signatureName) {
        
        return true;
    }
    
    @Override
    protected String getSignatureType() {
        // TODO Auto-generated method stub
        return "PADES-BASIC";
    }
    
}
