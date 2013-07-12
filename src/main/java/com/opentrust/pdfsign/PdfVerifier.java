package com.opentrust.pdfsign;

import java.util.List;

import com.keynectis.sequoia.security.signeddocument.DocumentVerifier;
import com.keynectis.sequoia.security.xml.dsig.SignatureAlgorithm;
import com.opentrust.spi.pdf.PdfSignParameters.PAdESParameters.PadesLevel;

public class PdfVerifier extends DocumentVerifier {
    
    private List<SignatureAlgorithm> acceptableSignatureAlgorithms = null;
    private PadesLevel padesConformanceLevel = PadesLevel.PADES_NONE;
    private String signatureType;
    
    public void setSignatureValidationParams(List<SignatureAlgorithm> acceptableSignatureAlgorithms) {
        this.acceptableSignatureAlgorithms = acceptableSignatureAlgorithms;
    }
    
    public void setPadesConformanceLevel(PadesLevel level) {
        this.padesConformanceLevel = level;
    }
    
    public boolean verify(PdfDocument document, String signatureName) {
        //FIXME
        signatureType = "PADES-BASIC";
        return true;
    }
    
    @Override
    protected String getSignatureType() {
        return signatureType;
    }
    
}
