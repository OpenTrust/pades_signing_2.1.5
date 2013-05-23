package com.opentrust.spi.cms;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

import com.keynectis.sequoia.ca.crypto.utils.OIDUtils;
import com.opentrust.spi.cms.helpers.OCSPResponse;
import com.opentrust.spi.cms.helpers.SignedAttributesHelper;

// Generates CMS signatures suitable for PAdES v3 (or Enhanced = BES or EPES) compatibility
public class CMSForPAdESEnhancedGenerator extends CMSForPAdESBasicGenerator {
	public static class PolicyIdentifierParams {
		private String signaturePolicyOID;
		private byte[] signaturePolicyHashValue;
		private String signaturePolicyHashAlgorithm;
		private boolean signaturePolicyImplied;

		public PolicyIdentifierParams(String signaturePolicyOID, byte[] signaturePolicyHashValue, String signaturePolicyHashAlgorithm) {
			this.signaturePolicyOID = signaturePolicyOID;
			this.signaturePolicyHashValue = signaturePolicyHashValue;
			this.signaturePolicyHashAlgorithm = signaturePolicyHashAlgorithm;
			this.signaturePolicyImplied = false;
		}
		
		protected PolicyIdentifierParams() {
		}
		
		public static PolicyIdentifierParams getPolicyImpliedParams() {
			PolicyIdentifierParams policyIdentifierParams = new PolicyIdentifierParams();
			policyIdentifierParams.signaturePolicyImplied = true;
			return policyIdentifierParams;
		}
		
		public String getSignaturePolicyOID() {
			return signaturePolicyOID;
		}
		public byte[] getSignaturePolicyHashValue() {
			return signaturePolicyHashValue;
		}
		public String getSignaturePolicyHashAlgorithm() {
			return signaturePolicyHashAlgorithm;
		}
		public boolean isSignaturePolicyImplied() {
			return signaturePolicyImplied;
		}
	}

	public CMSForPAdESEnhancedGenerator(String provider, Certificate certificate, PrivateKey privateKey, 
			Collection certStore, String digestAlgorithm, Collection<CRL> signedCrls, Collection<OCSPResponse> signedOcspResponses) throws NoSuchAlgorithmException {
		super(provider, certificate, privateKey, certStore, null, digestAlgorithm, signedCrls, signedOcspResponses);
		//null -> signingtime never set for PAdED enhanced
	}
	
	// Performs CMS signing on provided content
	// optionally, content can be encapsulated in CMS
	public static byte[] signContent(String provider, InputStream inputStream,
			Certificate certificate, PrivateKey privateKey,
			Collection certStore,
			String digestAlgorithm, Collection<CRL> signedCrls, Collection<OCSPResponse> signedOcspResponses,
			boolean encapsulate, PolicyIdentifierParams policyIdentifierParams) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			CertStoreException, CMSException, IOException, CRLException, OperatorCreationException, CertificateEncodingException, URISyntaxException, SignatureException {

		CMSForPAdESEnhancedGenerator cmsGenerator = new CMSForPAdESEnhancedGenerator(provider, certificate, privateKey, certStore, digestAlgorithm, signedCrls, signedOcspResponses);
		cmsGenerator.policyIdentifierParams = policyIdentifierParams;
		
		return cmsGenerator.signContent(inputStream, encapsulate);
	}
	
	// Performs CMS signing on pre-digested content
	public static byte[] signReference(String provider, byte[] digest, Certificate certificate,
			PrivateKey privateKey, Collection certStore,
			String digestAlgorithm, Collection<CRL> signedCrls, Collection<OCSPResponse> signedOcspResponses,
			PolicyIdentifierParams policyIdentifierParams)
			throws InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException,
			CertStoreException, CMSException, IOException,
			CRLException, OperatorCreationException, CertificateEncodingException, URISyntaxException, SignatureException {
		
		CMSForPAdESEnhancedGenerator cmsGenerator = new CMSForPAdESEnhancedGenerator(provider, certificate, privateKey, certStore, digestAlgorithm, signedCrls, signedOcspResponses);
		cmsGenerator.policyIdentifierParams = policyIdentifierParams;
		
		return cmsGenerator.signReference(digest);
	}
	
    protected PolicyIdentifierParams policyIdentifierParams;
	public void setPolicyIdentifierParams(PolicyIdentifierParams policyIdentifierParams) {
		this.policyIdentifierParams = policyIdentifierParams;
	}

    protected List<String> claimedAttributes = new ArrayList<String>();
    protected String claimedAttributesOID;
	public void addClaimedAttribute(String claimedAttribute) {
		if(certifiedAttributes==null)
			claimedAttributes.add(claimedAttribute);
		//TODO : else exception ?
	}
	public void setClaimedAttribute(String claimedAttributesOID, List<String> claimedAttributes) {
		if(certifiedAttributes==null) {
			this.claimedAttributesOID = claimedAttributesOID;
			this.claimedAttributes = claimedAttributes;
		}
		//TODO : else exception ?
	}
    protected byte[] certifiedAttributes;
	public void setCertifiedAttribute(byte[] certifiedAttribute) {
		if(claimedAttributes==null || claimedAttributes.isEmpty())
			certifiedAttributes = certifiedAttribute;
		//TODO : else exception ?
	}

	protected byte[] contentTimeStamp;
	public void setContentTimeStamp(byte[] contentTimeStamp) {
		this.contentTimeStamp = contentTimeStamp;
	}
	
	protected String commitmentTypeId;
	public void setCommitmentTypeId(String commitmentTypeId) {
		this.commitmentTypeId = commitmentTypeId;
	}

	@Override
 	protected void populateSignedAttributesHashtable() throws CRLException, IOException, CertificateEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
    	//AlgorithmID digestAlgo = digestAlg!=null?digestAlg:AlgorithmID.DIGEST_SHA256;
		String digestAlgo = digestAlg != null ? digestAlg : "Sha256";
    	//TODO : digestAlg being null means we should fetch digestAlgo elsewhere : by extracting it from contentSigner.getAlgorithm() ?
    	//(for now this method is always called with digestAlg not being null...)
		
    	//FIXME : deal with errors !
    	if(isSha1(digestAlgo))
    		SignedAttributesHelper.addSigningCertificateAttribute(signedAttributesHashtable, certificate);
    	else
    	{
    		AlgorithmIdentifier algoIdentifier = getAlgorithmIdentifier(digestAlgo);
			SignedAttributesHelper.addSigningCertificateV2Attribute(signedAttributesHashtable, algoIdentifier, certificate);
			//SignedAttributesHelper.addSigningCertificateV2Attribute(signedAttributesHashtable, AlgorithmIdentifier.getInstance(digestAlgo.getOID()), certificate);
    	}
		if(policyIdentifierParams!=null) {
			if(policyIdentifierParams.isSignaturePolicyImplied())
				SignedAttributesHelper.addImpliedSignaturePolicy(signedAttributesHashtable);
			else
				SignedAttributesHelper.addSignaturePolicyIdentifier(signedAttributesHashtable, new DERObjectIdentifier(policyIdentifierParams.getSignaturePolicyOID()), new DEROctetString(policyIdentifierParams.getSignaturePolicyHashValue()), AlgorithmIdentifier.getInstance(policyIdentifierParams.getSignaturePolicyHashAlgorithm()));
		}
		if((claimedAttributes!=null && !claimedAttributes.isEmpty()) || certifiedAttributes!=null)
			SignedAttributesHelper.addSignerAttributes(signedAttributesHashtable, claimedAttributesOID, claimedAttributes, certifiedAttributes);
		if(contentTimeStamp!=null)
			SignedAttributesHelper.addContentTimestampAttribute(signedAttributesHashtable, contentTimeStamp);
		if(commitmentTypeId!=null)
			SignedAttributesHelper.addCommitmentTypeIndicationAttribute(signedAttributesHashtable, commitmentTypeId);
		
   }

	private boolean isSha1(String digestAlgo) {
		try
		{
			DERObjectIdentifier oid = new DERObjectIdentifier(digestAlgo);
			DERObjectIdentifier sha1Oid = OIDUtils.getOID("SHA-1");
			return oid.equals(sha1Oid);			
		}catch(Exception e) {}
		return digestAlgo.equalsIgnoreCase("SHA-1") || digestAlgo.equalsIgnoreCase("SHA1");
	}

	public static AlgorithmIdentifier getAlgorithmIdentifier(String digestAlgo) {
		DERObjectIdentifier oid = OIDUtils.getOID(digestAlgo);
		return AlgorithmIdentifier.getInstance(oid.getId());
	}
}
