package com.opentrust.spi.pdf;

import java.awt.Color;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import org.apache.commons.lang.time.DateUtils;
import org.bouncycastle.x509.X509AttributeCertificate;

import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.opentrust.spi.cms.CMSForPAdESEnhancedGenerator.PolicyIdentifierParams;

public class PdfSignParameters {
	private String mode;

	// mode can be ppkms, ppklite or ppkvs
	// Tells whether the signing certificate comes from the windows store,
	// adobe store or verisign plug-in store
	// More generally, adobe users can install plugins that enable signing
	// from a given store (that can includes signing with biometric data,
	// etc).
	// In Adobe security preferences, one can specify the method to use when
	// signing (Edit/Preferences/Security/advanced/Creation/Default method
	// to use when signing documents)
	// It is also possible to specify what to do at signature verification
	// time (Edit/Preferences/Security/advanced/Verification) : use method
	// found in PDF, prompt, or use method specified in Adobe preferences
	// (plug-in store or Adobe store...)
	// As of Acrobat 7, there is no difference between ppkms (windows store)
	// and ppklite (adobe store). Or so it seems.

	// If you want signatures to be fully OK when viewing in Acrobat, you
	// need to add CAs that are root for the signing certificates.
	// Whether it is manually (Advanced/Manage trusted identities/add) or
	// automatically via windows store
	// (Edit/Preferences/Security/advanced/Windows Integration/Trust root
	// certifs in windows store).

	// Subfilters for ppkms or ppklite are described in
	// http://www.ietf.org/rfc/rfc3778.txt (possibly adbe.x509.rsa_sha1,
	// adbe.pkcs7.sha1 or adbe.pkcs7.detached).
	// Let's just say we'll only use adbe.pkcs7.detached for now

	private String reason;

	private String location;

	private String contact;

	private String certifLevel;
		public static String NOT_CERTIFIED = "NOT_CERTIFIED";
		public static String CERTIFIED_NO_CHANGES_ALLOWED = "CERTIFIED_NO_CHANGES_ALLOWED";
		public static String CERTIFIED_FORM_FILLING = "CERTIFIED_FORM_FILLING";
		public static String CERTIFIED_FORM_FILLING_AND_ANNOTATIONS = "CERTIFIED_FORM_FILLING_AND_ANNOTATIONS";
		// used for 'author' signature. Once a document
		// is 'author-signed' (certified), you can
		// decide which kind of further modification can
		// be done to the document (no modif, form fill
		// modif...)

	private boolean signatureAlreadyExists;

	private String signatureName; // A default name is given if no name is provided

	private boolean isVisible;

	private SignatureLayoutParameters signatureLayoutParameters;

	private boolean createNewRevision;
		// If true, the new signature will be part of a new revision (along with
		// other modifications possibly, but we're just adding a new signature
		// here), thus
		// not invalidating already existing signatures. In Acrobat, the latter
		// will appear in the new revision with a little warning
		// saying that they cover another revision (it is possible to view the
		// former revisions).
		// Should always be set to true, even when signature fields are already
		// in the document (in which case we could have hoped signatures would
		// remain valid without changing version).

	// Timestamp conf
	// In adobe, timestamp configuration is made by advanced/Security
	// settings/TimeStamp servers
	private TimestampingParameters timeStampParams;

	// Ocsp conf
	private List<OCSPParameters> ocspParams;

	private PAdESParameters padesParameters;
	
	private boolean allocateTimeStampContainer;
		// When not using a timestamp,
		// you can still prepare the
		// signature for a future
		// timestamping (allocate a
		// larger block than what is
		// necessary for a simple
		// signature)

	private int timeStampContainerSize;
	private int signatureContainerSize;
	
	private boolean keepPDFACompliance; // this means we embed the fonts used for signing, or use already embedded fonts
	
	// no signatureAlgorithm, because has algo used for sign = dataHashAlgorithm
	private String dataHashAlgorithm;
	
	private Calendar signingTime;
	
	/**
	 * 
	 * @param mode can be ppkms, ppklite or ppkvs (defaults to ppkms = Microsoft Cert Store)
	 * @param reason
	 * @param location
	 * @param contact
	 * @param certifLevel defaults to NOT_CERTIFIED
	 * @param signatureAlreadyExists
	 * @param signatureName Mandatory if signatureAlreadyExists=true
	 * @param createNewRevision
	 * @param allocateTimeStampContainer
	 * @param keepPDFACompliance
	 * @return
	 */
	public static PdfSignParameters getParametersForPresign(String mode, String reason, String location, String contact, String certifLevel, boolean signatureAlreadyExists, String signatureName,
			boolean createNewRevision, boolean allocateTimeStampContainer, int timeStampContainerSize, int signatureContainerSize, boolean keepPDFACompliance, Calendar signingTime) {
		return new PdfSignParameters(mode, reason, location, contact, certifLevel, signatureAlreadyExists, signatureName, createNewRevision,
				allocateTimeStampContainer, timeStampContainerSize, signatureContainerSize, keepPDFACompliance, null, signingTime);
	}

	/**
	 * 
	 * @param mode
	 * @param reason
	 * @param location
	 * @param contact
	 * @param certifLevel
	 * @param signatureAlreadyExists
	 * @param signatureName
	 * @param createNewRevision
	 * @param keepPDFACompliance
	 * @param dataHashAlgorithm
	 * @return
	 */
	 public static PdfSignParameters getParametersForSign(String mode, String reason, String location, String contact, String certifLevel, boolean signatureAlreadyExists, String signatureName,
			boolean createNewRevision, boolean keepPDFACompliance, boolean allocateTimeStampContainer, int timeStampContainerSize, int signatureContainerSize, String dataHashAlgorithm, Calendar signingTime) {
		return new PdfSignParameters(mode, reason, location, contact, certifLevel, signatureAlreadyExists, signatureName, createNewRevision,
				allocateTimeStampContainer, timeStampContainerSize, signatureContainerSize, keepPDFACompliance, dataHashAlgorithm, signingTime);
	}


	/**
	 * 
	 * @param mode
	 *            can be ppkms, ppklite or ppkvs
	 * @param reason
	 * @param location
	 * @param createNewRevision
	 *            when false, this signature possibly invalidates signatures that already exist in the document when
	 *            true, the signature covers a newly made revision. All existing signatures remain valid, with only a
	 *            little warning saying that they cover another revision.
	 * @param certifLevel
	 *            can be NOT_CERTIFIED, CERTIFIED_NO_CHANGES_ALLOWED, CERTIFIED_FORM_FILLING or
	 *            CERTIFIED_FORM_FILLING_AND_ANNOTATIONS
	 */
	private PdfSignParameters(String mode, String reason, String location, String contact, String certifLevel, boolean signatureAlreadyExists, String signatureName, 
			boolean createNewRevision, boolean allocateTimeStampContainer, int timeStampContainerSize, int signatureContainerSize, boolean keepPDFACompliance, String dataHashAlgorithm, Calendar signingTime) {
		super();
		this.mode = mode;
		this.reason = reason;
		this.location = location;
		this.contact = contact;
		this.certifLevel = certifLevel;
		this.signatureAlreadyExists = signatureAlreadyExists;
		this.signatureName = signatureName;
		this.createNewRevision = createNewRevision;
		this.allocateTimeStampContainer = allocateTimeStampContainer;
		this.timeStampContainerSize = timeStampContainerSize;
		this.signatureContainerSize = signatureContainerSize;
		this.keepPDFACompliance = keepPDFACompliance;
		this.dataHashAlgorithm = dataHashAlgorithm;
		//Stripping signingTime of its milliseconds, not used by CMS signingTime field format and which could lead to signature corruption
		this.signingTime = DateUtils.round(signingTime, Calendar.SECOND);
	}

	public SignatureLayoutParameters getSignatureLayoutParameters() {
		return signatureLayoutParameters;
	}

	/**
	 * Sets the signature to visible, using layout given as parameters
	 * @param signatureLayoutParameters
	 */
	public void setSignatureLayoutParameters(SignatureLayoutParameters signatureLayoutParameters) {
		this.isVisible = true;
		this.signatureLayoutParameters = signatureLayoutParameters;
	}

	public TimestampingParameters getTimeStampParams() {
		return timeStampParams;
	}

	public void setTimeStampParams(TimestampingParameters timeStampParams) {
		this.allocateTimeStampContainer = true;
		this.timeStampParams = timeStampParams;
	}

	public List<OCSPParameters> getOCSPParams() {
		return ocspParams;
	}

	public void setOCSPParams(List<OCSPParameters> ocspParams) {
		this.ocspParams = ocspParams;
	}
	public void addOCSPParams(OCSPParameters ocspParams) {
		if(this.ocspParams==null) this.ocspParams = new ArrayList<OCSPParameters>();
		this.ocspParams.add(ocspParams);
	}

	public PAdESParameters getPadesParameters() {
		return padesParameters;
	}

	public void setPadesParameters(PAdESParameters padesParameters) {
		this.padesParameters = padesParameters;
	}

	public PdfName getFilter() {
		if (mode.equalsIgnoreCase("ppkms")) {
			return PdfSignatureAppearance.WINCER_SIGNED;
		} else if (mode.equalsIgnoreCase("ppklite")) {
			return PdfSignatureAppearance.SELF_SIGNED;
		} else if (mode.equalsIgnoreCase("ppkvs")) {
			return PdfSignatureAppearance.VERISIGN_SIGNED;
		}
		return PdfSignatureAppearance.WINCER_SIGNED;
	}

	public int getCertifLevel() {
		if (certifLevel.equalsIgnoreCase("NOT_CERTIFIED")) {
			return PdfSignatureAppearance.NOT_CERTIFIED;
		} else if (certifLevel.equalsIgnoreCase("CERTIFIED_NO_CHANGES_ALLOWED")) {
			return PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED;
		} else if (certifLevel.equalsIgnoreCase("CERTIFIED_FORM_FILLING")) {
			return PdfSignatureAppearance.CERTIFIED_FORM_FILLING;
		} else if (certifLevel.equalsIgnoreCase("CERTIFIED_FORM_FILLING_AND_ANNOTATIONS")) {
			return PdfSignatureAppearance.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS;
		}
		return PdfSignatureAppearance.NOT_CERTIFIED;
	}

	public String getReason() {
		return reason;
	}

	public Calendar getSigningTime() {
		return signingTime;
	}

	public String getLocation() {
		return location;
	}

	public boolean isVisible() {
		return isVisible;
	}

	public boolean isSignatureAlreadyExists() {
		return signatureAlreadyExists;
	}

	public String getSignatureName() {
		return signatureName;
	}

	public boolean isCreateNewRevision() {
		return createNewRevision;
	}

	public boolean isAllocateTimeStampContainer() {
		return allocateTimeStampContainer;
	}

	public void setAllocateTimeStampContainer(boolean addTimeStampContainer) {
		this.allocateTimeStampContainer = addTimeStampContainer;
	}

	public String getContact() {
		return contact;
	}

	public String getDataHashAlgorithm() {
		return dataHashAlgorithm;
	}

	public boolean isKeepPDFACompliance() {
		return keepPDFACompliance;
	}

	@Override
	public String toString() {
		StringBuilder result = new StringBuilder();
		result.append(getClass().getName() + "{");
		result.append("mode:" + mode + ";");
		result.append("isVisible:" + isVisible + ";");
		result.append("certifLevel:" + certifLevel + ";");
		result.append("timeStampParams:" + timeStampParams + ";");
		result.append("createNewRevision:" + createNewRevision + ";");
		result.append("sigLayout:" + signatureLayoutParameters + ";");
		result.append("dataHashAlgorithm:" + dataHashAlgorithm + ";");
		result.append("signatureName:" + signatureName + ";");
		result.append("signingTime:" + (signingTime!=null?signingTime.getTimeInMillis():null) + ";");
		result.append("}");
		return result.toString();
	}

	public static class TimestampingParameters {
		private String timeStampServerURL;

		private String timeStampServerUsername;

		private String timeStampServerPassword;

		private String timeStampDigestAlgo;

		private boolean timeStampUseNonce;

		private String timeStampPolicyOID;

		public TimestampingParameters(String timeStampServerURL, String timeStampServerUsername, String timeStampServerPassword, String timeStampDigestAlgo, boolean timeStampUseNonce,
				String timeStampPolicyOID) {
			super();
			this.timeStampServerURL = timeStampServerURL;
			this.timeStampServerUsername = timeStampServerUsername;
			this.timeStampServerPassword = timeStampServerPassword;
			this.timeStampDigestAlgo = timeStampDigestAlgo;
			this.timeStampUseNonce = timeStampUseNonce;
			this.timeStampPolicyOID = timeStampPolicyOID;
		}

		public String getTimeStampDigestAlgo() {
			return timeStampDigestAlgo;
		}

		public String getTimeStampPolicyOID() {
			return timeStampPolicyOID;
		}

		public String getTimeStampServerPassword() {
			return timeStampServerPassword;
		}

		public String getTimeStampServerURL() {
			return timeStampServerURL;
		}

		public String getTimeStampServerUsername() {
			return timeStampServerUsername;
		}

		public boolean isTimeStampUseNonce() {
			return timeStampUseNonce;
		}
		
		@Override
		public String toString() {
			StringBuilder result = new StringBuilder();
			result.append(getClass().getName() + "{");
			result.append("timeStampServerURL:" + timeStampServerURL + ";");
			result.append("timeStampServerUsername:" + timeStampServerUsername + ";");
			result.append("timeStampServerPassword:" + timeStampServerPassword + ";");
			result.append("timeStampDigestAlgo:" + timeStampDigestAlgo + ";");
			result.append("timeStampUseNonce:" + timeStampUseNonce + ";");
			result.append("timeStampPolicyOID:" + timeStampPolicyOID + ";");
			result.append("}");
			return result.toString();
		}
	}

	public static class OCSPParameters {
		private String ocspResponderId;

		private Certificate targetCertificate;

		private Certificate issuerCertificate;

		public OCSPParameters(String ocspResponderId, Certificate targetCertificate, Certificate issuerCertificate) {
			super();
			this.ocspResponderId = ocspResponderId;
			this.targetCertificate = targetCertificate;
			this.issuerCertificate = issuerCertificate;
		}

		public Certificate getIssuerCertificate() {
			return issuerCertificate;
		}

		public String getOcspResponderId() {
			return ocspResponderId;
		}

		public Certificate getTargetCertificate() {
			return targetCertificate;
		}

		@Override
		public String toString() {
			StringBuilder result = new StringBuilder();
			result.append(getClass().getName() + "{");
			result.append("ocspResponderId:" + ocspResponderId + ";");
			result.append("targetCertificate:" + targetCertificate + ";");
			result.append("issuerCertificate:" + issuerCertificate + ";");
			result.append("}");
			return result.toString();
		}
		
	}
	
	public static class PAdESParameters {
		private PadesLevel padesLevel = PadesLevel.PADES_BASIC;
		public static enum PadesLevel {PADES_NONE, PADES_BASIC, PADES_BES, PADES_EPES}
		//PADES_NONE never used because generated signatures are at least PADES_BASIC
		//TODO : add PadesLevel.PADES_LTV ? Unless DSS & Document TS can be added without breaking existing signatures ? What about extension dico ?
		
		
		private PolicyIdentifierParams policyIdentifierParams;
		private List<String> claimedAttributes;
		private String claimedAttributesOID;
		private X509AttributeCertificate certifiedAttribute;
		private TimestampingParameters contentTimeStampParams;
		private String commitmentTypeId;
			
		private PAdESParameters(PadesLevel padesLevel) {
			this.padesLevel = padesLevel;
		}

		public static PAdESParameters getPAdESBasicParameters() {
			return new PAdESParameters(PadesLevel.PADES_BASIC);
		}
	
		public static PAdESParameters getPAdESBESParameters() {
			return new PAdESParameters(PadesLevel.PADES_BES);
		}

		public static PAdESParameters getPAdESEPESParameters(String signaturePolicyOID, byte[] signaturePolicyHashValue, String signaturePolicyHashAlgorithm) {
			return getPAdESEPESParameters(new PolicyIdentifierParams(signaturePolicyOID, signaturePolicyHashValue, signaturePolicyHashAlgorithm));
		}

		public static PAdESParameters getPAdESEPESParameters(PolicyIdentifierParams policyIdentifierParams) {
			PAdESParameters params = new PAdESParameters(PadesLevel.PADES_EPES);
			params.policyIdentifierParams = policyIdentifierParams;
			//TODO : add commitment-type-indication parameters & use them when creating signature
			return params;
		}

		public PadesLevel getPadesLevel() {
			return padesLevel;
		}
		public boolean isPadesEnhancedLevel() {
			return (padesLevel==PadesLevel.PADES_BES || padesLevel==PadesLevel.PADES_EPES);
		}
		public PolicyIdentifierParams getPolicyIdentifierParams() {
			return policyIdentifierParams;
		}
		public List<String> getClaimedAttributes() {
			return claimedAttributes;
		}
		public String getClaimedAttributesOID() {
			return this.claimedAttributesOID;
		}
		public void setClaimedAttributes(String claimedAttributesOID, List<String> claimedAttributes) {
			this.claimedAttributesOID = claimedAttributesOID;
			this.claimedAttributes = claimedAttributes;
		}
		public X509AttributeCertificate getCertifiedAttribute() {
			return certifiedAttribute;
		}
		public void setCertifiedAttribute(X509AttributeCertificate certifiedAttribute) {
			this.certifiedAttribute = certifiedAttribute;
		}
		public TimestampingParameters getContentTimeStampParams() {
			return contentTimeStampParams;
		}
		public void setContentTimeStampParams(TimestampingParameters contentTimeStampParams) {
			this.contentTimeStampParams = contentTimeStampParams;
		}
		public String getCommitmentTypeId() {
			return commitmentTypeId;
		}
		public void setCommitmentTypeId(String commitmentTypeId) {
			this.commitmentTypeId = commitmentTypeId;
		}
	}	
	
	
	
	public static class SignatureLayoutParameters {
		private float x1;

		private float y1;

		private float x2;

		private float y2;

		private int pageNbr;

		private String description;
		// Caution : if null, a default description
		// will be used. This description tries to access the
		// certificate properties (CN...).

		private byte[] backgroundImage;

		private float backgroundImageScale;
		// default 0, can be >0 or <0, see
		// javadoc for PdfSignatureAppearance.setImageScale

		private int runDirection;
			// possible values are
			// PdfWriter.RUN_DIRECTIONXXXX

		private int sigRenderMode;
			public static int SignatureRenderDescription = PdfSignatureAppearance.SignatureRenderDescription;
			public static int SignatureRenderGraphicAndDescription = PdfSignatureAppearance.SignatureRenderGraphicAndDescription;
			public static int SignatureRenderNameAndDescription = PdfSignatureAppearance.SignatureRenderNameAndDescription;
		// can be PdfSignatureAppearance.SignatureRenderXXX
			// * SignatureRenderDescription
			// * SignatureRenderGraphicAndDescription : don't forget to set a signatureImage
			// * SignatureRenderNameAndDescription : only works (with iText2.0.7) if
				// a certificate has been given to the SignatureAppearance object : this
				// certif's cn will be the name

		private byte[] signatureImage; // use when sigRenderMode = SignatureRenderGraphicAndDescription

		private int fontFamily = -1; // courier,times_roman...

		private int fontStyle = -1; // italic,bold...

		private float fontSize = -1F;

		// -1 for fontFamily, fontStyle and fontSize are default values (used in Font() for instance)
		
		private Color fontColor;

		
		
		private SignatureLayoutParameters(float x1, float y1, float x2, float y2, int pageNbr, String description, byte[] backgroundImage, float backgroundImageScale, int runDirection, int sigRenderMode, byte[] signatureImage, int fontFamily, int fontStyle, float fontSize, Color fontColor) {
			super();
			this.x1 = x1;
			this.y1 = y1;
			this.x2 = x2;
			this.y2 = y2;
			this.pageNbr = pageNbr;
			this.description = description;
			this.backgroundImage = backgroundImage;
			this.backgroundImageScale = backgroundImageScale;
			this.runDirection = runDirection;
			this.sigRenderMode = sigRenderMode;
			this.signatureImage = signatureImage;
			this.fontFamily = fontFamily;
			this.fontStyle = fontStyle;
			this.fontSize = fontSize;
			this.fontColor = fontColor;
		}

		/**
		 * @deprecated  replace with equivalent without 'statusText', which is not used anymore
		 */
		@Deprecated public static SignatureLayoutParameters getLayoutParametersForNewSign(float x1, float y1, float x2, float y2, int pageNbr, String description, byte[] backgroundImage, float backgroundImageScale, int runDirection, String statusText, int sigRenderMode, byte[] signatureImage, int fontFamily, int fontStyle, float fontSize, Color fontColor) {
			return new SignatureLayoutParameters(x1, y1, x2, y2, pageNbr, description, backgroundImage, backgroundImageScale, runDirection, sigRenderMode, signatureImage, fontFamily, fontStyle, fontSize, fontColor);
		}
		public static SignatureLayoutParameters getLayoutParametersForNewSign(float x1, float y1, float x2, float y2, int pageNbr, String description, byte[] backgroundImage, float backgroundImageScale, int runDirection, int sigRenderMode, byte[] signatureImage, int fontFamily, int fontStyle, float fontSize, Color fontColor) {
			return new SignatureLayoutParameters(x1, y1, x2, y2, pageNbr, description, backgroundImage, backgroundImageScale, runDirection, sigRenderMode, signatureImage, fontFamily, fontStyle, fontSize, fontColor);
		}
		
		//TODO : provide other versions of getLayoutParametersForNewSign
		public static SignatureLayoutParameters getLayoutParametersForNewSign(float x1, float y1, float x2, float y2, int pageNbr, String description) {
			return new SignatureLayoutParameters(x1, y1, x2, y2, pageNbr, description, null, 0, 0, SignatureRenderDescription , null, -1, -1, -1F, null);
		}

		/**
		 * @deprecated  replace with equivalent without 'statusText', which is not used anymore
		 */
		@Deprecated public static SignatureLayoutParameters getLayoutParametersForAlreadyExistingSign(String description, byte[] backgroundImage, float backgroundImageScale, int runDirection, String statusText, int sigRenderMode, byte[] signatureImage, int fontFamily, int fontStyle, float fontSize, Color fontColor) {
			return new SignatureLayoutParameters(0, 0, 0, 0, 0, description, backgroundImage, backgroundImageScale, runDirection, sigRenderMode, signatureImage, fontFamily, fontStyle, fontSize, fontColor);
		}
		public static SignatureLayoutParameters getLayoutParametersForAlreadyExistingSign(String description, byte[] backgroundImage, float backgroundImageScale, int runDirection, int sigRenderMode, byte[] signatureImage, int fontFamily, int fontStyle, float fontSize, Color fontColor) {
			return new SignatureLayoutParameters(0, 0, 0, 0, 0, description, backgroundImage, backgroundImageScale, runDirection, sigRenderMode, signatureImage, fontFamily, fontStyle, fontSize, fontColor);
		}
		
		public byte[] getBackgroundImage() {
			return backgroundImage;
		}

		public void setBackgroundImage(byte[] backgroundImage) {
			this.backgroundImage = backgroundImage;
		}

		public float getBackgroundImageScale() {
			return backgroundImageScale;
		}

		public void setBackgroundImageScale(float backgroundImageScale) {
			this.backgroundImageScale = backgroundImageScale;
		}

		public String getDescription() {
			return description;
		}

		public void setDescription(String description) {
			this.description = description;
		}

		public Color getFontColor() {
			return fontColor;
		}

		public void setFontColor(Color fontColor) {
			this.fontColor = fontColor;
		}

		public int getFontFamily() {
			return fontFamily;
		}

		public void setFontFamily(int fontFamily) {
			this.fontFamily = fontFamily;
		}

		public float getFontSize() {
			return fontSize;
		}

		public void setFontSize(float fontSize) {
			this.fontSize = fontSize;
		}

		public int getFontStyle() {
			return fontStyle;
		}

		public void setFontStyle(int fontStyle) {
			this.fontStyle = fontStyle;
		}

		public int getPageNbr() {
			return pageNbr;
		}

		public void setPageNbr(int pageNbr) {
			this.pageNbr = pageNbr;
		}

		public int getRunDirection() {
			return runDirection;
		}

		public void setRunDirection(int runDirection) {
			this.runDirection = runDirection;
		}

		public byte[] getSignatureImage() {
			return signatureImage;
		}

		public void setSignatureImage(byte[] signatureImage) {
			this.signatureImage = signatureImage;
		}

		public int getSigRenderMode() {
			return sigRenderMode;
		}

		public void setSigRenderMode(int sigRenderMode) {
			this.sigRenderMode = sigRenderMode;
		}

		public float getX1() {
			return x1;
		}

		public void setX1(float x1) {
			this.x1 = x1;
		}

		public float getX2() {
			return x2;
		}

		public void setX2(float x2) {
			this.x2 = x2;
		}

		public float getY1() {
			return y1;
		}

		public void setY1(float y1) {
			this.y1 = y1;
		}

		public float getY2() {
			return y2;
		}

		public void setY2(float y2) {
			this.y2 = y2;
		}

		@Override
		public String toString() {
			StringBuilder result = new StringBuilder();
			result.append(getClass().getName() + "{");
			result.append("x1:" + x1 + ";");
			result.append("y1:" + y1 + ";");
			result.append("x2:" + x2 + ";");
			result.append("y2:" + y2 + ";");
			result.append("pageNbr:" + pageNbr + ";");
			result.append("sigRenderMode:" + sigRenderMode + ";");
			result.append("}");
			return result.toString();
		}
	}

	public void setDataHashAlgorithm(String dataHashAlgorithm) {
		this.dataHashAlgorithm = dataHashAlgorithm;
	}

	public void setSigningTime(Calendar signingTime) {
		this.signingTime = signingTime;
	}

	public int getSignatureContainerSize() {
		return signatureContainerSize;
	}

	public int getTimeStampContainerSize() {
		return timeStampContainerSize;
	}

}