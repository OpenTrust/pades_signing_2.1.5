package com.opentrust.spi.cms.helpers;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
import org.bouncycastle.asn1.esf.SignerAttribute;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.ess.ContentHints;
import org.bouncycastle.asn1.ess.ContentIdentifier;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;

import com.opentrust.spi.crypto.CRLHelper;
import com.opentrust.spi.logger.Channel;
import com.opentrust.spi.logger.SPILogger;
/*
import com.opentrust.spi.crypto.CRLHelper;
import com.opentrust.spi.ocsp.OCSPResponse;
import com.opentrust.spi.ocsp.OCSPResponseFactory;
import com.opentrust.spi.tsp.TimestampToken;
import com.opentrust.spi.tsp.TimestampTokenManagerFactory;
*/
import com.opentrust.spi.tsp.TimestampToken;
import com.opentrust.spi.tsp.impl.BCTimeStampToken;

public class SignedAttributesHelper {
	private static SPILogger log = SPILogger.getLogger("CMS");
	public static final ASN1ObjectIdentifier ID_ADBE_REVOCATION = new ASN1ObjectIdentifier("1.2.840.113583.1.1.8");


	/****** SETTERS *******/
	public static void addMessageDigestAttribute(Hashtable<DERObjectIdentifier, Attribute> signedAttributesHashtable, byte[] digest) {
		if(digest==null) return;
		Attribute messageDigestAttribute = new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(digest)));
		signedAttributesHashtable.put(CMSAttributes.messageDigest, messageDigestAttribute);
	}

	public static void addSigningTimeAttribute(Hashtable<DERObjectIdentifier, Attribute> signedAttributesHashtable, Date signingTime) {
		if(signingTime==null) return;
		Attribute signingTimeAttribute = new Attribute(CMSAttributes.signingTime, new DERSet(new DERUTCTime(signingTime)));
		signedAttributesHashtable.put(CMSAttributes.signingTime, signingTimeAttribute);
	}

	public static void addSigningCertificateAttribute(
			Hashtable<DERObjectIdentifier, Attribute> signedAttributesHashtable, Certificate cert)
			throws CertificateEncodingException, NoSuchAlgorithmException {
		if (cert == null)
			return;
		ESSCertID essCertid = new ESSCertID(MessageDigest.getInstance("SHA-1").digest(cert.getEncoded()));
		Attribute signingCertificateAttribute = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate,
				new DERSet(new SigningCertificate(essCertid)));
		signedAttributesHashtable.put(PKCSObjectIdentifiers.id_aa_signingCertificate, signingCertificateAttribute);
	}

	public static void addSigningCertificateV2Attribute(
			Hashtable<DERObjectIdentifier, Attribute> signedAttributesHashtable,
			AlgorithmIdentifier hashAlgo, Certificate cert) 
	throws CertificateEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
		if (cert == null || hashAlgo == null)
			return;
		ESSCertIDv2 essCertid = new ESSCertIDv2(hashAlgo, MessageDigest.getInstance(hashAlgo.getAlgorithm().getId(),
				BouncyCastleProvider.PROVIDER_NAME).digest(cert.getEncoded()));
		Attribute signingCertificateV2Attribute = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
				new DERSet(new SigningCertificateV2(new ESSCertIDv2[] { essCertid })));
		signedAttributesHashtable.put(PKCSObjectIdentifiers.id_aa_signingCertificateV2, signingCertificateV2Attribute);
	}

	public static void addRevocationValuesAttribute(Hashtable<DERObjectIdentifier, Attribute> signedAttributesHashtable, Collection<CRL> crls, Collection<OCSPResponse> ocspResponses) throws IOException, CRLException {
		if (((crls == null) || (crls.size() == 0)) && ((ocspResponses == null) || (ocspResponses.size() == 0)))
			return;
		
		ASN1EncodableVector revocationValues = new ASN1EncodableVector();
		
		if ((crls != null) && (crls.size() > 0)) {
			ASN1EncodableVector v2 = new ASN1EncodableVector();
			for (CRL crl:crls) {
				ASN1InputStream t = new ASN1InputStream(new ByteArrayInputStream(((X509CRL) crl).getEncoded()));
				v2.add(t.readObject());
			}
			// 0->CRL
			revocationValues.add(new DERTaggedObject(true, 0, new DERSequence(
					v2)));
		}
		
		if ((ocspResponses != null) && (ocspResponses.size() > 0)) {
			ASN1EncodableVector v2 = new ASN1EncodableVector();
			for (OCSPResponse ocspResponse : ocspResponses) {
				ASN1InputStream t = new ASN1InputStream(
						new ByteArrayInputStream(ocspResponse.getEncoded()));
				v2.add(t.readObject());
			}
			// 1->OCSP
			revocationValues.add(new DERTaggedObject(true, 1, new DERSequence(
					v2)));
		}
		Attribute revocationAttr = new Attribute(ID_ADBE_REVOCATION,
				new DERSet(new DERSequence(revocationValues)));
		signedAttributesHashtable.put(ID_ADBE_REVOCATION, revocationAttr);
		
	}
	
	public static void addSignaturePolicyIdentifier(Hashtable<DERObjectIdentifier, Attribute> signedAttributesHashtable, DERObjectIdentifier signaturePolicyOID, ASN1OctetString signaturePolicyHashValue, AlgorithmIdentifier signaturePolicyHashAlgorithm) throws CertificateEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
		//FIXME : validate input
		SignaturePolicyIdentifier signaturePolicyIdentifier = new SignaturePolicyIdentifier(new SignaturePolicyId(signaturePolicyOID, new OtherHashAlgAndValue(signaturePolicyHashAlgorithm, signaturePolicyHashValue)));
		Attribute signaturePolicyIdentifierAttr = new Attribute(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId, new DERSet(signaturePolicyIdentifier)); 
		signedAttributesHashtable.put(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId, signaturePolicyIdentifierAttr);
	}

	public static void addImpliedSignaturePolicy(Hashtable<DERObjectIdentifier, Attribute> signedAttributesHashtable)  {
		SignaturePolicyIdentifier signaturePolicyIdentifier = new SignaturePolicyIdentifier();
		Attribute signaturePolicyIdentifierAttr = new Attribute(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId, new DERSet(signaturePolicyIdentifier)); 
		signedAttributesHashtable.put(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId, signaturePolicyIdentifierAttr);
	}

	public static void addSignerAttributes(Hashtable<DERObjectIdentifier, Attribute> signedAttributesHashtable, String claimedAttributesOID, List<String> claimedAttributes, byte[] certifiedAttributes) throws IOException  {
		SignerAttribute signerAttribute = null;
		if(claimedAttributes!=null && !claimedAttributes.isEmpty()) {
			DERUTF8String[] claimedRoles = new DERUTF8String[claimedAttributes.size()];
			int i = 0;
			for(String claimedRole : claimedAttributes) {
				claimedRoles[i++] = new DERUTF8String(claimedRole);
			}
			ASN1Set claimedRolesList = new DERSet(claimedRoles);

			Attribute claimedRolesAttr = new Attribute(new ASN1ObjectIdentifier(claimedAttributesOID), claimedRolesList);
			
			signerAttribute = new SignerAttribute(new DERSequence(claimedRolesAttr));
		} else if(certifiedAttributes!=null) {
			ByteArrayInputStream bIn = new ByteArrayInputStream(certifiedAttributes);
	        ASN1InputStream aIn = new ASN1InputStream(bIn);
	        ASN1Sequence seq = (ASN1Sequence) aIn.readObject();
			signerAttribute = new SignerAttribute(new AttributeCertificate(seq));
		}
		//TODO : else, when both are empty, throw exception
		Attribute signerAttributesAttr = new Attribute(PKCSObjectIdentifiers.id_aa_ets_signerAttr, new DERSet(signerAttribute)); 
		signedAttributesHashtable.put(PKCSObjectIdentifiers.id_aa_ets_signerAttr, signerAttributesAttr);
	}

	public static void addContentTimestampAttribute(Hashtable<DERObjectIdentifier, Attribute> signedAttributesHashtable, byte[] timeStampTokenBytes) throws IOException {
		if(timeStampTokenBytes==null) return;
		DERObject derObj = new ASN1InputStream(new ByteArrayInputStream(timeStampTokenBytes)).readObject();
        DERSet derSet = new DERSet(derObj);
        Attribute contentTimestampAtt = new Attribute(PKCSObjectIdentifiers.id_aa_ets_contentTimestamp, derSet);
        signedAttributesHashtable.put(PKCSObjectIdentifiers.id_aa_ets_contentTimestamp, contentTimestampAtt);
	}

	public static void addCommitmentTypeIndicationAttribute(Hashtable<DERObjectIdentifier, Attribute> signedAttributesHashtable, String commitmentTypeId) throws IOException {
		CommitmentTypeIndication indic = new CommitmentTypeIndication(new ASN1ObjectIdentifier(commitmentTypeId));
		Attribute commitmentTypeIndicationAttr = new Attribute(PKCSObjectIdentifiers.id_aa_ets_commitmentType, new DERSet(indic)); 
		signedAttributesHashtable.put(PKCSObjectIdentifiers.id_aa_ets_commitmentType, commitmentTypeIndicationAttr);
	}

	/****** GETTERS *******/
	public static Set<OCSPResponse> getSignedOCSPResponses(AttributeTable table) {
		Set<OCSPResponse> ocspResponses = new HashSet<OCSPResponse>();
		// OCSP responses found as signed ID_ADBE_REVOCATION attribute
		if(table!=null) {
			Attribute hash = table.get(ID_ADBE_REVOCATION);
			if(hash!=null) {
				ASN1Set attrValues = hash.getAttrValues();
				if(attrValues!=null) {
					DERSequence seq = (DERSequence) attrValues.getObjectAt(0);
					if(seq!=null) {
						Enumeration enumer0 = seq.getObjects();
						if(enumer0!=null) {
							while(enumer0.hasMoreElements()) {
								DEREncodable derenc = (DEREncodable)enumer0.nextElement();
								DERTaggedObject dertag = (DERTaggedObject) derenc;
								if (dertag.getTagNo()==1) { // 1->OCSP
									// Extracts signed OCSPs
									DERSequence seq3 = (DERSequence) dertag.getObject();
									for (int i=0; i < seq3.size(); ++i) {
										DERSequence seq4 = ((DERSequence)seq3.getObjectAt(i));
										OCSPResponse ocspResponse = null;
										try {
											byte[] ocspResponseEncoded = seq4.getDEREncoded();
											ocspResponse = OCSPResponse.parseResponse(ocspResponseEncoded);
										} catch (Exception e1) {
											log.error(Channel.TECH, "Problem with ocspResponse retrieving : " + e1);
										}
										if (ocspResponse != null) {
											log.debug(Channel.TECH, "Successfully parsed OCSP response");
											ocspResponses.add(ocspResponse);
										} else
											log.info(Channel.TECH, "OCSP response extracted from pdf signature is null !");
									}
								}
							}
						}
					}	
				}
			}
		}
		return ocspResponses;
	}
	
	public static Collection<CRL> getSignedCRLs(AttributeTable table) throws CRLException, CertificateException, IOException, NoSuchProviderException {
		Collection<CRL> x509CrlsCollection = new HashSet<CRL>();
		if(table!=null) {
			Attribute hash = table.get(ID_ADBE_REVOCATION);
			if(hash!=null) {
				ASN1Set attrValues = hash.getAttrValues();
				if(attrValues!=null) {
					DERSequence seq = (DERSequence) attrValues.getObjectAt(0);
					if(seq!=null) {
						Enumeration enumer0 = seq.getObjects();
						if(enumer0!=null) {
							while(enumer0.hasMoreElements()) {
								DEREncodable derenc = (DEREncodable)enumer0.nextElement();
								if(derenc!=null) {
									DERTaggedObject dertag = (DERTaggedObject) derenc;
									if (dertag.getTagNo()==0) { // 0->CRL
										// Extracts signed CRLs
										DERSequence seq3 = (DERSequence) dertag.getObject();
										for (int i=0; i < seq3.size(); ++i) {
											DERSequence seq4 = ((DERSequence)seq3.getObjectAt(i));
											CRL crl = CRLHelper.getCRL(seq4.getDEREncoded());
											x509CrlsCollection.add(crl);
										}
									}
								}
							}
						}
					}
				}
			}
		}
		return x509CrlsCollection;
	}
	
	public static Date getSigningTime(AttributeTable atab) {
		Date result = null;
		if (atab != null) {
			Attribute attr = atab.get(CMSAttributes.signingTime);
			if (attr != null) {
				Time t = Time.getInstance(attr.getAttrValues().getObjectAt(0).getDERObject());
				result = t.getDate();
			}
		}
		return result;
	}

	public static byte[] getDigestAttribute(AttributeTable atab) {
		byte[] result = null;
		if (atab != null) {
			Attribute attr = atab.get(CMSAttributes.messageDigest);
			if (attr != null) {
				result = ASN1OctetString.getInstance(attr.getAttrValues().getObjectAt(0)).getOctets();
			}
		}
		return result;
	}

	public static ASN1ObjectIdentifier getContentTypeAttribute(AttributeTable atab) {
		ASN1ObjectIdentifier result = null;
		if (atab != null) {
			Attribute attr = atab.get(CMSAttributes.contentType);
			if (attr != null) {
				result = (ASN1ObjectIdentifier)attr.getAttrValues().getObjectAt(0);
			}
		}
		return result;
	}

	public static ESSCertID getSigningCertificateAttribute(AttributeTable atab) {
		ESSCertID result = null;
		if (atab != null) {
			Attribute attr = atab.get(PKCSObjectIdentifiers.id_aa_signingCertificate);
			if (attr != null) {
				ESSCertID[] signingCerts = SigningCertificate.getInstance(attr.getAttrValues().getObjectAt(0)).getCerts();
				if(signingCerts!=null && signingCerts.length>0) {
					result = signingCerts[0];
				}
				//TODO : what should we do with the other certs ?
			}
		}
		return result;
	}

	public static ESSCertIDv2 getSigningCertificateV2Attribute(AttributeTable atab) {
		ESSCertIDv2 result = null;
		if (atab != null) {
			Attribute attr = atab.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
			if (attr != null) {
				ESSCertIDv2[] signingCerts = SigningCertificateV2.getInstance(attr.getAttrValues().getObjectAt(0)).getCerts();
				if(signingCerts!=null && signingCerts.length>0) {
					result = signingCerts[0];
				}
				//TODO : what should we do with the other certs ?
			}
		}
		return result;
	}

	public static SignaturePolicyIdentifier getSignaturePolicyIdentifierAttribute(AttributeTable atab) {
		SignaturePolicyIdentifier result = null;
		if (atab != null) {
			Attribute attr = atab.get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId);
			if (attr != null) {
				result = SignaturePolicyIdentifier.getInstance(attr.getAttrValues().getObjectAt(0));
			}
		}
		return result;
	}

	public static DEREncodable getContentReferenceAttribute(AttributeTable atab) {
		DEREncodable result = null;
		if (atab != null) {
			Attribute attr = atab.get(PKCSObjectIdentifiers.id_aa_contentReference);
			if (attr != null) {
				result = attr.getAttrValues().getObjectAt(0);
			}
		}
		return result;
	}

	public static ContentIdentifier getContentIdentifierAttribute(AttributeTable atab) {
		ContentIdentifier result = null;
		if (atab != null) {
			Attribute attr = atab.get(PKCSObjectIdentifiers.id_aa_contentIdentifier);
			if (attr != null) {
				result = ContentIdentifier.getInstance(attr.getAttrValues().getObjectAt(0));
			}
		}
		return result;
	}

	public static ContentHints getContentHintsAttribute(AttributeTable atab) {
		ContentHints result = null;
		if (atab != null) {
			Attribute attr = atab.get(CMSAttributes.contentHint);
			if (attr != null) {
				result = ContentHints.getInstance(attr.getAttrValues().getObjectAt(0));
			}
		}
		return result;
	}

	public static CommitmentTypeIndication getCommitmentTypeIndicationAttribute(AttributeTable atab) {
		CommitmentTypeIndication result = null;
		if (atab != null) {
			Attribute attr = atab.get(PKCSObjectIdentifiers.id_aa_ets_commitmentType);
			if (attr != null) {
				result = CommitmentTypeIndication.getInstance(attr.getAttrValues().getObjectAt(0));
			}
		}
		return result;
	}

	public static SignerLocation getSignerLocationAttribute(AttributeTable atab) {
		SignerLocation result = null;
		if (atab != null) {
			Attribute attr = atab.get(PKCSObjectIdentifiers.id_aa_ets_signerLocation);
			if (attr != null) {
				result = SignerLocation.getInstance(attr.getAttrValues().getObjectAt(0));
			}
		}
		return result;
	}

	public static SignerAttribute getSignerAttributesAttribute(AttributeTable atab) {
		SignerAttribute result = null;
		if (atab != null) {
			Attribute attr = atab.get(PKCSObjectIdentifiers.id_aa_ets_signerAttr);
			if (attr != null) {
				// Does not work for certifiedAttributes !? (AttributeCertificate.getInstance(dertaggedobject) tries to ASN1Sequence.getInstance(dertaggedobject) -> fails)
				//FIXME : use this simple line when bug is fixed by BC 
				//result = SignerAttribute.getInstance(attr.getAttrValues().getObjectAt(0));

				// Copied from SignerAttribute getInstance & constructor :
				Object obj = attr.getAttrValues().getObjectAt(0);
		        if(obj == null || (obj instanceof SignerAttribute))
		            return (SignerAttribute)obj;
		        if(obj instanceof ASN1Sequence) {
		        	ASN1Sequence asn1sequence = (ASN1Sequence)obj;
			        DERTaggedObject dertaggedobject = (DERTaggedObject)asn1sequence.getObjectAt(0);
			        if(dertaggedobject.getTagNo() == 0)
			            result = new SignerAttribute(ASN1Sequence.getInstance(dertaggedobject, true));
			        else if(dertaggedobject.getTagNo() == 1) {
		                return new SignerAttribute(new AttributeCertificate(ASN1Sequence.getInstance(dertaggedobject, true)));
			        } else
			            throw new IllegalArgumentException("illegal tag.");
			    } else
		            throw new IllegalArgumentException((new StringBuilder()).append("unknown object in 'SignerAttribute' factory: ").append(obj.getClass().getName()).append(".").toString());
			}
		}
		return result;
	}

	public static TimestampToken getContentTimestamp(AttributeTable atab) throws IOException, CMSException, TSPException {
		TimestampToken result = null;
		if(atab!=null) {
			Attribute attr = atab.get(PKCSObjectIdentifiers.id_aa_ets_contentTimestamp);
			if (attr != null) {
				DEREncodable dob = attr.getAttrValues().getObjectAt(0);
				if(dob!=null) {
					byte[] encodedTsp = dob.getDERObject().getEncoded();
					if(encodedTsp!=null) {
						result = new BCTimeStampToken(encodedTsp);
					}
				}
			}
		}
		return result;
	}

}
