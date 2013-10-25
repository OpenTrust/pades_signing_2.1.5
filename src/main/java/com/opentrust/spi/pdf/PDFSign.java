package com.opentrust.spi.pdf;

import java.awt.Color;
import java.awt.Transparency;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.imageio.ImageIO;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.encoders.Hex;

import com.keynectis.sequoia.ca.crypto.utils.OIDUtils;
import com.keynectis.sequoia.ca.crypto.utils.PKCS12File;
import com.keynectis.sequoia.security.clients.OCSPClient;
import com.keynectis.sequoia.security.clients.TspClient;
import com.keynectis.sequoia.security.clients.interfaces.IOCSPClient;
import com.keynectis.sequoia.security.clients.interfaces.ITspClient;
import com.opentrust.spi.cms.CMSForPAdESBasicGenerator;
import com.opentrust.spi.cms.CMSForPAdESEnhancedGenerator;
import com.opentrust.spi.cms.CMSGenerator;
import com.opentrust.spi.cms.CMSSignedDataWrapper;
import com.opentrust.spi.cms.helpers.OCSPResponse;
import com.opentrust.spi.crypto.CRLHelper;
import com.opentrust.spi.crypto.CertificateHelper;
import com.opentrust.spi.crypto.CryptoConstants.AlgorithmID;
import com.opentrust.spi.crypto.DigestHelper;
import com.opentrust.spi.crypto.ExceptionHandler;
import com.opentrust.spi.logger.Channel;
import com.opentrust.spi.logger.SPILogger;
import com.opentrust.spi.pdf.PdfSignParameters.OCSPParameters;
import com.opentrust.spi.pdf.PdfSignParameters.PAdESParameters;
import com.opentrust.spi.pdf.PdfSignParameters.SignatureLayoutParameters;
import com.opentrust.spi.pdf.PdfSignParameters.TimestampingParameters;
import com.opentrust.spi.tsp.TimeStampProcessor;
import com.opentrust.spi.tsp.TimestampToken;
import com.spilowagie.text.DocumentException;
import com.spilowagie.text.Font;
import com.spilowagie.text.FontFactory;
import com.spilowagie.text.Image;
import com.spilowagie.text.Rectangle;
import com.spilowagie.text.pdf.AcroFields;
import com.spilowagie.text.pdf.BaseFont;
import com.spilowagie.text.pdf.PdfArray;
import com.spilowagie.text.pdf.PdfDate;
import com.spilowagie.text.pdf.PdfDeveloperExtension;
import com.spilowagie.text.pdf.PdfDictionary;
import com.spilowagie.text.pdf.PdfIndirectReference;
import com.spilowagie.text.pdf.PdfName;
import com.spilowagie.text.pdf.PdfNumber;
import com.spilowagie.text.pdf.PdfObject;
import com.spilowagie.text.pdf.PdfReader;
import com.spilowagie.text.pdf.PdfSignatureAppearance;
import com.spilowagie.text.pdf.PdfStamper;
import com.spilowagie.text.pdf.PdfStream;
import com.spilowagie.text.pdf.PdfString;
import com.spilowagie.text.pdf.PdfWriter;
import com.spilowagie.text.pdf.RandomAccessFileOrArray;

//TODO : check if there is a fileID in the document to sign. If no fileID -> no fileID in outgoing file. If fileID, use it, along with signDate, to build the new fileID
public class PDFSign {

	public static String PRODUCED_BY = "OpenTrust SPI";

	public static void setPRODUCED_BY(String pRODUCED_BY) {
		PRODUCED_BY = pRODUCED_BY;
	}

	private static SPILogger log = SPILogger.getLogger("PDFSIGN");

	private static int CONTENT_SIZE = 0x2502;
	private static int TIMESTAMP_SIZE = 0x2502;

	//private static OCSPResponderManager ocspResponderManager = OCSPResponderManager.getInstance();
	protected IOCSPClient ocspClient;
	protected ITspClient tspClient;
	
	/*
	static IOCSPClient defaultOCSPClient;
	static ITspClient defaultTspClient;
	*/

	private static PdfName DOCTIMESTAMP= new PdfName("DocTimeStamp");
	static PdfName DSS= new PdfName("DSS");
	static PdfName CERTS= new PdfName("Certs");
	static PdfName CRLS= new PdfName("CRLs");
	static PdfName OCSPS= new PdfName("OCSPs");
	static PdfName VRI= new PdfName("VRI");
	static PdfName CRL= new PdfName("CRL");
	static PdfName OCSP= new PdfName("OCSP");
	
	
	static {
        FontFactory.register("/fonts/DejaVuSerif.ttf");
        FontFactory.register("/fonts/DejaVuSans.ttf");
        FontFactory.register("/fonts/DejaVuSansMono.ttf");
        //TODO : not using -Bold and -Oblique fonts, this apparently not being necessary
        //TODO : use something like ClassHelper.getClassesForPackage() to retrieve all ttf resource files in /fonts
	}
	
	/****************** BEGIN SIGN METHODS ************************/

	public static SignReturn sign(String provider, PdfReader reader, OutputStream out, File tmpFile, PrivateKey priv,
			Certificate[] certificateChain, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters)
			throws SPIException {
		try {
			Certificate signerCert = null;
			if (certificateChain != null & certificateChain.length != 0)
				signerCert = certificateChain[0];
			PdfStamper stp = prepareSign(reader, out, tmpFile, signerCert, parameters);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();

			SignResult signResult = cms_sign(provider, sap.getRangeStream(), priv, certificateChain, parameters, crls,
					ocspResponseEncoded);

			return signAfterPresignWithEncodedP7(sap, signResult.getEncodedPkcs7(), parameters,
					signResult.getTimestampToken());
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}

	public static SignReturn sign(String provider, PdfReader reader, OutputStream out, File tmpFile, String keyStoreFileName, String password, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
		try 
		{
			PKCS12File p12 = new PKCS12File(keyStoreFileName, password);
			/*
			KeyStore keyStore = KeyStoreHelper.load(keyStoreFileName, password);
			String alias = KeyStoreHelper.getDefaultAlias(keyStore);
			Certificate[] chain = (Certificate[]) keyStore.getCertificateChain(alias);
			PrivateKey priv = (PrivateKey) (keyStore.getKey(alias, password.toCharArray()));
			*/
			Certificate[] chain = p12.getChain();
			PrivateKey priv = p12.mPrivateKey;
			return sign(provider, reader, out, tmpFile, priv, chain, crls, ocspResponseEncoded, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}
	
	public static SignReturn sign(String provider, InputStream original_pdf, OutputStream out, PrivateKey priv, Certificate[] certificateChain, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
		log.debug(Channel.TECH, "Signing document using parameters %1$s", parameters);
		try {
			PdfReader reader = new PdfReader(original_pdf);
			return sign(provider, reader, out, null, priv, certificateChain, crls, ocspResponseEncoded, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}
	
	// Use for large Files
	public static SignReturn sign(String provider, String original_pdf_name, OutputStream out, File tmpFile, PrivateKey priv, Certificate[] certificateChain, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
		log.debug(Channel.TECH, "Signing document using parameters %1$s", parameters);
		try {
			PdfReader reader = new PdfReader(new RandomAccessFileOrArray(original_pdf_name), null);
			return sign(provider, reader, out, tmpFile, priv, certificateChain, crls, ocspResponseEncoded, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}

	public static SignReturn sign(String provider, File original_pdf, OutputStream out, PrivateKey priv, Certificate[] certificateChain, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
		try {
			return sign(provider, new FileInputStream(original_pdf), out, priv, certificateChain, crls, ocspResponseEncoded, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}

	public static SignReturn sign(String provider, File original_pdf, OutputStream out, String keyStoreFileName, String password, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
		log.debug(Channel.TECH, "Signing document retrieving certificate from keystore '%1$s' and using parameters %2$s", keyStoreFileName, parameters);
		try {
			return sign(provider, new FileInputStream(original_pdf), out, keyStoreFileName, password, crls, ocspResponseEncoded, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}

	public static SignReturn sign(String provider, InputStream original_pdf, OutputStream out, 
			String keyStoreFileName, String password, CRL[] crls, OCSPResponse[] ocspResponseEncoded, 
			PdfSignParameters parameters) throws SPIException {
		log.debug(Channel.TECH, "Signing document retrieving certificate from keystore '%1$s' and using parameters %2$s", keyStoreFileName, parameters);
		try {
			PdfReader reader = new PdfReader(original_pdf);
			return sign(provider, reader, out, null, keyStoreFileName, password, crls, ocspResponseEncoded, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}

	// Use for large Files
	public static SignReturn sign(String provider, String original_pdf_name, 
			OutputStream out, File tmpFile, String keyStoreFileName, String password, CRL[] crls, 
			OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException 
			{
		log.debug(Channel.TECH, "Signing document retrieving certificate from keystore '%1$s' and using parameters %2$s", keyStoreFileName, parameters);
		try {
			PdfReader reader = new PdfReader(new RandomAccessFileOrArray(original_pdf_name), null);
			return sign(provider, reader, out, tmpFile, keyStoreFileName, password, crls, ocspResponseEncoded, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e, "reading file " + original_pdf_name);
		}
		return null;
	}

	/****************** END SIGN METHODS ************************/

	/****************** BEGIN PRESIGN METHODS ************************/
	
	/**
	 * preSign
	 * Usage : call preSign + build and sign CMS using returned data as data to sign + send CMS-encoded bytes as encodedPkcs7 parameter to method signAfterPresignWithEncodedP7
	 */
	public static PresignReturn preSign(InputStream original_pdf, PdfSignParameters parameters) throws SPIException {
		return preSign(original_pdf, null, null, null, parameters);
	}

	//For large PDF
	public static PresignReturn preSign(String original_pdf_name, File tmpFile, PdfSignParameters parameters) throws SPIException {
		return preSign(original_pdf_name, tmpFile, null, null, null, parameters);
	}

	protected static PresignReturn preSign(PdfReader original_pdf, OutputStream output_pdf, File tmpFile, Certificate signerCert, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
		log.debug(Channel.TECH, "Presigning document using parameters %1$s", parameters);
		PresignReturn retour = null;
		try {
			PdfStamper stp = prepareSign(original_pdf, output_pdf, tmpFile, signerCert, parameters);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();
			
			retour = new PresignReturn(sap.getRangeStream(), sap.getFieldName(), sap);
			String dataHashAlgo = parameters.getDataHashAlgorithm();
			if(dataHashAlgo!=null) {
				// TODO : raise a wrong usage exception when dataHashAlgo==null && tmpFile!=null
				retour.setHashToSign(DigestHelper.getDigest(retour.getDataToSign(), parameters.getDataHashAlgorithm()));
				log.debug(Channel.TECH, "presign returning hash : %1$s", retour.getHashToSign());
			}
			// dataToSign stream is about to be closed, we set it to null
			if(tmpFile!=null) retour.dataToSign = null;
			
			sap.closeStreams();
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return retour;
	}
	public static PresignReturn preSign(InputStream original_pdf, Certificate signerCert, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
	    return preSign(original_pdf, null, signerCert, crls, ocspResponseEncoded, parameters);
	}
	
	//Use for large PDF
	public static PresignReturn preSign(String original_pdf_name, File tmpFile, Certificate signerCert, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
		return preSign(original_pdf_name, null, tmpFile, signerCert, crls, ocspResponseEncoded, parameters);
	}
	
	public static PresignReturn preSign(InputStream original_pdf, OutputStream output_pdf, Certificate signerCert, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
        try {
            log.debug(Channel.TECH, "preSign for normal size pdf");
            PdfReader reader = new PdfReader(original_pdf);
            return preSign(reader, output_pdf, null, signerCert, crls, ocspResponseEncoded, parameters);
        } catch (Exception e) {
            ExceptionHandler.handle(e);
        }
        return null;
    }
    
    //Use for large PDF
    public static PresignReturn preSign(String original_pdf_name, OutputStream output_pdf, File tmpFile, Certificate signerCert, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
        try {
            log.debug(Channel.TECH, "preSign for large size pdf");
            PdfReader reader = new PdfReader(new RandomAccessFileOrArray(original_pdf_name), null);
            return preSign(reader, output_pdf, tmpFile, signerCert, crls, ocspResponseEncoded, parameters);
        } catch (Exception e) {
            ExceptionHandler.handle(e);
        }
        return null;
    }
	/****************** END PRESIGN METHODS ************************/

	/****************** BEGIN PRESIGNFORRAWSIGNATURE METHODS ************************/
	
	/**
	 * preSignForRawSignature
	 * Usage : call preSignForRawSignature + sign returned data + 
	 *  - either send raw signature bytes as rawSignature parameter to method signAfterPresignWithRawSignature, along with returned encoded PKCS#7
	 *  - or insert raw signature in returned PKCS#7, and send it as encodedPkcs7 parameter to signAfterPresignWithEncodedPkcs7
	 */
	protected static PresignReturnForRawSignature preSignForRawSignature(PdfReader original_pdf, File tmpFile, Certificate[] certs, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
		log.debug(Channel.TECH, "Presigning document before raw signature using parameters %1$s", parameters);
		PresignReturnForRawSignature retour = null;
		try {
			PdfStamper stp = prepareSign(original_pdf, null, tmpFile, certs[0], parameters);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();
			
			String dataHashAlgo = parameters.getDataHashAlgorithm();
			if(dataHashAlgo==null) throw new IllegalArgumentException("digestAlgo required for preSignForRawSignature");

			// Computing data to sign hash
			MessageDigest messageDigest = MessageDigest.getInstance(dataHashAlgo);
			DigestInputStream dis = new DigestInputStream(sap.getRangeStream(),messageDigest);
			byte[] buf = new byte[1024];
			while (dis.read(buf, 0, buf.length) != -1);
			sap.closeStreams();

			// Building CMS
			// FIXME : use PadesBasicCMS class or Pades....etc
			PDFEnvelopedSignature otp7 = new PDFEnvelopedSignature(dis.getMessageDigest().digest(), certs, crls, ocspResponseEncoded, parameters.getDataHashAlgorithm(), BouncyCastleProvider.PROVIDER_NAME, "dummy".getBytes(), null, "RSA", parameters.getSigningTime()!=null?parameters.getSigningTime().getTime():null);
			byte[] encodedP7 = otp7.getEncodedPKCS7(null, null);
			
			retour = new PresignReturnForRawSignature(otp7.getSignedAttrs(), encodedP7, sap.getFieldName());
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return retour;
	}
	public static PresignReturnForRawSignature preSignForRawSignature(InputStream original_pdf, Certificate[] certs, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
		try {
			log.debug(Channel.TECH, "PresignReturnForRawSignature for normal size pdf");
			PdfReader reader = new PdfReader(original_pdf);
			return preSignForRawSignature(reader, null, certs, crls, ocspResponseEncoded, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}
	
	//Use for large PDF
	public static PresignReturnForRawSignature preSignForRawSignature(String original_pdf_name, File tmpFile, Certificate[] certs, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
		try {
			log.debug(Channel.TECH, "PresignReturnForRawSignature for large size pdf");
			PdfReader reader = new PdfReader(new RandomAccessFileOrArray(original_pdf_name), null);
			return preSignForRawSignature(reader, tmpFile, certs, crls, ocspResponseEncoded, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}
	/****************** END PRESIGNFORRAWSIGNATURE METHODS ************************/

	/****************** BEGIN signAfterPresignWithRawSignature METHODS ************************/

	/**
	 * signAfterPresignWithRawSignature
	 * Usage : call preSignForRawSignature + sign returned data + send raw signature bytes as rawSignature parameter to method signAfterPresignWithRawSignature, along with returned encoded PKCS#7
	 */
	public static SignReturn signAfterPresignWithRawSignature(InputStream original_pdf, OutputStream out, byte[] rawSignature, byte[] encodedUnsignedPkcs7, Certificate signerCert, PdfSignParameters parameters) throws SPIException {
		try {
			return signAfterPresignWithRawSignature(new PdfReader(original_pdf), out, null, rawSignature, encodedUnsignedPkcs7, signerCert, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}

	protected static SignReturn signAfterPresignWithRawSignature(PdfReader original_pdf, OutputStream out,
			File tmpFile, byte[] rawSignature, byte[] encodedUnsignedPkcs7, Certificate signerCert,
			PdfSignParameters parameters) throws SPIException {
		try {
			log.debug(Channel.TECH, "Signing document with incoming raw signature, using parameters %1$s", parameters);

			// TODO : see if we can use something like
			// CMSSignedData.replaceSigners instead, to start from the unsigned
			// p7 and only change its signaturevalue
			CMSSignedDataWrapper unsignedCmsSignature = new CMSSignedDataWrapper(encodedUnsignedPkcs7);
			CRL[] crlList = null;
			if (unsignedCmsSignature.getCRLs() != null)
				crlList = (CRL[]) unsignedCmsSignature.getCRLs().toArray(new CRL[] {});
			OCSPResponse[] ocspResponseEncoded = unsignedCmsSignature.getOCSPResponses().toArray(new OCSPResponse[] {});

			String dataDigestAlgorithm = unsignedCmsSignature.getDataDigestAlgorithm();
			try
			{
				DERObjectIdentifier oid = new DERObjectIdentifier(dataDigestAlgorithm);
				dataDigestAlgorithm = OIDUtils.getName(oid);
			}
			catch(Exception e) {}
			PDFEnvelopedSignature signedotp7 = new PDFEnvelopedSignature(unsignedCmsSignature.getDigestAttribute(),
					unsignedCmsSignature.getSignatureCertificateInfo().toArray(new Certificate[] {}), crlList,
					ocspResponseEncoded, dataDigestAlgorithm,
					BouncyCastleProvider.PROVIDER_NAME, rawSignature, null,
					unsignedCmsSignature.getSignatureAlgorithm(), unsignedCmsSignature.getSigningTime());

			byte[] p7 = signedotp7.getEncodedPKCS7();
			TimestampingParameters tsParams = parameters.getTimeStampParams();
			if (tsParams != null) {
				// fetch timestamp and add it to p7
				CMSSignedDataWrapper cmsSignature = new CMSSignedDataWrapper(p7);
				PDFEnvelopedSignature.addTSToCMS(cmsSignature, tsParams.getTimeStampDigestAlgo(), tsParams.getTspClient());
				p7 = cmsSignature.getEncoded();
			}

			return signAfterPresignWithEncodedP7(original_pdf, out, tmpFile, p7, signerCert, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}

	//Use for large PDF
	public static SignReturn signAfterPresignWithRawSignature(String original_pdf_name, OutputStream out, File tmpFile, byte[] rawSignature, byte[] encodedUnsignedPkcs7, Certificate signerCert, PdfSignParameters parameters) throws SPIException {
		try {
			return signAfterPresignWithRawSignature(new PdfReader(new RandomAccessFileOrArray(original_pdf_name), null), out, tmpFile, rawSignature, encodedUnsignedPkcs7, signerCert, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}

	/****************** END signAfterPresignWithRawSignature METHODS ************************/


	/****************** BEGIN signAfterPresignWithEncodedP7 METHODS ************************/

	/**
	 * signAfterPresignWithEncodedP7
	 * Usage : call preSign + build and sign CMS using returned data as data to sign + send CMS-encoded bytes as encodedPkcs7 parameter to method signAfterPresignWithEncodedP7
	 * 
	 * tspToken, when provided, is already inside encodedPkcs7 and results from using parameters.getTimeStampParams()
	 */
	protected static SignReturn signAfterPresignWithEncodedP7(PdfSignatureAppearance sap, byte[] encodedPkcs7,
			PdfSignParameters parameters, TimestampToken tspToken) throws SPIException {

		SignReturn retour = null;
		log.debug(Channel.TECH, "Signing document with incoming CMS-encoded signature, using parameters %1$s",
				parameters);
		try {
			PdfDictionary dic2 = new PdfDictionary();

			// We re-compute the size that was allocated in the original pdf to
			// receive the PKCS#7, and compare it with actual pkcs#7 data size
			// TODO adapt to CRL size
			int content_size = CONTENT_SIZE;
			if (parameters != null) {
				if (parameters.getSignatureContainerSize() > 0)
					content_size = parameters.getSignatureContainerSize();
				int ts_size = TIMESTAMP_SIZE;
				if (parameters.getTimeStampContainerSize() > 0)
					ts_size = parameters.getTimeStampContainerSize();
				if (parameters.isAllocateTimeStampContainer() || parameters.getTimeStampParams() != null) {
					log.debug(Channel.TECH, "adding %1$s to content_size(%2$s) because of timestamping", ts_size,
							content_size);
					content_size += ts_size;
				}
			}
			byte out[] = new byte[content_size];
			log.debug(Channel.TECH, "adding P7 in PDF. Size in bytes is %1$s and signblock size is %2$s",
					encodedPkcs7.length, out.length);
			if (encodedPkcs7.length > out.length)
				throw new SPIException(
						"Signature size (%1$s) is bigger than expected (%2$s). Please change input estimated size or configuration default signblock size.",
						encodedPkcs7.length, out.length);

			System.arraycopy(encodedPkcs7, 0, out, 0, encodedPkcs7.length);

			dic2.put(PdfName.CONTENTS, new PdfString(out).setHexWriting(true));
			sap.close(dic2);
			CMSSignedDataWrapper p7 = new CMSSignedDataWrapper(encodedPkcs7);
			retour = new SignReturn(sap.getFieldName(), p7.getSignatureValue(), tspToken);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return retour;
	}
	
	protected static SignReturn signAfterPresignWithEncodedP7(PdfReader original_pdf, OutputStream out, File tmpFile, byte[] encodedPkcs7, Certificate certs, PdfSignParameters parameters) throws SPIException {
		return signAfterPresignWithEncodedP7(original_pdf, out, tmpFile, encodedPkcs7, certs, parameters, null);
	}
	
	protected static SignReturn signAfterPresignWithEncodedP7(PdfReader original_pdf, OutputStream out, File tmpFile, byte[] encodedPkcs7, Certificate signerCert, PdfSignParameters parameters, TimestampToken tspToken) throws SPIException {
		SignReturn retour = null;
		log.debug(Channel.TECH, "Signing document with incoming CMS-encoded signature, using parameters %1$s", parameters);
		try {
			//Parsing incoming encodedPkcs7
			CMSSignedDataWrapper p7 = new CMSSignedDataWrapper(encodedPkcs7);
			if(p7.getSigningTime()!=null) {
				Calendar cmsSigningTime = Calendar.getInstance();
				cmsSigningTime.setTime(p7.getSigningTime());
				log.debug(Channel.TECH, "Signing time found in CMS : %1$s", cmsSigningTime);
				if(parameters.getSigningTime()!=null) {
					if(!parameters.getSigningTime().equals(cmsSigningTime)) {
						log.debug(Channel.TECH, "Signing time found in CMS (%1$s) is different from signing time given as input parameter (%2$s). Input parameter will be used.", cmsSigningTime, parameters.getSigningTime());
					} else {
						log.debug(Channel.TECH, "Signing time found in CMS (%1$s) is identical to signing time given as input parameter (%2$s).", cmsSigningTime, parameters.getSigningTime());
					}
				} else {
					log.debug(Channel.TECH, "Using signing time found in CMS : %1$s", cmsSigningTime);
					parameters.setSigningTime(cmsSigningTime);
				}
			}
			
			PdfStamper stp = prepareSign(original_pdf, out, tmpFile, signerCert, parameters);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();

			retour = signAfterPresignWithEncodedP7(sap, encodedPkcs7, parameters, tspToken);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return retour;
	}
	
	public static SignReturn signAfterPresignWithEncodedP7(InputStream original_pdf, OutputStream out, byte[] encodedPkcs7, Certificate signerCert, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
		try {
			PdfReader reader = new PdfReader(original_pdf);
			return signAfterPresignWithEncodedP7(reader, out, null, encodedPkcs7, signerCert, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}

	// Use for large PDF
	public static SignReturn signAfterPresignWithEncodedP7(String original_pdf_name, OutputStream out, File tmpFile, byte[] encodedPkcs7, Certificate signerCert, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
		try {
			PdfReader reader = new PdfReader(new RandomAccessFileOrArray(original_pdf_name), null);
			return signAfterPresignWithEncodedP7(reader, out, tmpFile, encodedPkcs7, signerCert, parameters);
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}
	
	public static SignReturn signAfterPresignWithEncodedP7(PdfSignatureAppearance sap, byte[] encodedPkcs7, Certificate signerCert, CRL[] crls, OCSPResponse[] ocspResponseEncoded, PdfSignParameters parameters) throws SPIException {
        try {
            return signAfterPresignWithEncodedP7(sap, encodedPkcs7, parameters, null);
        } catch (Exception e) {
            ExceptionHandler.handle(e);
        }
        return null;
    }

	/****************** END signAfterPresignWithEncodedP7 METHODS ************************/

	/****************** BEGIN cms_sign METHODS ************************/
	/**
	 *  cms_sign :
	 *  adbe.pkcs7.detached signing for PDF, by providing data or digestData (=data digested with parameters.dataHashAlgorithm)
	 */

	public static SignResult cms_sign(byte[] digestData, PrivateKey priv, Certificate[] certChain, PdfSignParameters parameters, CRL[] crls, OCSPResponse[] ocspResponseEncoded) throws Exception {
		return cms_sign(null, null, digestData, priv, certChain, parameters, crls, ocspResponseEncoded);
	}
	
	public static SignResult cms_sign(byte[] digestData, String keyStoreFileName, String password, PdfSignParameters parameters, CRL[] crls, OCSPResponse[] ocspResponseEncoded) throws Exception {
		return cms_sign(null, digestData, keyStoreFileName, password, parameters, crls, ocspResponseEncoded);
	}
	
	public static SignResult cms_sign(String provider, InputStream data, PrivateKey priv, Certificate[] certChain,
			PdfSignParameters parameters, CRL[] crls, OCSPResponse[] ocspResponseEncoded) throws Exception {
		return cms_sign(provider, data, null, priv, certChain, parameters, crls, ocspResponseEncoded);
	}

	public static SignResult cms_sign(InputStream data, String keyStoreFileName, String password,
			PdfSignParameters parameters, CRL[] crls, OCSPResponse[] ocspResponseEncoded) throws Exception {
		return cms_sign(data, null, keyStoreFileName, password, parameters, crls, ocspResponseEncoded);
	}

	private static SignResult cms_sign(InputStream data, byte[] digestData, String keyStoreFileName, String password,
			PdfSignParameters parameters, CRL[] crls, OCSPResponse[] ocspResponseEncoded) throws Exception {
		KeyStore ks = KeyStore.getInstance("pkcs12");
		ks.load(new FileInputStream(keyStoreFileName), password.toCharArray());
		String ALIAS = (String) ks.aliases().nextElement();

		java.security.cert.Certificate[] certChain = ks.getCertificateChain(ALIAS);
		PrivateKey priv = (PrivateKey) (ks.getKey(ALIAS, password.toCharArray()));
		return cms_sign(null, data, digestData, priv, certChain, parameters, crls, ocspResponseEncoded);
	}
	
	private static SignResult cms_sign(String provider, InputStream data, byte[] digestData, PrivateKey priv,
			Certificate[] certChain, PdfSignParameters parameters, CRL[] crls, OCSPResponse[] ocspResponseEncoded)
			throws Exception {
		IOCSPClient ocspClient = parameters.ocspClient;
		TimestampingParameters timeStampParams = parameters.getTimeStampParams();
		ITspClient tspClient = timeStampParams != null ? timeStampParams.getTspClient() : null; 
			
		Collection<OCSPResponse> ocspResponses = new ArrayList<OCSPResponse>();
		List<OCSPParameters> ocspParamsList = parameters.getOCSPParams();
		if (ocspResponseEncoded != null)
			ocspResponses = Arrays.asList(ocspResponseEncoded);
		else if (ocspParamsList != null) 
		{
			for (OCSPParameters ocspParams : ocspParamsList) {
				log.debug(Channel.TECH, "Requests a new OCSP Response");
				BasicOCSPResp status = parameters.ocspClient.getStatus((X509Certificate) ocspParams.getTargetCertificate(), 
						(X509Certificate) ocspParams.getIssuerCertificate());
				ocspResponses.add(new OCSPResponse(status));
				/*
				  OCSPResponder ocspResponder =
				  ocspResponderManager.getOCSPResponder
				  (ocspParams.getOcspResponderId()); OCSPResponse
				  ocspResponseFresh =
				  ocspResponder.getOCSPResponse(ocspParams.getTargetCertificate
				  (), ocspParams.getIssuerCertificate());
				  ocspResponses.add(ocspResponseFresh);
				 */
				
			}
		}
		String dataHashAlgorithm = parameters.getDataHashAlgorithm();
		String digestAlgOID = AlgorithmID.valueOfTag(dataHashAlgorithm).getOID();
		byte[] encodedPkcs7 = null;
		PAdESParameters padesParameters = parameters.getPadesParameters();
		boolean isPAdesEnhancedLevel = padesParameters != null ? 
				padesParameters.isPadesEnhancedLevel() : false;
		CMSGenerator generator = null;
		
		Certificate signatureCertificate = certChain[0];
		List<Certificate> certStore = certChain != null ? Arrays.asList(certChain) : null;
		List<java.security.cert.CRL> signedCrls = crls != null ? Arrays.asList(crls) : null;
		if (isPAdesEnhancedLevel) {
			generator = new CMSForPAdESEnhancedGenerator(provider, signatureCertificate, priv,
					certStore, digestAlgOID,
					signedCrls, ocspResponses);
			CMSForPAdESEnhancedGenerator padesGenerator = (CMSForPAdESEnhancedGenerator) generator;
			padesGenerator.setPolicyIdentifierParams(padesParameters.getPolicyIdentifierParams());
			padesGenerator.setClaimedAttribute(padesParameters.getClaimedAttributesOID(),
					padesParameters.getClaimedAttributes());
			if (padesParameters.getCertifiedAttribute() != null)
				padesGenerator.setCertifiedAttribute(padesParameters.getCertifiedAttribute().getEncoded());
			// FIXME : if commitment-type and no signature-policy-identifier,
			// implicitly set commitment-type in reason entry ?
			if (padesParameters.getCommitmentTypeId() != null)
				padesGenerator.setCommitmentTypeId(padesParameters.getCommitmentTypeId());
			TimestampingParameters contentTimeStampParams = padesParameters.getContentTimeStampParams();
			if (contentTimeStampParams != null) {
				if (data != null) {					
					
					byte[] digest = DigestHelper.getDigest(data, dataHashAlgorithm);
					ITspClient tspClient2 = contentTimeStampParams.tspClient;
					byte[] tsp = tspClient2.getRawTsp(digest, dataHashAlgorithm);
					TimeStampResponse response = new TimeStampResponse(tsp);
					padesGenerator.setContentTimeStamp(response.getTimeStampToken().getEncoded());

					digestData = digest;
					data = null;
				} // FIXME : implement else
			}
		} else {
			Date signingTime = parameters.getSigningTime().getTime();
			generator = new CMSForPAdESBasicGenerator(provider, signatureCertificate, priv,
					certStore, signingTime, digestAlgOID, signedCrls, ocspResponses);
		}
		if (data != null) {
			encodedPkcs7 = generator.signContent(data, false);
		} else {
			encodedPkcs7 = generator.signReference(digestData);
		}

		if (tspClient == null)
			return new SignResult(encodedPkcs7, null);
		
		TimestampingParameters tsParams = timeStampParams;

		CMSSignedDataWrapper cmsSignature = new CMSSignedDataWrapper(encodedPkcs7);
		PDFEnvelopedSignature.addTSToCMS(cmsSignature, tsParams.getTimeStampDigestAlgo(), tspClient);
		return new SignResult(cmsSignature.getEncoded(), null);
	}
	
	/****************** END cms_sign METHODS ************************/

	public static CMSSignedDataWrapper cms_sign(String digestAlgo, byte[] digest, PrivateKey priv,
			Certificate[] certChain, PdfSignParameters parameters, CRL[] crls, OCSPResponse[] ocspResponseEncoded)
			throws Exception {
		IOCSPClient ocspClient = parameters.ocspClient;
		TimestampingParameters timeStampParams = parameters.getTimeStampParams();
		ITspClient tspClient = timeStampParams != null ? timeStampParams.getTspClient() : null;

		Collection<OCSPResponse> ocspResponses = new ArrayList<OCSPResponse>();
		List<OCSPParameters> ocspParamsList = parameters.getOCSPParams();
		if (ocspResponseEncoded != null)
			ocspResponses = Arrays.asList(ocspResponseEncoded);
		else if (ocspParamsList != null) {
			for (OCSPParameters ocspParams : ocspParamsList) {
				log.debug(Channel.TECH, "Requests a new OCSP Response");
				BasicOCSPResp status = parameters.ocspClient.getStatus(
						(X509Certificate) ocspParams.getTargetCertificate(),
						(X509Certificate) ocspParams.getIssuerCertificate());
				ocspResponses.add(new OCSPResponse(status));
			}
		}
		String dataHashAlgorithm = parameters.getDataHashAlgorithm();
		String digestAlgOID = AlgorithmID.valueOfTag(dataHashAlgorithm).getOID();
		byte[] encodedPkcs7 = null;
		PAdESParameters padesParameters = parameters.getPadesParameters();
		boolean isPAdesEnhancedLevel = padesParameters != null ? padesParameters.isPadesEnhancedLevel() : false;
		CMSGenerator generator = null;

		Certificate signatureCertificate = certChain[0];
		List<Certificate> certStore = certChain != null ? Arrays.asList(certChain) : null;
		List<java.security.cert.CRL> signedCrls = crls != null ? Arrays.asList(crls) : null;
		
		if (isPAdesEnhancedLevel) {
			generator = new CMSForPAdESEnhancedGenerator(null, signatureCertificate, priv, certStore, digestAlgOID,
					signedCrls, ocspResponses);
			CMSForPAdESEnhancedGenerator padesGenerator = (CMSForPAdESEnhancedGenerator) generator;
			padesGenerator.setPolicyIdentifierParams(padesParameters.getPolicyIdentifierParams());
			padesGenerator.setClaimedAttribute(padesParameters.getClaimedAttributesOID(),
					padesParameters.getClaimedAttributes());
			if (padesParameters.getCertifiedAttribute() != null)
				padesGenerator.setCertifiedAttribute(padesParameters.getCertifiedAttribute().getEncoded());
			// FIXME : if commitment-type and no signature-policy-identifier,
			// implicitly set commitment-type in reason entry ?
			if (padesParameters.getCommitmentTypeId() != null)
				padesGenerator.setCommitmentTypeId(padesParameters.getCommitmentTypeId());
			TimestampingParameters contentTimeStampParams = padesParameters.getContentTimeStampParams();
			if (contentTimeStampParams != null) {
				ITspClient tspClient2 = contentTimeStampParams.tspClient;
				byte[] tsp = tspClient2.getRawTsp(digest, dataHashAlgorithm);
				TimeStampResponse response = new TimeStampResponse(tsp);
				padesGenerator.setContentTimeStamp(response.getTimeStampToken().getEncoded());

			}
		} else {
			Date signingTime = parameters.getSigningTime().getTime();
			generator = new CMSForPAdESBasicGenerator(null, signatureCertificate, priv, certStore, signingTime,
					digestAlgOID, signedCrls, ocspResponses);
		}
		encodedPkcs7 = generator.signReference(digest);

		CMSSignedDataWrapper cmsSignature = new CMSSignedDataWrapper(encodedPkcs7);
		if (tspClient == null)
			return cmsSignature;

		TimestampingParameters tsParams = timeStampParams;

		PDFEnvelopedSignature.addTSToCMS(cmsSignature, tsParams.getTimeStampDigestAlgo(), tspClient);
		return cmsSignature;
	}
	
	/****************** BEGIN LTV Timestamp METHODS ************************/
	
	//FIXME : other addLTVTimestamp methods (as many as sign methods ?)
	public static SignReturn addLTVTimestamp(InputStream fileInputStream, OutputStream fileOutputStream, 
			TimestampingParameters timestampingParameters) throws SPIException {
		try {
			PdfReader reader = new PdfReader(fileInputStream);
			PdfStamper stp = prepareDocTimeStamp(reader, fileOutputStream, null, timestampingParameters);
			PdfSignatureAppearance sap = stp.getSignatureAppearance();
			
			/*
		   	TimeStampProcessor timeStampProcessor = TimeStampProcessorFactory.getInstance().
   			getTimeStampProcessor(timestampingParameters.getTimeStampServerURL(), timestampingParameters.getTimeStampPolicyOID(), timestampingParameters.getTimeStampDigestAlgo(), true);
		   	byte[] tsResponse = timeStampProcessor.timestamp(sap.getRangeStream());
		   	
		   	TimestampToken timestampToken = TimestampTokenManagerFactory.getInstance(BouncyCastleProvider.PROVIDER_NAME).getTimeStampToken(tsResponse);
		   	*/
			ITspClient tspClient = timestampingParameters.getTspClient();
			String digestAlgo = timestampingParameters.getTimeStampDigestAlgo();
			byte [] digest = DigestHelper.getDigest(sap.getRangeStream(), digestAlgo);
			byte[] tsp = tspClient.getRawTsp(digest, digestAlgo);
			TimeStampResponse response = new TimeStampResponse(tsp);
			tsp = response.getTimeStampToken().getEncoded();
			return signAfterPresignWithEncodedP7(sap, tsp, null, null);
			
		} catch (Exception e) {
			ExceptionHandler.handle(e);
		}
		return null;
	}
	
	/****************** END LTV Timestamp METHODS ************************/

	/****************** BEGIN LTV DSS METHODS 
	 * @throws SPIException ************************/
	
	//Adds a LTV DocumentSecurityStore dictionary
	public static void addLTVDSS(InputStream fileInputStream, OutputStream fileOutputStream, List<Certificate> certsList, List<CRL> crlsList, List<OCSPResponse> ocspsList) throws SPIException {
		addLTVDSSWithVRI(fileInputStream, fileOutputStream, certsList, crlsList, ocspsList, null);
	}

	// Adds a LTV DocumentSecurityStore dictionary including VRI dictionaries if requested using vriClrs or vriOCSPs lists
	// All clrs or ocsps in VRI lists will also be added to the main DSS lists
	// Caller should make sure that provided CRLs or OCSPs are not already in the signatures' P7 data
	public static void addLTVDSSWithVRI(InputStream fileInputStream, OutputStream fileOutputStream, List<Certificate> certsList, List<CRL> crlsList, List<OCSPResponse> ocspsList, List<VRIData> vriData) throws SPIException {
		try {
			PdfReader reader = new PdfReader(fileInputStream);
			PdfStamper stp = new PdfStamper(reader, fileOutputStream, '\0', true);
			PdfWriter writer = stp.getWriter();
			AcroFields af = reader.getAcroFields();
	        PdfDictionary catalog = reader.getCatalog();
	        stp.markUsed(catalog);
	
	        PdfDictionary dss = new PdfDictionary();
	        PdfArray dssCerts = new PdfArray();
	        PdfArray dssCrls = new PdfArray();
	        PdfArray dssOcsps = new PdfArray();
	        if(vriData!=null) {
	            PdfDictionary vrim = new PdfDictionary();
		        for (VRIData vriDat : vriData) {
		            PdfArray vriCert = new PdfArray();
		            PdfArray vriCrl = new PdfArray();
		            PdfArray vriOcsp = new PdfArray();
		            PdfDictionary vri = new PdfDictionary();
		            if(vriDat.certsList!=null) {
			            for (Certificate certObject : vriDat.certsList) {
			            	addIndirectBytesToArrays(writer, ((X509Certificate) certObject).getEncoded(), vriCert, dssCerts);
			            }
		            }
		            if(vriDat.crlsList!=null) {
			            for (CRL crlObject : vriDat.crlsList) {
			            	addIndirectBytesToArrays(writer, ((X509CRL) crlObject).getEncoded(), vriCrl, dssCrls);
			            }
		            }
		            if(vriDat.ocspsList!=null) {
			            for (OCSPResponse ocspObject : vriDat.ocspsList) {
			            	addIndirectBytesToArrays(writer, ocspObject.getEncoded(), vriOcsp, dssOcsps);
			            }
		            }
		            if (vriCert.size() > 0)
		                vri.put(PdfName.CERT, addObjectAsIndirectRef(writer, vriCert));
		            if (vriCrl.size() > 0)
		                vri.put(CRL, addObjectAsIndirectRef(writer, vriCrl));
		            if (vriOcsp.size() > 0)
		                vri.put(OCSP, addObjectAsIndirectRef(writer, vriOcsp));
		            vrim.put(getVRIKey(af.getSignatureDictionary(vriDat.signatureName)), addObjectAsIndirectRef(writer, vri));
		            // Not TU or TS because "not recommended" by ETSI TS 102 778-4 V1.1.2
		        }
		        dss.put(VRI, addObjectAsIndirectRef(writer, vrim));
	        }
	
	        if(certsList!=null) {
	        	for (Certificate certObject : certsList) {
	        		addIndirectBytesToArrays(writer, ((X509Certificate) certObject).getEncoded(), dssCerts);
		        }
	        }
	        if(crlsList!=null) {
	        	for (CRL crlObject : crlsList) {
	        		addIndirectBytesToArrays(writer, ((X509CRL) crlObject).getEncoded(), dssCrls);
		        }
	        }
	        if(ocspsList!=null) {
		        for (OCSPResponse ocspObject : ocspsList) {
		        	addIndirectBytesToArrays(writer, ocspObject.getEncoded(), dssOcsps);
		        }
	        }
	
	        if (dssCerts.size() > 0)
	            dss.put(CERTS, addObjectAsIndirectRef(writer, dssCerts));
	        if (dssCrls.size() > 0)
	            dss.put(CRLS, addObjectAsIndirectRef(writer, dssCrls));
	        if (dssOcsps.size() > 0)
	            dss.put(OCSPS, addObjectAsIndirectRef(writer, dssOcsps));
	        catalog.put(DSS, addObjectAsIndirectRef(writer, dss));
	        
	        stp.close();
		} catch(Exception e) {
			ExceptionHandler.handle(e);
		}
	}

	private static void addIndirectBytesToArrays(PdfWriter writer, byte[] bytes, PdfArray... arrays) throws IOException {
		PdfStream ps = new PdfStream(bytes);
        ps.flateCompress();
        PdfIndirectReference iref = addObjectAsIndirectRef(writer, ps);
        for(PdfArray array : arrays) {
        	array.add(iref);
        }
	}

	private static PdfIndirectReference addObjectAsIndirectRef(PdfWriter writer, PdfObject object) throws IOException {
		return writer.addToBody(object, false).getIndirectReference();
	}
	//The key of each entry in [the VRI] dictionary is the base-16-encoded (uppercase) SHA1 digest of the signature to which it applies
	//For a Time-stamp's signature [the signature to digest] is the bytes of the Time-stamp itself since the Time-stamp token is a signed data object
    protected static PdfName getVRIKey(PdfDictionary dic) throws SPIException {
        try {
        	PdfString contents = dic.getAsString(PdfName.CONTENTS);
	        byte[] sigContent = contents.getOriginalBytes();
	        if (PdfName.ETSI_RFC3161.equals(PdfReader.getPdfObject(dic.get(PdfName.SUBFILTER)))) {
	            sigContent = getSigContentForTS(sigContent);
	        }
	        return getVRIKey(sigContent);
        } catch(Exception e) {
        	ExceptionHandler.handle(e);
        }
        return null;
    }
    protected static byte[] getSigContentForTS(byte[] sigContent) throws Exception {
    	//FIXME : find which version should be used
    	return sigContent;
//    	ASN1InputStream din = new ASN1InputStream(new ByteArrayInputStream(sigContent));
//        DERObject pkcs = din.readObject();
//        return pkcs.getEncoded();
    }
    
    protected static PdfName getVRIKey(byte[] sigContent) throws SPIException {
        try {
	        byte[] sigContentDigest = DigestHelper.getDigest(sigContent, "SHA1");
	        return new PdfName(new String(Hex.encode(sigContentDigest)).toUpperCase());
        } catch(Exception e) {
        	ExceptionHandler.handle(e);
        }
        return null;
    }

    public static class VRIData {
		protected String signatureName;
		protected List<Certificate> certsList = new ArrayList<Certificate>();
		protected List<CRL> crlsList = new ArrayList<CRL>();
		protected List<OCSPResponse> ocspsList = new ArrayList<OCSPResponse>();
		public VRIData(String signatureName, List<Certificate> certsList, List<CRL> crlsList, List<OCSPResponse> ocspsList) {
			this.signatureName = signatureName;
			this.certsList = certsList;
			this.crlsList = crlsList;
			this.ocspsList = ocspsList;
		}
		public void addCertificate(Certificate cert) {
			certsList.add(cert);
		}
		public void addCRL(CRL crl) {
			crlsList.add(crl);
		}
		public void addOCSP(OCSPResponse ocsp) {
			ocspsList.add(ocsp);
		}
	}

    public static class VRIValidationData {
		protected PdfName signatureVRIKey;
		protected List<CertificateWithRevision> certsList = new ArrayList<CertificateWithRevision>();
		protected List<CRLWithRevision> crlsList = new ArrayList<CRLWithRevision>();
		protected List<OCSPResponseWithRevision> ocspsList = new ArrayList<OCSPResponseWithRevision>();
		protected VRIValidationData(PdfName signatureVRIKey) {
			this.signatureVRIKey = signatureVRIKey;
		}
		public void setCertificates(List<CertificateWithRevision> certsList) {
			this.certsList = certsList;
		}
		protected void setCRLs(List<CRLWithRevision> crlsList) {
			this.crlsList = crlsList;
		}
		protected void setOCSPs(List<OCSPResponseWithRevision> ocspsList) {
			this.ocspsList = ocspsList;
		}
		public List<CertificateWithRevision> getCertsList() {
			return certsList;
		}
		public List<CRLWithRevision> getCrlsList() {
			return crlsList;
		}
		public List<OCSPResponseWithRevision> getOcspsList() {
			return ocspsList;
		}
	}

	public static class ValidationData {
		protected List<CertificateWithRevision> certsList = new ArrayList<CertificateWithRevision>();
		protected List<CRLWithRevision> crlsList = new ArrayList<CRLWithRevision>();
		protected List<OCSPResponseWithRevision> ocspsList = new ArrayList<OCSPResponseWithRevision>();
		protected Map<PdfName, VRIValidationData> vriList = new HashMap<PdfName, VRIValidationData>();
		protected ValidationData(){}
		public void setCertificates(List<CertificateWithRevision> certsList) {
			this.certsList = certsList;
		}
		protected void setCRLs(List<CRLWithRevision> crlsList) {
			this.crlsList = crlsList;
		}
		protected void setOCSPs(List<OCSPResponseWithRevision> ocspsList) {
			this.ocspsList = ocspsList;
		}
		protected void addVRI(VRIValidationData vri) {
			vriList.put(vri.signatureVRIKey, vri);
		}
		public List<CertificateWithRevision> getCertsList() {
			return certsList;
		}
		public List<CRLWithRevision> getCrlsList() {
			return crlsList;
		}
		public List<OCSPResponseWithRevision> getOcspsList() {
			return ocspsList;
		}
		public VRIValidationData getVriData(PDFEnvelopedSignature signature) throws SPIException {
			byte[] sigContent = signature.getCONTENTSContent();
			try {
				if(signature.getDocTimeStampValue()!=null) {
		            sigContent = getSigContentForTS(sigContent);
		        }
	        } catch(Exception e) {
	        	ExceptionHandler.handle(e);
	        }
			return vriList.get(getVRIKey(sigContent));
		}
	}

	public static interface ObjectWithRevision {
		public int getRevision();
	}
	
	public static interface ObjectWithRevisionAbstractFactory<ConcreteObjectWithRevision extends ObjectWithRevision> {
		public ConcreteObjectWithRevision createObjectWithRevision(byte[] octets, int revision) throws Exception;
	}

	public static class CertificateWithRevisionFactory implements ObjectWithRevisionAbstractFactory<CertificateWithRevision> {
		public CertificateWithRevision createObjectWithRevision(byte[] octets, int revision) throws Exception {
			Certificate cert = CertificateHelper.getCertificate(octets);
			log.debug(Channel.TECH, "certificate found in dictionary");
			return new CertificateWithRevision(cert, revision);
		}
	}

	public static class CRLWithRevisionFactory implements ObjectWithRevisionAbstractFactory<CRLWithRevision> {
		public CRLWithRevision createObjectWithRevision(byte[] octets, int revision) throws Exception {
			CRL crl = CRLHelper.getCRL(octets);
			log.debug(Channel.TECH, "CRL found in dictionary");
			return new CRLWithRevision(crl, revision);
		}
	}

	public static class OCSPResponseWithRevisionFactory implements ObjectWithRevisionAbstractFactory<OCSPResponseWithRevision> {
		public OCSPResponseWithRevision createObjectWithRevision(byte[] octets, int revision) throws Exception {
			//OCSPResponse ocsp = OCSPResponseFactory.getInstance().getOCSPResponse(octets);
			OCSPResponse ocsp = new OCSPResponse(octets);
			log.debug(Channel.TECH, "OCSP response found in dictionary");
			return new OCSPResponseWithRevision(ocsp, revision);
		}
	}

	public static class CertificateWithRevision implements ObjectWithRevision {
		private Certificate cert;
		private int revision;
		public int getRevision() {
			return revision;
		}
		public Certificate getCertificate() {
			return cert;
		}
		public CertificateWithRevision(Certificate cert, int revision) {
			this.cert = cert;
			this.revision = revision;
		}
	}
	
	public static class CRLWithRevision implements ObjectWithRevision {
		private CRL crl;
		private int revision;
		public int getRevision() {
			return revision;
		}
		public CRL getCRL() {
			return crl;
		}
		public CRLWithRevision(CRL crl, int revision) {
			this.crl = crl;
			this.revision = revision;
		}
	}

	public static class OCSPResponseWithRevision implements ObjectWithRevision {
		private OCSPResponse ocspR;
		private int revision;
		public int getRevision() {
			return revision;
		}
		public OCSPResponse getOCSPResponse() {
			return ocspR;
		}
		public OCSPResponseWithRevision(OCSPResponse ocspR, int revision) {
			this.ocspR = ocspR;
			this.revision = revision;
		}
	}

	/****************** END LTV DSS METHODS ************************/

	//FIXME : avoid copies between prepareDocTimeStamp & prepareSign
	protected static PdfStamper prepareDocTimeStamp(PdfReader reader, OutputStream fout, File tmpFile, TimestampingParameters timestampingParameters) throws Exception {
		PdfStamper stp = PdfStamper.createSignature(reader, fout, '\0', tmpFile, true);
		stp.addDeveloperExtension(new PdfDeveloperExtension(new PdfName("ESIC"), PdfWriter.PDF_VERSION_1_7, 1));
		
		PdfSignatureAppearance sap = stp.getSignatureAppearance();

		sap.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);

		PdfDictionary dic = new PdfDictionary();
		dic.put(PdfName.TYPE, DOCTIMESTAMP); 
		dic.put(PdfName.FILTER, PdfSignatureAppearance.WINCER_SIGNED);
		dic.put(PdfName.SUBFILTER, PdfName.ETSI_RFC3161);

			PdfDictionary buildDic = new PdfDictionary();
				PdfDictionary buildDataDic = new PdfDictionary();
				buildDataDic.put(new PdfName("Name"), PdfSignatureAppearance.WINCER_SIGNED);
			buildDic.put(new PdfName("Filter"), buildDataDic);
				buildDataDic = new PdfDictionary();
				buildDataDic.put(new PdfName("Name"), new PdfName(PRODUCED_BY));
			buildDic.put(new PdfName("App"), buildDataDic);
		dic.put(new PdfName("Prop_Build"), buildDic);

		sap.setCryptoDictionary(dic);
		LinkedHashMap exc = new LinkedHashMap();
		//TODO implement content size calculation base on CRL size (and OCSP response size)
		int content_size = CONTENT_SIZE;

		int hexblock_size = content_size*2+2;
		log.debug(Channel.TECH, "Prepared signing with content_size=%1$s bytes (%2$s real bytes once hex-encoded)", content_size, hexblock_size);
		exc.put(PdfName.CONTENTS, new Integer(hexblock_size));
		sap.preClose(exc);
		
		if(log.isDebugEnabled(Channel.TECH)) {
			log.debug(Channel.TECH, "PDF Prepared for signature. ByteRange is %1$s", Arrays.toString(sap.getRange()));
		}

		return stp;
	}
	
	protected static PdfStamper prepareSign(PdfReader reader, OutputStream fout, File tmpFile, Certificate signerCert, PdfSignParameters parameters) throws Exception {
		//FIXME : check that this new signature won't break existing certification signatures (with DocMDP transform)
		
		Calendar presignDate = parameters.getSigningTime();
		
		// '\0' means we keep the same Acrobat version as the one in incoming
		// file (Acrobat 7 -> Acrobat 7, Acrobat 8 -> Acrobat 8, etc)
		// first null is because we're not going to create an output file in
		// this method
		// second null means signature will be created in memory, not in a temporary file
		//TODO : force version to 1.7 when PAdES enhanced or LTV ? Doesn't it break existing signatures ? Adobe Pro X doesn't change PDF version, and produces documents with for instance PdfVersion=1.4 and extension.BaseVersion=1.7 ...
		PdfStamper stp = PdfStamper.createSignature(reader, fout, '\0', tmpFile, parameters.isCreateNewRevision());
		
		boolean isPadesEnhancedLevel = false;
		// PAdES v3 : extension dictionary
		PAdESParameters padesParams = parameters.getPadesParameters();
		isPadesEnhancedLevel = padesParams!=null && padesParams.isPadesEnhancedLevel();
		if(isPadesEnhancedLevel)
			stp.addDeveloperExtension(new PdfDeveloperExtension(new PdfName("ESIC"), PdfWriter.PDF_VERSION_1_7, 2));
		// Adobe Pro X seems to add <</ADBE<</BaseVersion/1.7/ExtensionLevel 8>>>>
		
		PdfSignatureAppearance sap = stp.getSignatureAppearance();
		String signatureName = parameters.getSignatureName();
		
		if(signatureName != null && signatureName.length() == 0) 
			signatureName = null;
		
		if(signatureName!=null) {
			if(!parameters.isSignatureAlreadyExists() && reader.getAcroFields().getField(signatureName)!=null) 
				throw new SPIIllegalDataException("A PDF field with the same name (%1$s) already exists in the document", signatureName);
			sap.setFieldName(signatureName);
		}

		if (parameters.isSignatureAlreadyExists()) {
			//FIXME : check that the new signature conforms to 'seed values' for this field
			if(signatureName==null) throw new SPIIllegalDataException("Already existing signatures cannot have empty signature names");

			AcroFields af = reader.getAcroFields();
	        AcroFields.Item item = af.getFieldItem(signatureName);
	        if (item == null) throw new SPIIllegalDataException("The field %1$s does not exist.",signatureName);
	        PdfDictionary merged = (PdfDictionary)item.getMerged(0);
	        if(merged.get(PdfName.V)!=null) throw new SPIIllegalDataException("The field %1$s is not empty.",signatureName);
	        
	        sap.setVisibleSignature(signatureName);
		}		
		sap.setCertificationLevel(parameters.getCertifLevel());
		if (parameters.isVisible()) { // This means SignatureLayoutParameters is not null
			log.debug(Channel.TECH, "Visible signature");
			SignatureLayoutParameters signatureLayoutParameters = parameters.getSignatureLayoutParameters();
			
			if (!parameters.isSignatureAlreadyExists()) {
				// bottom left point
				float x1 = signatureLayoutParameters.getX1();
				float y1 = signatureLayoutParameters.getY1();
				// upper right
				float x2 = signatureLayoutParameters.getX2();
				float y2 = signatureLayoutParameters.getY2();
				
				int pageNbr = signatureLayoutParameters.getPageNbr();
				if (reader.getNumberOfPages() < pageNbr || pageNbr <= 0)
					throw new SPIIllegalDataException("Invalid page number: %1$s", pageNbr);


				// check that the signature rectangle is contained in the page
				Rectangle pageRectangle = reader.getPageSizeWithRotation(pageNbr);
				float pgX1 = pageRectangle.getLeft();
				float pgX2 = pageRectangle.getRight();
				float pgY1 = pageRectangle.getBottom();
				float pgY2 = pageRectangle.getTop();
				
				if (pgX1 > x1 || pgX2 < x2 || pgY1 > y1 || pgY2 < y2)
					throw new SPIIllegalDataException(
							"Given signature rectangle (left=%1$s,right=%2$s,bottom=%3$s,top=%4$s) doesn't fit into page rectangle: (left=%5$s,right=%6$s,bottom=%7$s,top=%8$s)",
							x1, x2, y1, y2, pgX1, pgX2, pgY1, pgY2);

				sap.setVisibleSignature(new Rectangle(x1, y1, x2, y2), pageNbr, signatureName);
			}
			
			String description = signatureLayoutParameters.getDescription();
			if (description != null) sap.setLayer2Text(description);
			else if(signerCert==null) throw new SPIIllegalArgumentException("No description and no signer certificate provided. Default description cannot be created.");
			
			sap.setRunDirection(signatureLayoutParameters.getRunDirection());

			byte[] backgroundImage = signatureLayoutParameters.getBackgroundImage();
			if(backgroundImage!=null) {
				sap.setImage(Image.getInstance(backgroundImage));
				sap.setImageScale(signatureLayoutParameters.getBackgroundImageScale());
			}
			
			int sigRenderMode = signatureLayoutParameters.getSigRenderMode();
			byte[] signatureImage = null;
			if(sigRenderMode==PdfSignatureAppearance.SignatureRenderGraphicAndDescription) {
				signatureImage = signatureLayoutParameters.getSignatureImage();
				if(signatureImage!=null) {
					sap.setSignatureGraphic(Image.getInstance(signatureImage));
				} else throw new SPIIllegalDataException("Cannot use graphic+description signature render mode without providing a graphic");
			} else if(sigRenderMode==PdfSignatureAppearance.SignatureRenderNameAndDescription) {
				if(signerCert==null) throw new SPIIllegalArgumentException("Cannot use name+description signature render mode without providing the signer certificate");
			}
			sap.setAcro6Layers(true);
			sap.setRender(sigRenderMode);
			

			int fontFamily = signatureLayoutParameters.getFontFamily();
			int fontStyle = signatureLayoutParameters.getFontStyle();
			float fontSize= signatureLayoutParameters.getFontSize();
			Color fontColor = signatureLayoutParameters.getFontColor();
			if(parameters.isKeepPDFACompliance()) {
				// Test if images with transparency are used, which would break PDF/A compliance
				if(backgroundImage!=null) {
					BufferedImage bi = ImageIO.read(new ByteArrayInputStream(backgroundImage));
					if(bi.getTransparency()!=Transparency.OPAQUE) throw new SPIIllegalArgumentException("Cannot use background image with transparency when trying to keep PDF/A compliance");
				}
				if(signatureImage!=null) {
					BufferedImage bi = ImageIO.read(new ByteArrayInputStream(signatureImage));
					if(bi.getTransparency()!=Transparency.OPAQUE) throw new SPIIllegalArgumentException("Cannot use signature image with transparency when trying to keep PDF/A compliance");
				}
				
				// Embed a look-alike font
				//TODO : see if we could reuse an embedded font instead of a replacement (embedded fully OR with all the characters we need), see PDFFontHelper
				String replacementFont = "dejavusans"; // fontFamily==Font.HELVETICA
		    	if(fontFamily==Font.COURIER) replacementFont = "dejavusansmono";
		    	else if(fontFamily==Font.TIMES_ROMAN) replacementFont = "dejavuserif";
				//TODO : no 'SYMBOL' or 'ZAPFDINGBATS' replacement, using 'dejavusans'
		    	
		    	/*for (String f : (Set<String>)FontFactory.getRegisteredFonts()) {
		            System.out.println("registered font : "+f);;
		        }*/
		    	Font font = FontFactory.getFont(replacementFont, BaseFont.CP1252, BaseFont.EMBEDDED, fontSize, fontStyle, fontColor);
		    	sap.setLayer2Font(font);
			} else {
				sap.setLayer2Font(new Font(fontFamily,fontSize,fontStyle, fontColor));
			}
		} else {
			log.debug(Channel.TECH, "Invisible signature");
		}

		// seems only useful for visible signatures when no layer2Text (description) has been set. And in this case only certs is used
		sap.setCrypto(null, new Certificate[] {signerCert}, null, null);

		String reason = parameters.getReason();
		String location = parameters.getLocation();
		String contact = parameters.getContact();
		PdfDictionary dic = new PdfDictionary();
		dic.put(PdfName.FT, PdfName.SIG);
		dic.put(PdfName.FILTER, parameters.getFilter());
		if(isPadesEnhancedLevel) dic.put(PdfName.SUBFILTER, new PdfName(PDFEnvelopedSignature.SF_ETSI_CADES_DETACHED));
		else dic.put(PdfName.SUBFILTER, PdfName.ADBE_PKCS7_DETACHED);
		dic.put(PdfName.M, new PdfDate(presignDate));
		// We do not add a dic.put(PdfName.NAME, "XXX")) because it should only
		// be used when "it is not possible to extract the name from the
		// signature" (PDF reference), which is not the case here
		//if (!StringHelper.isNullOrEmpty(location))
		if (location != null && location.length() > 0)
			dic.put(PdfName.LOCATION, new PdfString(location, PdfObject.TEXT_UNICODE)); // sap.setLocation doesn't work if a criptodictionary is specified
		if (reason != null && reason.length() > 0)
			dic.put(PdfName.REASON, new PdfString(reason, PdfObject.TEXT_UNICODE)); // sap.setReason doesn't work if a criptodictionary is specified
		if (contact != null && contact.length() > 0)
			dic.put(PdfName.CONTACTINFO, new PdfString(contact, PdfObject.TEXT_UNICODE)); // sap.setContact doesn't work if a criptodictionary is specified

			PdfDictionary buildDic = new PdfDictionary();
				PdfDictionary buildDataDic = new PdfDictionary();
				buildDataDic.put(new PdfName("Name"), parameters.getFilter());
			buildDic.put(new PdfName("Filter"), buildDataDic);
				buildDataDic = new PdfDictionary();
				buildDataDic.put(new PdfName("Name"), new PdfName(PRODUCED_BY));
				//TODO : see if version can be retrieved from com.opentrust.spi.securityserver.install.ProductInfo
				//TODO : see if we can also add SPI platform ID
				//buildDataDic.put(new PdfName("REx"), new PdfString("2.2.1", PdfObject.TEXT_UNICODE));
			buildDic.put(new PdfName("App"), buildDataDic);
		dic.put(new PdfName("Prop_Build"), buildDic);

		
		if (parameters.getCertifLevel() > 0) {
			// By changing TRANSFORMMETHOD parameters and the transformparams
			// dictionary, it is possible to sign parts only of the document.
			// See TransformMethod = DocMDP, UR, FieldMDP or Identity in PDF reference
			// we only use DocMDP for now

			PdfDictionary transformParams = new PdfDictionary();
			transformParams.put(PdfName.P, new PdfNumber(parameters.getCertifLevel()));
			transformParams.put(PdfName.V, new PdfName("1.2")); // 1.2 is the default value for the "DocMDP transform parameters dictionary version". "1.2" is the value to be used for PDF 1.5 and later
			transformParams.put(PdfName.TYPE, PdfName.TRANSFORMPARAMS);

			PdfDictionary reference = new PdfDictionary();
			reference.put(PdfName.TRANSFORMMETHOD, PdfName.DOCMDP);
			reference.put(PdfName.TYPE, PdfName.SIGREF);
			reference.put(PdfName.TRANSFORMPARAMS, transformParams);
			PdfArray types = new PdfArray();
			types.add(reference);
			dic.put(PdfName.REFERENCE, types);
		}

		sap.setCryptoDictionary(dic);
		sap.setSignDate(presignDate);
		LinkedHashMap exc = new LinkedHashMap();
		//TODO implement content size calculation base on CRL size (and OCSP response size)
		int content_size = CONTENT_SIZE;
		if(parameters.getSignatureContainerSize()>0) content_size = parameters.getSignatureContainerSize();
		int ts_size = TIMESTAMP_SIZE;
		if(parameters.getTimeStampContainerSize()>0) ts_size = parameters.getTimeStampContainerSize();
		if(parameters.isAllocateTimeStampContainer() || parameters.getTimeStampParams()!=null) {
			log.debug(Channel.TECH, "adding %1$s to content_size(%2$s) because of timestamping", ts_size, content_size);
			content_size += ts_size;
		}
		int hexblock_size = content_size*2+2;
		log.debug(Channel.TECH, "Prepared signing with content_size=%1$s bytes (%2$s real bytes once hex-encoded)", content_size, hexblock_size);
		exc.put(PdfName.CONTENTS, new Integer(hexblock_size));
		sap.preClose(exc);
		
		if(log.isDebugEnabled(Channel.TECH)) {
			log.debug(Channel.TECH, "PDF Prepared for signature. ByteRange is %1$s", Arrays.toString(sap.getRange()));
		}

		return stp;
	}
	
	public static class SignResult {
		private byte[] encodedPkcs7;
		private TimestampToken timestampToken;
		public SignResult(byte[] encodedPkcs7, TimestampToken timestampToken) {
			this.encodedPkcs7 = encodedPkcs7;
			this.timestampToken = timestampToken;
		}
		public byte[] getEncodedPkcs7() {
			return encodedPkcs7;
		}
		public TimestampToken getTimestampToken() {
			return timestampToken;
		}
	}
	
	public static class SignReturn {
		private TimestampToken timestampToken;
		private byte[] pkcs7SignatureValue;
		private String signatureName;

		public SignReturn(String signatureName, byte[] pkcs7SignatureValue, TimestampToken timestampToken) {
			super();
			this.signatureName = signatureName;
			this.pkcs7SignatureValue=pkcs7SignatureValue;
			this.timestampToken=timestampToken;
		}

		/**
		 * null if no timestamp was added
		 */
		public TimestampToken getTimestampToken() {
			return timestampToken;
		}
		public byte[] getPkcs7SignatureValue() {
			return pkcs7SignatureValue;
		}
		public String getSignatureName() {
			return signatureName;
		}
	}
	
	public static class PresignReturn {
		private InputStream dataToSign;
		private String signatureName;
		private byte[] hashToSign;
		private PdfSignatureAppearance pdfSignatureAppearance;
		
		public PresignReturn(InputStream dataToSign, String signatureName) {
		    this(dataToSign, signatureName, null);
		}
		public PresignReturn(InputStream dataToSign, String signatureName, PdfSignatureAppearance pdfSignatureAppearance) {
            super();
            this.dataToSign = dataToSign;
            this.signatureName = signatureName;
            this.pdfSignatureAppearance = pdfSignatureAppearance;
        }
		public InputStream getDataToSign() {
			return dataToSign;
		}
		public String getSignatureName() {
			return signatureName;
		}
		public byte[] getHashToSign() {
			return hashToSign;
		}
		public void setHashToSign(byte[] hashToSign) {
			this.hashToSign = hashToSign;
		}
		public PdfSignatureAppearance getPdfSignatureAppearance() {
            return pdfSignatureAppearance;
        }
	}
	
	public static class PresignReturnForRawSignature {
		private String signatureName;
		private byte[] hashToSign;
		private byte[] encodedPkcs7WithoutSignature;
		
		public PresignReturnForRawSignature(byte[] hashToSign, byte[] encodedPkcs7WithoutSignature, String signatureName) {
			super();
			this.hashToSign = hashToSign;
			this.encodedPkcs7WithoutSignature = encodedPkcs7WithoutSignature;
			this.signatureName = signatureName;
		}
		public String getSignatureName() {
			return signatureName;
		}
		public byte[] getHashToSign() {
			return hashToSign;
		}
		public byte[] getEncodedPkcs7WithoutSignature() {
			return encodedPkcs7WithoutSignature;
		}
	}
	
    /**
     * Flatten a PDF document (convert cryptographic signature field into flat image).
     * 
     * @param pdfIs input stream containing the PDF document. The Stream is read to the end but not closed.
     * @param flattenPdfOs output stream containing the flattened PDF document
     * @throws IOException
     * @throws DocumentException
     */
    public static void flattenPdf(InputStream pdfIs, OutputStream flattenPdfOs) throws IOException, DocumentException {
        PdfReader pdfReader = new PdfReader(pdfIs);
        PdfStamper pdfStamper = new PdfStamper(pdfReader, flattenPdfOs);
        pdfStamper.setFormFlattening(true);
        pdfStamper.close();
        pdfReader.close();
    }
}