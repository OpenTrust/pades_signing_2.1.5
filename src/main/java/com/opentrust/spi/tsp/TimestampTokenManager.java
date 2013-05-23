package com.opentrust.spi.tsp;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.util.Date;

import org.bouncycastle.cms.CMSException;

/**
 * Interface du gestionnaire de jeton d'horodatage
 * @author mehdi.bouallagui
 *
 */


public interface TimestampTokenManager {

	
	/**
	 * g�n�re une requ�te d'horodatage.
	 * 
	 * @param data donn�es � horodater. Il s'agit g�n�ralement d'un hash de donn�es de plus grande taille.
	 * @param policy_oid cha�ne repr�sentant la politique d'horodatage.
	 * @return requ�te d'horodatage sous forme binaire.
	 * @throws IOException
	 * @throws NoSuchAlgorithmException 
	 */
	public byte[] generateRequest(byte[] digest, String digestAlgoId, String policy_oid, BigInteger nonce)
			throws IOException, NoSuchAlgorithmException;

	
	public abstract byte[] generateResponse(byte[] requestBytes, PrivateKey privateKey, Certificate certificate,
			Date date, CertStore certStore, String digestAlgorithm, String tsaPolicyOID, String provider)
			throws IllegalArgumentException, CertStoreException, NoSuchAlgorithmException,
			NoSuchProviderException, IOException, InvalidAlgorithmParameterException;
	
	/**
	 * permet de construire un TimeStampIF � partir d'un tableau de bytes repr�sentant un jeton d'horodatage
	 * @param timeStampTokenBytes repr�sentation binaire d'un jeton d'horodatage
	 * @return un jeton d'horodatage sous forme abstraite. Les classes concr�tes sont d�finies dans les factories 
	 * @throws IOException
	 */
	public abstract TimestampToken getTimeStampToken(byte[] timeStampTokenBytes)
			throws IOException;
	
	
	/**
	 * @param digest
	 * @param digestAlgId
	 * @param policy_oid
	 * @param httpUrl
	 * @param useNonce 
	 * @return
	 * @throws IOException
	 * @throws NoSuchFieldException 
	 * @throws NoSuchAlgorithmException 
	 * @throws CMSException 
	 * @throws SPITimestampException 
	 */
	public byte[] getHTTPServerToken(byte[] digest, String digestAlgId, String policy_oid, String httpUrl,
			boolean useNonce) throws IOException, NoSuchFieldException, NoSuchAlgorithmException,
			CMSException;

	public byte[] getServerToken(byte[] digest, TimeStampProcessor tspProcessor) throws IOException,
			NoSuchFieldException, NoSuchAlgorithmException, CMSException;

}