package com.opentrust.spi.tsp;

import java.io.IOException;
import java.math.BigInteger;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.util.Date;

/**
 * représentation abstraite un jeton d'horodatage.
 * @author mehdi.bouallagui
 *
 */
public interface TimestampToken {

	/**
	 * récupère la date du jeton
	 * @return date du jeton
	 * @throws NoSuchFieldException dans le cas où la date ne peut être retrouvée à partir du jeton
	 */
	public abstract Date getDateTime()
			throws NoSuchFieldException;

	/**
	 * permet de retrouver la précision de l'horodatage
	 * @return chaîne de caractères représentant la présision de l'horodatage. Le format de la chaine est défini par le motif suivant:
	 * "xx sec yy millis zz micros"
	 * 
	 * @throws NoSuchFieldException dans le cas où la précision ne peut pas être retrouvée.
	 */
	public abstract String getAccuracy()
			throws NoSuchFieldException;

	/**
	 * retrouve la politique d'horodatage utilisée
	 * @return OID de la politique d'horodatage 
	 * @throws NoSuchFieldException
	 */
	public abstract String getPolicy()
			throws NoSuchFieldException;

	/**
	 * retrouve le certificat de l'horodateur
	 * @return certificat de l'horodateur
	 * @throws NoSuchFieldException dans le cas où le certificat ne peut être retrouvé.
	 */
	public abstract Certificate getSignerCertificate()
			throws NoSuchFieldException;
	
	/**
	 * permet de retrouver le nonce, utilisé pour déjouer les attaques par rejeu: le nonce 
	 * de la réponse doit correspondre à celui de la requête.
	 * @return nonce 
	 * @throws NoSuchFieldException
	 */
	public abstract BigInteger getNonce()
	throws NoSuchFieldException;

	/**
	 * verifie que la signature de l'horodateur est 'cryptographiquement' correcte:
	 * en déchiffrant les données signées avec la clé publique de l'horodateur, on doit retrouver le hash des données
	 * initiales.
	 * @return vrai si la vérification réussit.
	 * @throws SignatureException si la vérification échoue 
	 */
	public abstract boolean verifySignature() throws SignatureException;

	/**
	 * vérifie que l'empreinte des données en entrée correpond à celle des données horodatées.
	 * @param data
	 * @return
	 * @throws DigestException si la vérification échoue
	 */
	public abstract boolean verifyImprint(byte[] data) throws DigestException;
	
	/**
	 * Vérifie qu'il est possible de construire une chaine de certificats entre le certificat de l'horodateur
	 * et un ensemble de certificats de confiance (pouvant être root ou pas)
	 * @param trustedCertificates certificats de confiance.
	 * @return
	 */
	public abstract boolean verifyCertPath(Certificate [] trustedCertificates);

	/**
	 * convertit le jeton sous format binaire
	 * @return le jeton d'horodatage sous sa représentation binaire
	 */
	public abstract byte[] getEncoded()
			throws IOException;
	
	/**
	 * extrait les certificats et les CRLs enveloppées dans le jeton d'horodatage
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchFieldException
	 */
	public abstract CertStore getCertificatesAndCRLs() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchFieldException;
	
	public abstract String getMessageImprintAlgName();



}