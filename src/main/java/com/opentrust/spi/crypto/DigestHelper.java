/*
 * Created on 22 juin 2005
 */
package com.opentrust.spi.crypto;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * Classe utilitaire pour gérer les opération de hachage
 * 
 * @author mehdi.bouallagui
 */

public class DigestHelper {

	/*
	public static String getAlgorithmFromURI(String uriString)
			throws URISyntaxException {
		try {

			AlgorithmID algorithmID = CryptoConstants.AlgorithmID
					.valueOfURI(uriString);
			if (algorithmID.getType() != AlgorithmType.DIGEST) {
				throw new IllegalArgumentException(
						"URI does not correspond to a digest algorithm: "
								+ uriString);
			}
			return algorithmID.getTag();
		} catch (NullPointerException e) {
			throw new IllegalArgumentException(
					"URI does not correspond to a supported algorithm: "
							+ uriString);
		}
	}

	public static String getURIFromAlgorithm(String algString) {
		try {
			AlgorithmID algorithmID = CryptoConstants.AlgorithmID
					.valueOfTag(algString);
			if (algorithmID.getType() != AlgorithmType.DIGEST) {
				throw new IllegalArgumentException(
						"URI does not correspond to a digest algorithm: "
								+ algString);
			}
			return algorithmID.getURI();
		} catch (NullPointerException e) {
			throw new IllegalArgumentException(
					"Algorithm Id does not correspond to a supported algorithm: "
							+ algString);
		}
	}
	
	public static String getOIDFromAlgorithm(String algString) {
		try {
			AlgorithmID algorithmID = CryptoConstants.AlgorithmID
					.valueOfTag(algString);
			if (algorithmID.getType() != AlgorithmType.DIGEST) {
				throw new IllegalArgumentException(
						"URI does not correspond to a digest algorithm: "
								+ algString);
			}
			return algorithmID.getOID();
		} catch (NullPointerException e) {
			throw new IllegalArgumentException(
					"Algorithm Id does not correspond to a supported algorithm: "
							+ algString);
		}
	}
	*/

	public static byte[] getDigest(byte []data, String hashAlgorithm) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
		return digest.digest(data);
	}


	/**
	 * méthode de calcul de hash du contenu d'un fichier. Le calcul se fait 'on
	 * the fly' pour permettre le support des fichiers de grande taille.
	 * 
	 * @param file
	 *            fichier dont on veut hacher le contenu
	 * @param algorithm
	 *            algorithme de hachage
	 * @return tableau d'octets représentant le hash
	 * @throws NoSuchAlgorithmException
	 *             dans le cas où aucun provider enregistré n'implémente
	 *             l'algorithme spécifié
	 * @throws IOException
	 *             dans le cas d'un problème de lecture du fichier
	 */
	public static byte[] getDigest(File file, String algorithm)
			throws NoSuchAlgorithmException, IOException {

		FileInputStream fileInputStream = new FileInputStream(file);
		byte[] digest;
		try {
			digest = getDigest(fileInputStream, algorithm);
			return digest;		
		} catch (IOException e) {
			throw e;
		} finally {
			try {
				if (fileInputStream != null) {
					fileInputStream.close();
				}
			} catch (IOException e) {
			}
		}
	}

	/**
	 * méthode de calcul de hash à partir d'un flux entrant
	 * 
	 * @param inputStream
	 *            flux
	 * @param algorithm
	 *            algorithme de hachage
	 * @return tableau d'octets représentant le hash
	 * @throws IOException
	 *             dans le cas d'un problème de lecture du flux
	 * @throws IOException
	 *             dans le cas d'un problème de lecture du fichier
	 */
	public static byte[] getDigest(InputStream inputStream, String algorithm)
			throws IOException, NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(algorithm);
		byte[] buffer = new byte[10000];
		int i = 0;
		while ((i = inputStream.read(buffer)) != -1) {
			md.update(buffer, 0, i);
		}
		return md.digest();
	}
	


}