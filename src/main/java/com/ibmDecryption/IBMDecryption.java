package com.ibmDecryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import java.security.Key;

import org.apache.commons.lang.ArrayUtils;


import com.ibm.crypto.provider.AESKeySpec;

public class IBMDecryption {
	private static final int timestampExpiredInMinutes = 10;

	public String encrypt(String plainText) throws Exception {
		try {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
			SimpleDateFormat sdfLog = new SimpleDateFormat(
					"yyyy-MM-dd HH:mm:ss");
			Date currentTime = new Date();
			plainText = sdf.format(currentTime) + "-" + plainText;
			System.out.println("encrypt time:" + sdfLog.format(currentTime));
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, generateKey());
			byte[] encrypted = cipher.doFinal(plainText.getBytes());
			String result = new String(Base64.encode(encrypted));
			return result;
		} catch (Exception e) {
			System.out.println("encrypt error ..." + e);
			throw e;
		}
	}

	public byte[] getContent(String filePath) throws IOException {
		File file = new File(filePath);
		long fileSize = file.length();
		if (fileSize > Integer.MAX_VALUE) {
			System.out.println("file too big...");
			return null;
		}
		FileInputStream fi = new FileInputStream(file);
		byte[] buffer = new byte[(int) fileSize];
		int offset = 0;
		int numRead = 0;
		while (offset < buffer.length
				&& (numRead = fi.read(buffer, offset, buffer.length - offset)) >= 0) {
			offset += numRead;
		}
		fi.close();
		return buffer;
	}

	public String decrypt(String encryptedText) throws Exception {
		return decrypt(encryptedText, timestampExpiredInMinutes);
	}

	private String decrypt(final String encryptedText,
			final int timestampExpired) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, generateKey());
			byte[] raw = Base64.decode(encryptedText.toCharArray());
			String decryptedStr = new String(cipher.doFinal(raw));

			int idx = decryptedStr.indexOf('-');
			if (idx <= 0) {
				System.out.println("the encrypted text no timestamp part...");
				decryptedStr = null;
			} else {
				if (timestampExpired > 0) {
					SimpleDateFormat sdf = new SimpleDateFormat(
							"yyyyMMddHHmmss");
					Date encryptTime = sdf
							.parse(decryptedStr.substring(0, idx));

					long tslong = encryptTime.getTime();
					long nowlong = (new Date()).getTime();
					/*
					 * return null if timestamp is later than now or 10 minutes
					 * before now
					 */
					if (tslong >= nowlong
							|| (nowlong - tslong) > timestampExpiredInMinutes * 60 * 1000) {
						System.out
								.println("the encrypted text is time out ...");
						decryptedStr = null;
					} else {
						decryptedStr = decryptedStr.substring(idx + 1);
					}
				} else {
					decryptedStr = decryptedStr.substring(idx + 1);
				}
			}
			return decryptedStr;
		} catch (Exception e) {
			System.out.println("decrypt error ..." + e);
			throw e;
		}
	}

	public Key generateKey() throws Exception {
		byte[] keyBytes = new byte[0];
		try {
			byte[] array = getContent("C:/Users/fionalyn.ping.fu/Desktop/remoteServerDown/MLCPinSecretKey.ser");
			for (int i = 0; i < array.length; i++) {
				keyBytes = ArrayUtils.add(keyBytes, array[i]);
			}
		} catch (Exception e) {
			System.out.println("Generate Key error" + e);
			throw e;
		}
		return toKey(keyBytes);
	}

	private Key toKey(byte[] key) throws Exception {
		try {
			AESKeySpec dks = new AESKeySpec(key);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("AES");
			SecretKey secretKey = keyFactory.generateSecret(dks);
			return secretKey;
		} catch (Exception e) {
			System.out.println("byte array to Key object error" + e);
			throw e;
		}
	}


	public static void main(String[] args) throws Exception {
		IBMDecryption decryption = new IBMDecryption();
		String encryptedStringPath = "C:\\testData\\encryptedString.txt";
		String decryptedStringPath = "C:\\testData\\decryptedString.txt";
		String testStringPath = "C:\\testData\\testString.txt";
		ArrayList<String> tempList = new ArrayList<String>();
		ArrayList<String> decryptedList = new ArrayList<String>();
		tempList = Utils.convertFileToList(",", encryptedStringPath);
		for (int i = 0; i < tempList.size(); i++) {
			decryptedList.add(decryption.decrypt(tempList.get(i)));
		}
		Utils.writeArrayListToFile(decryptedStringPath, decryptedList);
		String testStringMD5 = Utils.getFileMD5(new File(testStringPath));
		String decryptedMD5 = Utils.getFileMD5(new File(decryptedStringPath));
		if (testStringMD5.equals(decryptedMD5)) {
			System.out.println("The test files's MD5 is equal to decryptedString's MD5. The decryption is correct!");
		} else {
			System.out.println("decryption error!");
		}
	}
}
