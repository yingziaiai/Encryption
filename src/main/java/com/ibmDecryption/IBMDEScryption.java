package com.ibmDecryption;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.Cipher;

import com.ibm.jvm.util.ByteArrayOutputStream;




public class IBMDEScryption {
	private static final int timestampExpiredInMinutes = 10;
	 public String encrypt(String plainText) throws Exception {
	        try {
	            SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
	            SimpleDateFormat sdfLog = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

	            Date currentTime = new Date();
	            plainText = sdf.format(currentTime) + "-" + plainText;
	            System.out.println("encrypt time:" + sdfLog.format(currentTime));

	            Cipher cipher = Cipher.getInstance("DES");
	            cipher.init(Cipher.ENCRYPT_MODE, generateKey());

	            byte[] encrypted = cipher.doFinal(plainText.getBytes());
	            String result = new String(Base64.encode(encrypted));
	            return result;
	        } catch (Exception e) {
	            System.out.println("encrypt error ..." + e);
	            throw e;
	        }
	    }

	    /**
	     * @see com.cathaypacific.mlc.crypto.ICommonEncrypter#decrypt(java.lang.String)
	     */
	    public String decrypt(String encryptedText) throws Exception {
	        return decrypt(encryptedText, timestampExpiredInMinutes);
	    }

	    
	    public String decryptWithoutExpiryChecking(String encryptedText) throws Exception {
	        return decrypt(encryptedText, 0);
	    }

	    private String decrypt(final String encryptedText, final int timestampExpired) throws Exception {
	        try {
	            Cipher cipher = Cipher.getInstance("DES");
	            cipher.init(Cipher.DECRYPT_MODE, generateKey());
	            byte[] raw = Base64.decode(encryptedText.toCharArray());
	            String decryptedStr = new String(cipher.doFinal(raw));

	            int idx = decryptedStr.indexOf('-');
	            if (idx <= 0) {
	                System.out.println("the encrypted text no timestamp part...");
	                decryptedStr = null;
	            } else {
	                if (timestampExpired > 0) {
	                    SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
	                    Date encryptTime = sdf.parse(decryptedStr.substring(0, idx));

	                    long tslong = encryptTime.getTime();
	                    long nowlong = (new Date()).getTime();
	                    /*
	                     * return null if timestamp is later than now or 10 minutes before now
	                     */
	                    if (tslong >= nowlong || (nowlong - tslong) > timestampExpired * 60 * 1000) {
	                        System.out.println("the encrypted text is time out ...");
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
	    
//		public Key generateKey() throws Exception {
//			byte[] keyBytes = new byte[0];
//			try {
//				byte[] array = getContent("C:/ideaWorkspace/mlcCloudAddon/src/main/resources/key/DES/MLCPinSecretKey.ser");
//				for (int i = 0; i < array.length; i++) {
//					keyBytes = ArrayUtils.add(keyBytes, array[i]);
//				}
//			} catch (Exception e) {
//				System.out.println("Generate Key error" + e);
//				throw e;
//			}
//			return toKey(keyBytes);
//		}
	    
	    public Key generateKey() throws Exception {
	    	ObjectInputStream ois = null;
	    	InputStream is = null;
	    	Key key = null;
	    	try {
	    		byte[] array = getContent("C:/ideaWorkspace/mlcCloudAddon/src/main/resources/key/DES/MLCPinSecretKey.ser");
	    		is = new  ByteArrayInputStream(array);  
//	    	    is = keyFile.getInputStream();
	    	    ois = new ObjectInputStream(is);
	    	    key = (Key) ois.readObject();
//	    	    Object object = ois.readObject();
////	    	    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();  
////	    	    outputStream.toByteArray();
//	    	    
//	            ByteArrayOutputStream bo = new ByteArrayOutputStream();  
//	            ObjectOutputStream oo = new ObjectOutputStream(bo);  
//	            oo.writeObject(object);
	            
	         
	    	   
	    	    
	    	} catch (Exception e) {
	    	    System.out.println("Generate DES Key error" + e);
	    	    throw e;
	    	} finally {
	    	    if (ois != null) {
	    		ois.close();
	    	    }
	    	    if (is != null) {
	    		is.close();
	    	    }
	    	}
	    	return key;
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
		
//		private Key toKey(byte[] key) throws Exception {
//			try {
//				DESKeySpec dks = new DESKeySpec(key);
//				SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
//				SecretKey secretKey = keyFactory.generateSecret(dks);
//				return secretKey;
//			} catch (Exception e) {
//				System.out.println("byte array to Key object error" + e);
//				throw e;
//			}
//		}
		public static void main(String[] args) throws Exception {
			IBMDEScryption decryption = new IBMDEScryption();
//			String encryptedString = decryption.encrypt("test test test");
//			System.out.println(encryptedString);
			String decryptedString = decryption.decrypt("FdRo7YCZ2RjsetwPfPz786ncmDanVtLFCoKB2fVB7UU=");
			System.out.println(decryptedString);
			
		}
}
