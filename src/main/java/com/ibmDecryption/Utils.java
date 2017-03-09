package com.ibmDecryption;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.StringTokenizer;

import org.apache.commons.lang.ArrayUtils;

public class Utils {
	
	public static void writeArrayListToFile(String filePath, ArrayList<String> stringList) {
		try {
			File testFile = new File(filePath);
			FileWriter fileWriter = new FileWriter(testFile);
			fileWriter.write(ArrayUtils.toString(stringList));
			fileWriter.flush();
			fileWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	 public static String getFileMD5(File file) {
	        if (!file.isFile()) {
	            return null;
	        }
	        MessageDigest digest = null;
	        FileInputStream in = null;
	        byte buffer[] = new byte[8192];
	        int len;
	        try {
	            digest =MessageDigest.getInstance("MD5");
	            in = new FileInputStream(file);
	            while ((len = in.read(buffer)) != -1) {
	                digest.update(buffer, 0, len);
	            }
	            BigInteger bigInt = new BigInteger(1, digest.digest());
	            return bigInt.toString(16);
	        } catch (Exception e) {
	            e.printStackTrace();
	            return null;
	        } finally {
	            try {
	                in.close();
	            } catch (Exception e) {
	                e.printStackTrace();
	            }
	        }
	      
	    }
	 
	public static ArrayList<String> convertFileToList(String seperator,
			String filePath) {
		ArrayList<String> tempList = new ArrayList<String>();
		try {
			String encoding = "GBK";
			File file = new File(filePath);
			String lineinfo = "";
			if (file.isFile() && file.exists()) {
				InputStreamReader read = new InputStreamReader(
						new FileInputStream(file), encoding);
				BufferedReader bufferReader = new BufferedReader(read);
				while ((lineinfo = bufferReader.readLine()) != null) {
					StringTokenizer stk = new StringTokenizer(lineinfo,
							seperator);// 被读取的文件的字段以seperator分隔

					String[] strArrty = new String[stk.countTokens()];

					int i = 0;
					while (stk.hasMoreTokens()) {
						strArrty[i++] = stk.nextToken();
					}
					System.out.println(strArrty.length);
					// tempList = (ArrayList<String>)
					// java.util.Arrays.asList(strArrty);
					for (int j = 0; j < strArrty.length; j++) {
						tempList.add(strArrty[j]);
					}
					System.out.println(tempList.size());

				}
				read.close();
			}
		} catch (Exception e) {
			System.out.println("读取文件内容出错");
			e.printStackTrace();
		}
		return tempList;
	}
}
