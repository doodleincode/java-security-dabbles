package net.awesomeapps.security.io;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Base64;

import net.awesomeapps.utils.StringUtil;

public class PemWriter {
	
	/**
	 * Write the given PEM object to the provided file.
	 * 
	 * @param out
	 * @param pemObject
	 * @throws UnsupportedEncodingException
	 * @throws IOException
	 */
	public static void write(File out, PemObject pemObject) throws UnsupportedEncodingException, IOException {
		FileOutputStream fos = null;
		StringBuilder sb = new StringBuilder();
		
		// Build the output
		sb.append(pemObject.getStart());
		sb.append(System.lineSeparator());
		sb.append(StringUtil.lineWrap(Base64.getEncoder().encodeToString(pemObject.getContent()), 64));
		sb.append(System.lineSeparator());
		sb.append(pemObject.getEnd());
		
		try {
			fos = new FileOutputStream(out);
			fos.write(sb.toString().getBytes("UTF-8"));
			fos.flush();
		}
		finally {
			if (fos != null) {
				fos.close();
			}
		}
	}
	
}
