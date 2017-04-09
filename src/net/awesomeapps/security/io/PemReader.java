package net.awesomeapps.security.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.Base64;

public class PemReader {

	public static PemObject read(File file) throws IOException, GeneralSecurityException {
		PemObject.ContentType contentType = null;
		
		// Read in the file
		String buffer = new String(Files.readAllBytes(file.toPath()));
		
		// Determine the file type
		for (PemObject.ContentType ct: PemObject.ContentType.values()) {
			if (buffer.contains(ct.toString())) {
				contentType = ct;
				break;
			}
		}
		
		if (contentType == null) {
			throw new GeneralSecurityException("Unknown or invalid certificate.");
		}
		
		// Remove the start/end strings and all newlines
		buffer = buffer.replace(PemObject.createStart(contentType), "")
					.replace(PemObject.createEnd(contentType), "")
					.replaceAll(System.lineSeparator(), "");
		
		// Base64 decode to get the original encoded bytes
		byte[] content = Base64.getDecoder().decode(buffer);
		
		return new PemObject(content, contentType);
	}
	
}
