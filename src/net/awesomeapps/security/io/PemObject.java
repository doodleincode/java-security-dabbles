package net.awesomeapps.security.io;

import java.security.Key;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * This class represets a PEM object that can be written to disk using {@link PemWriter}
 * or read into using {@link PemReader}
 *
 */
public class PemObject {

	public enum ContentType {
		CERTIFICATE, RSA_PRIVATE_KEY, PUBLIC_KEY, PRIVATE_KEY;
		
		@Override
		public String toString() {
			switch (this) {
				default: return this.name().replaceAll("_", " ");
			}
		}
	}
	
	private byte[] content;
	private ContentType contentType;
	
	public PemObject(byte[] content, ContentType contentType) {
		this.content = content;
		this.contentType = contentType;
	}
	
	public PemObject(Key key, ContentType contentType) {
		this(key.getEncoded(), contentType);
	}
	
	public PemObject(X509Certificate certificate, ContentType contentType) throws CertificateEncodingException {
		this(certificate.getEncoded(), contentType);
	}

	public byte[] getContent() {
		return content;
	}

	public ContentType getContentType() {
		return contentType;
	}
	
	public String getStart() {
		return createStart(getContentType());
	}
	
	public String getEnd() {
		return createEnd(getContentType());
	}
	
	public static String createStart(ContentType contentType) {
		return "-----BEGIN " + contentType + "-----";
	}
	
	public static String createEnd(ContentType contentType) {
		return "-----END " + contentType + "-----";
	}
	
}
