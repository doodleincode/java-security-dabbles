package test;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import net.awesomeapps.security.RSA;
import net.awesomeapps.security.X509CertificateGenerator;
import net.awesomeapps.security.io.PemObject;
import net.awesomeapps.security.io.PemWriter;

public class CertGenTest {

	public static void main(String[] args) {
		try {
			X509CertificateGenerator generator = X509CertificateGenerator.getInstance(RSA.KEYSIZE_2048, RSA.SHA1_RSA);
			
			generator.setCertificateInfo("test.com", "Department House", "Company", "Someville", "Some State", "AA");
			generator.setValidity(1000);
			generator.generate();
			
			System.out.println(generator.getCertificate().getSubjectDN().getName());
			
			// Write out the certs to file
			PemObject publicKey = new PemObject(generator.getCertificate().getEncoded(), PemObject.ContentType.CERTIFICATE);
			PemObject privateKey = new PemObject(generator.getPrivateKey(), PemObject.ContentType.RSA_PRIVATE_KEY);
			
			PemWriter.write(new File("test.crt"), publicKey);
			PemWriter.write(new File("private.key"), privateKey);
		}
		catch (GeneralSecurityException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
