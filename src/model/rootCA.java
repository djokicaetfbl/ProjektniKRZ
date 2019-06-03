package model;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class rootCA {
    private static X509Certificate rootCAcertificate;
    private static PublicKey certificatePublicKey ;
    private static PrivateKey certificatePrivateKey;

    static {
        File file = new File(System.getProperty("user.dir") + File.separator + "rootCA" + File.separator + "certs" + File.separator + "ca.cer");
        try {
            rootCAcertificate = (X509Certificate) CertificateFactory.getInstance("x.509").generateCertificate(new FileInputStream(file));
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(System.getProperty("user.dir") + File.separator + "root_CA"
                    + File.separator + "privateKey" + File.separator + "privateKey.der")));
            certificatePublicKey = rootCAcertificate.getPublicKey();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            certificatePrivateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

    }
}
