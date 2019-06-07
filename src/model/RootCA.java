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
import java.util.Base64;

import org.bouncycastle.cert.X509CRLHolder;

public class RootCA {
    private static X509Certificate rootCAcertificate;
    private static PublicKey certificatePublicKey ;
    private static PrivateKey certificatePrivateKey;
    private static X509CRLHolder crlList;

    public static X509CRLHolder getCrlList() {
        return crlList;
    }

    public static void setCrlList(X509CRLHolder crlList) {
        RootCA.crlList = crlList;
    }

    static {
        File file = new File(System.getProperty("user.dir") + File.separator + "rootCA" + File.separator + "certs" + File.separator + "ca.cer");
        try {
            rootCAcertificate = (X509Certificate) CertificateFactory.getInstance("x.509").generateCertificate(new FileInputStream(file));
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(System.getProperty("user.dir") + File.separator + "rootCA"
                    + File.separator + "private" + File.separator + "caprivate.der")));
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
    public static boolean isUserOnCRLList(final User user) {
        System.out.println("USER "+user);
        //System.out.println("USER CERTIFICATE: "+user.getUserCertificate());
        System.out.println("SERIAL NUMBER: "+user.getUserCertificate().getSerialNumber());
        return crlList.getRevokedCertificate(user.getUserCertificate().getSerialNumber()) != null;
    }
}
