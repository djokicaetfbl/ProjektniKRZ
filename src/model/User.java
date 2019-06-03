package model;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;
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
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class User implements Serializable {

    private String username;
    public static List<User> userList = new ArrayList<User>();
    private PublicKey publicKey;
    transient public X509Certificate certificate;
    private static X509Certificate userCertificate;

    public PrivateKey getPrivateKey() {
        try {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(System.getProperty("user.dir")+File.separator+"users"+ File.separator+this.username+File.separator +this.username+"PrivateKey.der")));
            return KeyFactory.getInstance("RSA").generatePrivate(pkcs8EncodedKeySpec);
        } catch (IOException e) {
            Logger.getLogger(getClass().getName()).log(Level.SEVERE, null, e);
        } catch (NoSuchAlgorithmException e) {
            Logger.getLogger(getClass().getName()).log(Level.SEVERE, null, e);
        } catch (InvalidKeySpecException e) {
            Logger.getLogger(getClass().getName()).log(Level.SEVERE, null, e);
        }
        return null;
    }

    public PublicKey getPublicKey(){
        try {
            File file = new File(System.getProperty("user.dir") + File.separator + "certs" + File.separator + this.getUsername() +".cer");
            userCertificate = (X509Certificate) CertificateFactory.getInstance("x.509").generateCertificate(new FileInputStream(file));
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return userCertificate.getPublicKey();
    }

    public static User getUser(String username){
        return userList.stream().filter(x -> x.username.equals(username)).findFirst().get();
    }

    public User(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public static List<User> getUserList() {
        return userList;
    }

    public static void setUserList(List<User> userList) {
        User.userList = userList;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public String toString() {
        return "User{" + "username='" + username + '\'' + '}';
    }
}
