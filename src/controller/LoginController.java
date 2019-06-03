package controller;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import main.Main;
import model.User;

import java.io.*;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

public class LoginController implements Initializable {

    @FXML
    private Label lUsername;

    @FXML
    private Label lPassword;

    @FXML
    private Label lSertificatePath;

    @FXML
    private TextField tfUserName;

    @FXML
    private PasswordField tfPassword;

    @FXML
    private Button bFileChooser;

    @FXML
    private Button bObfuscation;

    @FXML
    private CheckBox checkBoxConfirmCertificate;

    public static File certificateFile = null;


    public static void userSerialization(){
        try(ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream("user.ser")))){
            oos.writeObject(User.userList);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void userDeserialization(){
        try(ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream("user.ser")))){
            User.userList = (ArrayList<User>) ois.readObject();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static boolean challenge(final File file, PrivateKey privateKey){
        X509Certificate certificate = readCertificate(file);
        ByteBuffer challengeBytes = ByteBuffer.allocate(10000);
        try { 
            SecureRandom.getInstanceStrong().nextBytes(challengeBytes.array());
        Signature signatureForPrivateKey, signatureForPublicKey;
        signatureForPublicKey = Signature.getInstance("SHA256WithRSA", "BC");
        signatureForPrivateKey = Signature.getInstance("SHA256WithRSA", "BC");

        signatureForPrivateKey.initSign(privateKey);
        signatureForPrivateKey.update(challengeBytes.array());
        signatureForPublicKey.initVerify(certificate.getPublicKey());
        signatureForPublicKey.update(challengeBytes.array());
        return signatureForPublicKey.verify(signatureForPrivateKey.sign());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }

    private static X509Certificate readCertificate(final File file) {
        if(file.getName().endsWith(".cer")) {
            CertificateFactory cf;
            X509Certificate certificate = null;
            try {
                cf = CertificateFactory.getInstance("X.509");
                FileInputStream fileInputStream = new FileInputStream(file);
                certificate = (X509Certificate) cf.generateCertificate(fileInputStream);
            } catch (CertificateException e) {
                Logger.getLogger(LoginController.class.getName()).log(Level.SEVERE, null, e);
            } catch (FileNotFoundException e) {
                Logger.getLogger(LoginController.class.getName()).log(Level.SEVERE, null, e);
            }
            return certificate;
        } else {
            return null;
        }
    }


    public void doObfuscationAction() {
            if (authentication()) {
                if(checkPassword(tfPassword.getText())){
                if (certificateFile != null) {
                    if (challenge(certificateFile, User.getUser(tfUserName.getText()).getPrivateKey())) {
                        try {

                            //userSerialization();
                            final FXMLLoader loader = new FXMLLoader(getClass().getResource("/view/Obfuscation.fxml"));
                            ObfuscationController obfuscationController = null;
                            loader.setController(obfuscationController);
                            Parent root = null;
                            root = loader.load();
                            Scene scene = new Scene(root);
                            Stage stage = new Stage();
                            stage.setScene(scene);
                            stage.setResizable(false);
                            stage.getIcons().add(new Image(Main.class.getResourceAsStream("/resources/Protect.png")));
                            ((Stage) bObfuscation.getScene().getWindow()).close();
                            stage.show();

                        } catch (IOException e) {
                            Logger.getLogger(LoginController.class.getName()).log(Level.SEVERE, null, e);
                        }
                    } else {
                        challengeAlarm();
                        return;
                    }
                } else {
                    pathToUserCertificateAlarm();
                    return;
                }
            } else {
                authenticationAlarm();
                return;
            }
            } else {
                authenticationAlarm();
                return;
            }
    }

    public void pathToUserCertificateAction() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File(System.getProperty("user.dir")));  //jenkov
        File selectedFile = fileChooser.showOpenDialog(bFileChooser.getScene().getWindow());
        certificateFile = selectedFile;
        if(certificateFile != null){
            checkBoxConfirmCertificate.setVisible(true);
            checkBoxConfirmCertificate.setSelected(true);
            checkBoxConfirmCertificate.setDisable(true);
        }
    }

    public boolean checkUserName(String username){
        System.out.println("ASA: "+username);
        User.userList.forEach(System.out::println);
        System.out.println("-----------------------------------");
        return User.userList.stream().anyMatch( x -> x.getUsername().equals(username));
    }

    public boolean checkPassword(String password){
        if(!checkUserName(tfUserName.getText())){
            return false;
        }
        File userFile = new File(System.getProperty("user.dir")+File.separator+"users"+File.separator
                +tfUserName.getText()+File.separator+tfUserName.getText()/*+"PrivateKey"*/+".txt");
        if(userFile.exists()){
            try {
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                String saltHash = Files.readAllLines(userFile.toPath(), StandardCharsets.ISO_8859_1).get(0);
                String hash = saltHash.substring(0, saltHash.lastIndexOf("#"));
                String salt = saltHash.substring(saltHash.lastIndexOf("#") + 1);

                byte[] decodedSaltFromFile = Base64.getDecoder().decode(salt);
                byte[] decodedHashFromFile = Base64.getDecoder().decode(hash);

                byte[] passwordFromFile = decodedHashFromFile;
                byte[] saltFromFile = decodedSaltFromFile;
                messageDigest.reset();
                messageDigest.update(saltFromFile);
                byte[] forCheck = messageDigest.digest(password.getBytes(StandardCharsets.UTF_8));

                return Arrays.equals(forCheck, passwordFromFile);
            } catch (IOException e) {
                Logger.getLogger(LoginController.class.getName()).log(Level.SEVERE, null, e);
            } catch (NoSuchAlgorithmException e) {
                Logger.getLogger(LoginController.class.getName()).log(Level.SEVERE, null, e);
            }
        }
        return false;
    }

    public boolean authentication(){
        if(!(tfUserName.getText().isEmpty() && tfPassword.getText().isEmpty())){
            return true;
        }
        return false;
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
            bFileChooser.setOnAction(x -> pathToUserCertificateAction());
            bObfuscation.setOnAction(x -> doObfuscationAction());
            checkBoxConfirmCertificate.setVisible(false);
            checkBoxConfirmCertificate.setSelected(false);
    }


    private static void authenticationUserNameAlarm() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Upozorenje");
        alert.setHeaderText("Autentifikacija");
        alert.setContentText("Korisnicko ime vec postoji!");
        alert.showAndWait();
    }

    private static void authenticationAlarm() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Upozorenje");
        alert.setHeaderText("Autentifikacija");
        alert.setContentText("Provjerite 'Korisničko ime' ili 'Lozinka' !");
        alert.showAndWait();
    }
    private static void pathToUserCertificateAlarm() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Upozorenje");
        alert.setHeaderText("Putanja do sertifikata");
        alert.setContentText("Izaberite sertifikat !");
        alert.showAndWait();
    }
    private static void challengeAlarm() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Upozorenje");
        alert.setHeaderText("Provjera sertifikata");
        alert.setContentText("Izaberite odgovarajuci sertifikat!");
        alert.showAndWait();
    }
}
