package controller;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import main.Main;
import model.Services;
import model.User;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static model.Services.dencryptFileWithSesionKey;

/** The steps followed in creating digital signature are :

 1.Message digest is computed by applying hash function on the message and then message digest is encrypted using private key of sender to form the digital signature.
 (digital signature = encryption (private key of sender, message digest) and message digest = message digest algorithm(message)).
 2.Digital signature is then transmitted with the message.(message + digital signature is transmitted)
 3.Receiver decrypts the digital signature using the public key of sender.(This assures authenticity,as only sender has his private key so only sender can encrypt using
 his private key which can thus be decrypted by sender’s public key).
 4.The receiver now has the message digest.
 5.The receiver can compute the message digest from the message (actual message is sent with the digital signature).
 6.The message digest computed by receiver and the message digest (got by decryption on digital signature) need to be same for ensuring integrity.

 Message digest is computed using one-way hash function, i.e. a hash fucntion in which computation of hash value of a is easy but computation of a from hash value of a is very difficult.
 */


public class ObfuscationController implements Initializable {

    @FXML
    private RadioButton rbEncrypt;

    @FXML
    private RadioButton rbDecrypt;

    @FXML
    private Button bChooseSourceCode;

    @FXML
    private ComboBox cmbHashAlgorihm;

    @FXML
    private ComboBox cmbEncryptAlgorithm;

    @FXML
    private ComboBox cmbReciver;

    @FXML
    private ComboBox cmbEncryptedContent;

    @FXML
    private Button bSendEncryptedContent;

    @FXML
    private Button bExit;

    @FXML
    private Button bDecryptContent;

    @FXML
    private Button bCompileAndRun;

    @FXML
    private Label lChooseSourceCode;

    @FXML
    private Label lChooseHashAlgorithm;

    @FXML
    private Label lChooseEncryptAlgorithm;

    @FXML
    private Label lChooseSender;

    @FXML
    private Label lChooseCryptContent;

    public static final String sha256withrsa = "SHA256WithRSA";
    public static final String sha512withrsa = "SHA512WithRSA";
    public static final String aes = "AES";
    public static final Integer aesKeyBitSize = 256;
    public static final String blowfish = "Blowfish";
    public static final Integer blowfishKeyBitSize = 128;
    public static final String des3 = "DES3";
    public static final Integer des3KeyBitSize = 112;
    public static String userContentPath;

    private File excetuteFile;
    private File fileForCompile;

    void bExitAction() {
        ((Stage) bExit.getScene().getWindow()).close();
        final FXMLLoader loader = new FXMLLoader(getClass().getResource("/view/Login.fxml"));
        LoginController logInController = null;
        loader.setController(logInController);
        Parent root = null;
        try {
            root = loader.load();
        } catch (IOException e) {
            Logger.getLogger(getClass().getName()).log(Level.SEVERE, null, e);
        }
        Scene scene = new Scene(root);
        Stage stage = new Stage();
        stage.setScene(scene);
        stage.setResizable(false);
        stage.setTitle("Login");
        //stage.getIcons().add(new Image(Main.class.getResourceAsStream("/com/ognjen/resursi/Login.png")));
       // stage.setOnHiding(e -> Users.serialize());
        //stage.setOnCloseRequest(e -> Users.serialize());
        stage.show();
    }

    public void chooseEncryptAlgorithmAction() {

    }

    public void chooseEncryptedContentAction() {

    }

    public void chooseHashAlgorithmAction() {

    }

    public void chooseReciverAction() {

    }

    public void compileAndRunAction() {

    }

    public void decryptContentAction() {
        if(!cmbEncryptedContent.getSelectionModel().isEmpty()) {
            try{
            userContentPath = System.getProperty("user.dir") + File.separator + "users" + File.separator + LoginController.currentUser.getUsername() +
                    File.separator + "userContent" + File.separator + cmbEncryptedContent.getSelectionModel().getSelectedItem();
            System.out.println("USER CONTENT PATH: " + userContentPath);
            String fileContent = Files.readAllLines(Paths.get(userContentPath), StandardCharsets.UTF_8).stream().collect(Collectors.joining("")); //data


            System.out.println("FILE CONTENT: " + fileContent);

            byte[] decodeFileHeader = Base64.getDecoder().decode(fileContent.split("#")[0].getBytes(StandardCharsets.UTF_8)); //username // header

            System.out.println("DECODE FILE HEADER: " + decodeFileHeader);

            byte[] decryptFileHeader = Services.decryptHeader(decodeFileHeader,LoginController.currentUser.getPrivateKey());
            System.out.println("DECRYPT FILE HEADER: "+decryptFileHeader);

            String headerFileString = new String(decryptFileHeader, 0, decryptFileHeader.length, StandardCharsets.UTF_8);
            System.out.println("HEADER FILE STRING: "+headerFileString);

            byte[] sessionKey;

                sessionKey = Hex.decode(headerFileString.split("#")[1].getBytes("UTF-8")); // secret key
            System.out.println("SESSION KEY: " + sessionKey);
                byte[] digitalSignature;
                try {
                    digitalSignature = Hex.decode(fileContent.split("#")[2].getBytes(StandardCharsets.UTF_8));// VRATI OVO
                    System.out.println("DIGITAL SIGNATURE: "+digitalSignature);
                } catch (Exception ex) {
                    System.out.println("Sadrzaj poruke je ostecen!");
                    return;
                }

            System.out.println("ENCRYPT ALGORITHM: " + headerFileString.split("#")[2]);
                SecretKey originalKey = new SecretKeySpec(sessionKey, 0, sessionKey.length, headerFileString.split("#")[2]);
                byte[] javaClassInByte;
                try {
                    javaClassInByte = Base64.getDecoder().decode(fileContent.split("#")[1]); // session key
                } catch (Exception ex) {
                    System.out.println("Sadrzaj poruke je ostecen!");
                    return;
                }
                System.out.println("JAVA CLASS IN BYTE: "+javaClassInByte);
                System.out.println("ORIGINAL KEY: "+originalKey);
                byte[] textInByte = Services.dencryptFileWithSesionKey(javaClassInByte, originalKey, headerFileString.split("#")[2]);
                String fileText = new String(textInByte,0,textInByte.length,StandardCharsets.UTF_8);

                if(Services.verificationOfDigitalSignature(fileText.getBytes(), digitalSignature,headerFileString.split("#")[3],User.getUser(headerFileString.split("#")[0]))){
                    fileForCompile = new File(System.getProperty("user.dir") + File.separator + "users" + File.separator + LoginController.currentUser.getUsername() +
                            File.separator + "userContent" + File.separator + headerFileString.split("#")[4]);
                    Files.write(fileForCompile.toPath(),fileText.getBytes(),StandardOpenOption.CREATE);
                } else {
                    System.out.println("PORUKA JE MJENJANA !!");
                }



        }catch(Exception e){
            e.printStackTrace();
        }

        } else {
            encryptedFileNotSelected();
        }


    }

    public List<File> getUserContent(){
        List<Path> userContentFileList = null;
        List<File> files = new ArrayList<File>();
        try(Stream<Path> walk = Files.walk(Paths.get(System.getProperty("user.dir") + File.separator + "users" + File.separator + LoginController.currentUser.getUsername() + File.separator + "userContent"))){
            userContentFileList =  walk.filter(x -> x.getFileName().toString().endsWith(".enc")).collect(Collectors.toList());
            userContentFileList.forEach(x ->{
                files.add(x.toFile());
            });
        } catch (IOException e) {
            e.printStackTrace();
        }
        return  files;
    }



    public void sendEncryptedContentAction() {

        userContentPath = System.getProperty("user.dir") + File.separator+ "users" + File.separator + cmbReciver.getSelectionModel().getSelectedItem().toString()+File.separator + "userContent";
        if(!new File(userContentPath).exists()){
            new File(userContentPath).mkdir();
        }

        byte[] digitalSignatureOfDocument = Services.digitalSignature(excetuteFile,cmbHashAlgorihm.getSelectionModel().getSelectedItem().toString(), LoginController.currentUser.getPrivateKey());
        SecretKey secretKey = Services.generateSecretKey(cmbEncryptAlgorithm.getSelectionModel().getSelectedItem().toString());

        String hexForUsedSessionKey = Hex.toHexString(secretKey.getEncoded());
        ByteBuffer fileHeaderByteBuffer =  ByteBuffer.allocate(LoginController.currentUser.getUsername().length()+ Hex.toHexString(secretKey.getEncoded()).length() + cmbHashAlgorihm.getSelectionModel().getSelectedItem().toString().length()
        + cmbEncryptAlgorithm.getSelectionModel().getSelectedItem().toString().length() + 4 * "#".getBytes(StandardCharsets.UTF_8).length
        +  excetuteFile.getName().getBytes(StandardCharsets.UTF_8).length);

        System.out.println("LIMIT: "+fileHeaderByteBuffer.limit());

        try {
            fileHeaderByteBuffer.put(LoginController.currentUser.getUsername().getBytes("UTF-8"));

            fileHeaderByteBuffer.put("#".getBytes("UTF-8"));
        fileHeaderByteBuffer.put((hexForUsedSessionKey.getBytes("UTF-8")));

        fileHeaderByteBuffer.put("#".getBytes("UTF-8"));

        fileHeaderByteBuffer.put(cmbEncryptAlgorithm.getSelectionModel().getSelectedItem().toString().getBytes(StandardCharsets.UTF_8));
        fileHeaderByteBuffer.put("#".getBytes("UTF-8"));

        fileHeaderByteBuffer.put(cmbHashAlgorihm.getSelectionModel().getSelectedItem().toString().getBytes(StandardCharsets.UTF_8));
        fileHeaderByteBuffer.put("#".getBytes("UTF-8"));

        fileHeaderByteBuffer.put(excetuteFile.getName().getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        String reciverContentPath = userContentPath+File.separator + excetuteFile.getName()+".enc";
        if(! new File(reciverContentPath).exists()) {
            try {
                new File(reciverContentPath).createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        System.out.println("RECIVER PATH: "+reciverContentPath);

        try {
            byte[] encryptHeader = Services.encryptHeader(fileHeaderByteBuffer, ((User) cmbReciver.getSelectionModel().getSelectedItem()).getPublicKey());
            Files.write(Paths.get(reciverContentPath), Base64.getEncoder().encodeToString(encryptHeader).getBytes("UTF-8"), StandardOpenOption.CREATE);
            Files.write(Paths.get(reciverContentPath), "#".getBytes("UTF-8"), StandardOpenOption.APPEND);

            byte[] encFileWithSesKey = Base64.getEncoder().encodeToString(Services.encryptFileWithSesionKey(excetuteFile, secretKey, cmbEncryptAlgorithm.getSelectionModel().getSelectedItem().toString())).getBytes("UTF-8");
            Files.write(Paths.get(reciverContentPath), encFileWithSesKey, StandardOpenOption.APPEND);
            Files.write(Paths.get(reciverContentPath), "#".getBytes("UTF-8"), StandardOpenOption.APPEND);

            Files.write(Paths.get(reciverContentPath), Hex.toHexString(digitalSignatureOfDocument).getBytes("UTF-8"), StandardOpenOption.APPEND);
            succesTransactionInfo();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public void sourceCodeFileChooserAction() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setInitialDirectory(new File(System.getProperty("user.dir")));
        File selectedFile = fileChooser.showOpenDialog(bChooseSourceCode.getScene().getWindow());
        if(!(selectedFile.isFile() && selectedFile.toString().substring(selectedFile.toString().lastIndexOf(".")).equals(".java"))) {
            wrongSelectFileType();
            return;
        } else {
            excetuteFile = selectedFile;
        }
    }

    public void setRbEncryptPanel(){
        rbDecrypt.setSelected(false);
        hideShowAllEncrypt(true);
        hideShowAllDecrypt(false);
    }

    public void setRbDencryptPanel(){
        rbEncrypt.setSelected(false);
        hideShowAllEncrypt(false);
        hideShowAllDecrypt(true);
        List<File> userFiles = getUserContent();
        List<String> userContentFilesName = new ArrayList<String>();
        userFiles.forEach(x -> {
            userContentFilesName.add(x.getName());
        });
        cmbEncryptedContent.getItems().addAll(userContentFilesName);
    }

    public void hideShowAllEncrypt(boolean status){
        lChooseSourceCode.setVisible(status);
        lChooseHashAlgorithm.setVisible(status);
        lChooseEncryptAlgorithm.setVisible(status);
        lChooseSender.setVisible(status);

        bChooseSourceCode.setVisible(status);
        cmbHashAlgorihm.setVisible(status);
        cmbEncryptAlgorithm.setVisible(status);
        cmbReciver.setVisible(status);

        bSendEncryptedContent.setVisible(status);
    }
    public void hideShowAllDecrypt(boolean status){
        lChooseCryptContent.setVisible(status);

        cmbEncryptedContent.setVisible(status);

        bDecryptContent.setVisible(status);
        bCompileAndRun.setVisible(status);
    }

    public void hideAllDefault(){

        hideShowAllEncrypt(false);
        hideShowAllDecrypt(false);
    }


    @Override
    public void initialize(URL location, ResourceBundle resources) {
        hideAllDefault();
        bExit.setOnAction(x -> bExitAction());
        rbEncrypt.setOnAction(x -> setRbEncryptPanel());
        rbDecrypt.setOnAction(x -> setRbDencryptPanel());
        cmbEncryptAlgorithm.setOnAction(x -> chooseEncryptAlgorithmAction());
        cmbHashAlgorihm.setOnAction(x -> chooseHashAlgorithmAction());
        cmbEncryptedContent.setOnAction(x -> chooseEncryptedContentAction());
        bChooseSourceCode.setOnAction(x -> sourceCodeFileChooserAction());
        cmbReciver.setOnAction(x -> chooseReciverAction());
        bSendEncryptedContent.setOnAction(x -> sendEncryptedContentAction());
        bDecryptContent.setOnAction(x -> decryptContentAction());
        bCompileAndRun.setOnAction(x -> compileAndRunAction());


        cmbEncryptAlgorithm.getItems().addAll(aes,blowfish,des3);
        cmbHashAlgorihm.getItems().addAll(sha256withrsa,sha512withrsa);
        cmbReciver.getItems().addAll(User.userList.stream().filter(x -> !x.getUsername().equals(LoginController.currentUser.getUsername())).collect(Collectors.toList()));

        /*if(rbDecrypt.isSelected()){
            System.out.println("RRRRRRRRRRRRRRRR");
            List<File> userFiles = getUserContent();
            cmbEncryptedContent.getItems().addAll(userFiles.toString());
        }*/
    }

    private void wrongSelectFileType() {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle("Upozorenje");
        alert.setHeaderText("Pogresan fajl");
        alert.setContentText("Izaberite fajl sa ekstenzijom .java !");
        alert.showAndWait();
    }

    private void succesTransactionInfo() {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Obavjestenje");
        alert.setHeaderText("Fajl uspjesno poslat!");
        alert.setContentText("Fajl uspjesno poslat!");
        alert.showAndWait();
    }

    private void encryptedFileNotSelected() {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle("Upozorenje");
        alert.setHeaderText("Izaberite fajl kriptovani sadrzaj !");
        alert.setContentText("Izaberite fajl kriptovani sadrzaj !");
        alert.showAndWait();
    }

}
