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
import java.security.PrivateKey;
import java.util.Base64;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

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

    }

    public void decryptModeAction() {

    }

    public void encryptModeAction() {

    }



    public void sendEncryptedContentAction() {

        userContentPath = System.getProperty("user.dir") + File.separator+ "users" + File.separator + cmbReciver.getSelectionModel().getSelectedItem().toString()+File.separator + "userContent";
        if(!new File(userContentPath).exists()){
            new File(userContentPath).mkdir();
        }

        byte[] digitalSignatureOfDocument = Services.digitalSignature(excetuteFile,cmbHashAlgorihm.getSelectionModel().getSelectedItem().toString(), LoginController.currentUser.getPrivateKey());
        SecretKey secretKey = Services.generateSecretKey(cmbEncryptAlgorithm.getSelectionModel().getSelectedItem().toString());

        System.out.println("Digital signature: "+digitalSignatureOfDocument);
        System.out.println("Secret session key1: "+secretKey.getEncoded());
        System.out.println("Secret session key2: "+ Hex.toHexString(secretKey.getEncoded()));

        ByteBuffer fileHeaderByteBuffer =  ByteBuffer.allocate(excetuteFile.getName().getBytes(StandardCharsets.UTF_8).length + cmbHashAlgorihm.getSelectionModel().getSelectedItem().toString().length()
        + cmbEncryptAlgorithm.getSelectionModel().getSelectedItem().toString().length()+ Hex.toHexString(secretKey.getEncoded()).length() + 4*("#".getBytes(StandardCharsets.UTF_8).length)
        + LoginController.currentUser.getUsername().getBytes(StandardCharsets.UTF_8).length);

        fileHeaderByteBuffer.put(excetuteFile.getName().getBytes(StandardCharsets.UTF_8));
        fileHeaderByteBuffer.put(cmbHashAlgorihm.getSelectionModel().getSelectedItem().toString().getBytes(StandardCharsets.UTF_8));
        fileHeaderByteBuffer.put(cmbEncryptAlgorithm.getSelectionModel().getSelectedItem().toString().getBytes(StandardCharsets.UTF_8));
        fileHeaderByteBuffer.put(Hex.toHexString(secretKey.getEncoded()).getBytes(StandardCharsets.UTF_8));
        fileHeaderByteBuffer.put("#".getBytes(StandardCharsets.UTF_8));
        fileHeaderByteBuffer.put(LoginController.currentUser.getUsername().getBytes(StandardCharsets.UTF_8));

        String reciverContentPath = userContentPath+File.separator + excetuteFile.getName().toString()+".enc";
        if(! new File(reciverContentPath).exists()) {
            try {
                new File(reciverContentPath).createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        System.out.println("RECIVER PATH: "+reciverContentPath);
        Cipher cipher = null;
        try {
             cipher = Cipher.getInstance("RSA");
             cipher.init(Cipher.ENCRYPT_MODE,((User)cmbReciver.getSelectionModel().getSelectedItem()).getPublicKey());
             Files.write(Paths.get(reciverContentPath), Base64.getEncoder().encodeToString(cipher.doFinal(fileHeaderByteBuffer.array())).getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE);
             Files.write(Paths.get(reciverContentPath), "#".getBytes(StandardCharsets.UTF_8),StandardOpenOption.APPEND);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
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

    }

    private static void wrongSelectFileType() {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle("Upozorenje");
        alert.setHeaderText("Pogresan fajl");
        alert.setContentText("Izaberite fajl sa ekstenzijom .java !");
        alert.showAndWait();
    }
}
