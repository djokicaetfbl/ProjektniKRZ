package controller;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import main.Main;

import java.io.IOException;
import java.net.URL;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

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

    }

    public void sourceCodeFileChooserAction() {

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
    }
}
