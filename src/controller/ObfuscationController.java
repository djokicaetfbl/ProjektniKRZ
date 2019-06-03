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
