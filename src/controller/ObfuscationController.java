package controller;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import model.User;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
    //public static final String des = "des";
    public static final String des = "DES";
    //public static final Integer desKeyBitSize = 112;
    public static final Integer desKeyBitSize = 56;
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

            byte[] decryptHeaderFromFile = decryptFileHeader(decodeFileHeader,LoginController.currentUser.getPrivateKey());
            System.out.println("DECRYPT FILE HEADER: "+decryptHeaderFromFile);

            String headerFileString = new String(decryptHeaderFromFile, 0, decryptHeaderFromFile.length, StandardCharsets.UTF_8);
            System.out.println("HEADER FILE STRING: "+headerFileString);

            byte[] sessionKey;

                sessionKey = Hex.decode(headerFileString.split("#")[1].getBytes("UTF-8")); // secret key
            System.out.println("SESSION KEY: " + sessionKey);
                byte[] digitalSignatureFromFile;
                try {
                    digitalSignatureFromFile = Hex.decode(fileContent.split("#")[2].getBytes(StandardCharsets.UTF_8));// VRATI OVO
                    System.out.println("DIGITAL SIGNATURE: "+digitalSignatureFromFile);
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
                byte[] textInByte = dencryptFileWithSesionKey(javaClassInByte, originalKey, headerFileString.split("#")[2]);
                String fileText = new String(textInByte,0,textInByte.length,StandardCharsets.UTF_8);

                if(verificationOfDigitalSignature(fileText.getBytes(), digitalSignatureFromFile,headerFileString.split("#")[3],User.getUser(headerFileString.split("#")[0]))){
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

        byte[] digitalSignatureOfDocument = digitalSignature(excetuteFile,cmbHashAlgorihm.getSelectionModel().getSelectedItem().toString(), LoginController.currentUser.getPrivateKey());
        SecretKey secretKey = generateSecretKey(cmbEncryptAlgorithm.getSelectionModel().getSelectedItem().toString());

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
            byte[] encryptHeaderFromFile = encryptFileHeader(fileHeaderByteBuffer, ((User) cmbReciver.getSelectionModel().getSelectedItem()).getPublicKey());
            Files.write(Paths.get(reciverContentPath), Base64.getEncoder().encodeToString(encryptHeaderFromFile).getBytes("UTF-8"), StandardOpenOption.CREATE);
            Files.write(Paths.get(reciverContentPath), "#".getBytes("UTF-8"), StandardOpenOption.APPEND);

            byte[] encFileWithSesKey = Base64.getEncoder().encodeToString(encryptFileWithSesionKey(excetuteFile, secretKey, cmbEncryptAlgorithm.getSelectionModel().getSelectedItem().toString())).getBytes("UTF-8");
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

        public static byte[] digitalSignature(File file, String hash, PrivateKey senderPrivateKey) {
        byte[] digitalSignatureData = null;
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file))) {
            Signature signature = Signature.getInstance(hash, "BC");
            signature.initSign(senderPrivateKey);

            while (bis.available() != 0) {
                byte[] buffer = new byte[bis.available() > 8192 * 10 ? 8192 : 1024];
                int readSize = bis.read(buffer);
                signature.update(buffer, 0, readSize);
            }
            digitalSignatureData = signature.sign();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        System.out.println("DIGITAL SIGNATURE: "+digitalSignatureData);
        return digitalSignatureData;
    }

    public static boolean verificationOfDigitalSignature(byte[] originalFile, byte[] didgitalSignatureData, String hash, User sender) {
        try {
            Signature signature = Signature.getInstance(hash, "BC");
            signature.initVerify(sender.getPublicKey());
            signature.update(originalFile);
            return signature.verify(didgitalSignatureData);
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

    public static byte[] encryptFileWithSesionKey(File file, SecretKey secretKey, String symmetricAlgorithm) {
        try {
            //  int size = symmetricAlgorithm.equals(ObfuscationController.aes) ? 16 : 8;
            int size = 0;
            if(symmetricAlgorithm.equals("AES")){
                size = 16; //16B block
                System.out.println("JESTE KOD ENKRIPCIJE 16");
            } else {
                size = 8;
            }
            byte[] vector = new byte[size];
            for (int i = 0; i < vector.length; i++) {
                vector[i] = secretKey.getEncoded()[i];
            }
            IvParameterSpec ivParameterSpec = new IvParameterSpec(vector);
            Cipher cipher = Cipher.getInstance(symmetricAlgorithm + "/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            return cipher.doFinal(Files.readAllBytes(file.toPath()));
        } catch (NoSuchAlgorithmException e) {
            Logger.getLogger(ObfuscationController.class.getName()).log(Level.SEVERE, null, e);
        } catch (NoSuchPaddingException e) {
            Logger.getLogger(ObfuscationController.class.getName()).log(Level.SEVERE, null, e);
        } catch (InvalidKeyException e) {
            Logger.getLogger(ObfuscationController.class.getName()).log(Level.SEVERE, null, e);
        } catch (IOException e) {
            Logger.getLogger(ObfuscationController.class.getName()).log(Level.SEVERE, null, e);
        } catch (BadPaddingException e) {
            Logger.getLogger(ObfuscationController.class.getName()).log(Level.SEVERE, null, e);
        } catch (IllegalBlockSizeException e) {
            Logger.getLogger(ObfuscationController.class.getName()).log(Level.SEVERE, null, e);
        } catch (InvalidAlgorithmParameterException e) {
            Logger.getLogger(ObfuscationController.class.getName()).log(Level.SEVERE, null, e);
        }
        return null;
    }

    public static byte[] dencryptFileWithSesionKey(byte[] file, SecretKey secretKey, String symmetricAlgorithm) {
        try {
            //int size = symmetricAlgorithm.equals(ObfuscationController.aes) ? 16 : 8;
            int size = 0;
            if(symmetricAlgorithm.equals("AES")){
                System.out.println("JESTE KOD DEKRIPCIJE 16");
                size = 16;
            } else {
                size = 8;
            }
            byte[] vector = new byte[size];
            for (int i = 0; i < vector.length; i++) {
                vector[i] = secretKey.getEncoded()[i];
            }
            IvParameterSpec ivParameterSpec = new IvParameterSpec(vector);
            Cipher cipher = Cipher.getInstance(symmetricAlgorithm + "/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            return cipher.doFinal(file);
        } catch (NoSuchAlgorithmException e) {
            Logger.getLogger(ObfuscationController.class.getName()).log(Level.SEVERE, null, e);
        } catch (NoSuchPaddingException e) {
            Logger.getLogger(ObfuscationController.class.getName()).log(Level.SEVERE, null, e);
        } catch (InvalidKeyException e) {
            Logger.getLogger(ObfuscationController.class.getName()).log(Level.SEVERE, null, e);
        } catch (BadPaddingException e) {
            Logger.getLogger(ObfuscationController.class.getName()).log(Level.SEVERE, null, e);
        } catch (IllegalBlockSizeException e) {
            Logger.getLogger(ObfuscationController.class.getName()).log(Level.SEVERE, null, e);
        } catch (InvalidAlgorithmParameterException e) {
            Logger.getLogger(ObfuscationController.class.getName()).log(Level.SEVERE, null, e);
        }
        return null;
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


        cmbEncryptAlgorithm.getItems().addAll(aes,blowfish,des);
        cmbHashAlgorihm.getItems().addAll(sha256withrsa,sha512withrsa);
        cmbReciver.getItems().addAll(User.userList.stream().filter(x -> !x.getUsername().equals(LoginController.currentUser.getUsername())).collect(Collectors.toList()));

    }

    public static SecretKey generateSecretKey(String symmetricAlgorithm) {  // session key http://tutorials.jenkov.com/java-cryptography/keygenerator.html
        SecretKey secretKey = null;
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(symmetricAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        switch (symmetricAlgorithm) {
            case ObfuscationController.aes:
                keyGenerator.init(ObfuscationController.aesKeyBitSize, new SecureRandom());
                break;
            case ObfuscationController.blowfish:
                keyGenerator.init(ObfuscationController.blowfishKeyBitSize, new SecureRandom());
                break;
            case ObfuscationController.des:
                keyGenerator.init(ObfuscationController.desKeyBitSize, new SecureRandom());
                break;
        }
        secretKey = keyGenerator.generateKey();
        return secretKey;
    }

    public  byte[] encryptFileHeader(ByteBuffer header, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(header.array());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public  byte[] decryptFileHeader(byte[] header, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(header);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
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
