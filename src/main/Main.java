package main;

import controller.LoginController;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import model.User;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main extends Application {

    private static byte[] generateSalt(final int lenght) {
        byte[] salt = new byte[lenght];
        try {
            SecureRandom   secureRandom = SecureRandom.getInstanceStrong();
            secureRandom.nextBytes(salt);
        } catch (NoSuchAlgorithmException e) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, e);
        }
        return salt;
    }

    public static void createUser(String username,String password){
        File filePassword = new File(System.getProperty("user.dir")+File.separator+"users"+File.separator+username+File.separator+username+".txt");

        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] salt = generateSalt(32);
        messageDigest.reset(); // za svaki slucaj da ponisti stanje, obicno ako ako sam vec koristio tu instancu od MessageDigest, dakle cilj je da sva prethodna podesavanja pocisti
        messageDigest.update(salt); // ucitavanje salt-a

        User newUser = new User(username);
        User.userList.add(newUser);
        byte[] passwordHashWithSalt = messageDigest.digest(password.getBytes(StandardCharsets.UTF_8));
        try {
            Files.write(filePassword.toPath(), (Base64.getEncoder().encodeToString(passwordHashWithSalt) + "#" + Base64.getEncoder().encodeToString(salt)).getBytes(), StandardOpenOption.CREATE);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws IOException {
        try {
            Handler handler = new FileHandler("./error.log");
            Logger.getLogger("").addHandler(handler);
        } catch (IOException | SecurityException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
        Security.addProvider(new BouncyCastleProvider());
        createUser("user1","user1");
        createUser("user2","user2");
        createUser("user3","user3");

//        LoginController.userDeserialization();

        User.userList.forEach(System.out::println);
        System.out.println("-------------------------------------------");
        User.userList.forEach(x -> System.out.println(x.getPrivateKey()));
        System.out.println("###########################################");
        User.userList.forEach(x -> System.out.println(x.getPublicKey()));

        final FXMLLoader loader = new FXMLLoader(getClass().getResource("/view/Login.fxml"));
        LoginController loginController = null;
        loader.setController(loginController);
        Parent root = loader.load();
        Scene scene = new Scene(root);
        primaryStage.setScene(scene);
        primaryStage.setResizable(false);
        primaryStage.setTitle("Login");
        primaryStage.getIcons().add(new Image(Main.class.getResourceAsStream("/resources/Ethereum.png")));
        primaryStage.show();


    }
}
