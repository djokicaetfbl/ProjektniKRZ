module ProjektniKRZ {
    requires javafx.fxml;
    requires javafx.graphics;
    requires javafx.base;
    requires javafx.controls;
    requires java.logging;
    requires org.bouncycastle.provider;

    opens main;
    opens controller;
    opens view;
}