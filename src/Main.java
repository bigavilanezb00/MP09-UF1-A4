import javax.crypto.BadPaddingException;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws IOException {

        System.out.println("1.5 - Xifrar i desxifrar un text en clar amb una clau generada amb el codi 1.1.1");
        SecretKey clau1 = UtilitatsXifrar.keygenKeyGeneration(128);

        // Xifra i desxifra un text amb la clau generada anteriorment
        String text1 = "Això és un text en clar.";
        byte[] textXifrat1 = UtilitatsXifrar.encryptData(text1.getBytes(), clau1);
        byte[] textDesxifrat1 = UtilitatsXifrar.decryptData(textXifrat1, clau1);
        System.out.println("Text en clar: " + text1);
        System.out.println("Text xifrat: " + new String(textXifrat1));
        System.out.println("Text desxifrat: " + new String(textDesxifrat1));

        // Genera una clau secreta a partir d'una paraula de pas
        String password = "micontrasenya";
        SecretKey clau2 = UtilitatsXifrar.passwordKeyGeneration(password, 128);

        // Xifra i desxifra un text amb la clau generada a partir de la paraula de pas
        System.out.println("1.6 - Xifrar i desxifrar un text en clar amb una clau (codi 1.1.2) generada a partir de la paraula de pas.");
        String text2 = "Aquesta és una altra frase per xifrar.";
        byte[] textXifrat2 = UtilitatsXifrar.encryptData(text2.getBytes(), clau2);
        byte[] textDesxifrat2 = UtilitatsXifrar.decryptData(textXifrat2, clau2);
        System.out.println("Text en clar: " + text2);
        System.out.println("Text xifrat: " + new String(textXifrat2));
        System.out.println("Text desxifrat: " + new String(textDesxifrat2));

        // Prova alguns dels mètodes de la classe SecretKey
        System.out.println("1.7 - Prova alguns dels mètodes que proporciona la classe SecretKey");
        String algorisme = clau2.getAlgorithm();
        byte[] encoded = clau2.getEncoded();
        String format = clau2.getFormat();
        System.out.println("Algorisme de la clau: " + algorisme);
        System.out.println("Clau codificada en bytes: " + new String(encoded));
        System.out.println("Format de la clau: " + format);

        // Desxifra el text del punt 6 amb una paraula de pas incorrecte
        System.out.println("1.8 - Desxifra el text del punt 6 i comprova que donant una paraula de pas incorrecte salta l'excepció BadPaddingException");
        Scanner scanner = new Scanner(System.in);
        System.out.println("Introdueix una paraula de pas incorrecte: ");
        String passwordIncorrecte = scanner.nextLine();
        SecretKey clauIncorrecta = UtilitatsXifrar.passwordKeyGeneration(passwordIncorrecte, 128);
        byte[] textDesxifratIncorrecte = UtilitatsXifrar.decryptData(textXifrat2, clauIncorrecta);
        System.out.println("Text desxifrat amb la paraula de pas incorrecte: " + new String(textDesxifratIncorrecte));


        // Exercici 2
        System.out.println("2 - Donat un text xifrat (textamagat) amb algoritme estàndard AES i clau simètrica generada amb el\n" +
                "mètode SHA-256 a partir d’una contrasenya, i donat un fitxer (clausA4.txt) on hi ha possibles\n" +
                "contrasenyes correctes, fes un programa per trobar la bona i desxifrar el missatge.");

        Path path = Paths.get("textamagat.crypt");
        byte[] textenbytes = Files.readAllBytes(path);

        File f = new File("clausA4.txt");
        FileReader fr = new FileReader(f);

        BufferedReader bufferedReader = new BufferedReader(fr);
        String line = bufferedReader.readLine();
        while(line != null ) {
            SecretKey secretKey = UtilitatsXifrar.passwordKeyGeneration(line,128);
            byte[] result = UtilitatsXifrar.decryptData(textenbytes,secretKey);
            String desencriptar = new String(result,0,result.length);
            System.out.println("Mensaje: " + desencriptar);
            line = bufferedReader.readLine();
        }

    }



}