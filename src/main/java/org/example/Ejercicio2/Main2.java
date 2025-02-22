package org.example.Ejercicio2;

import javax.crypto.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Scanner;

public class Main2 {
    public static Scanner leer = new Scanner(System.in);
    public static SecureRandom secureRandom = new SecureRandom();

    public static void main(String[] args) {
        System.out.println("Introduce un fichero existente");
        String nombreFich = leer.nextLine();
        File fichero = new File(nombreFich);
        //compruebo que el fichero exista
        while (!fichero.exists()) {
            System.out.println("El fichero no existe, intentalo de nuevo");
            nombreFich = leer.nextLine();
            fichero =  new File(nombreFich);
        }
        String fichCifrado = "fichero1Cifrado.txt";
        String fichDescifrado = "fichero1Descifrado.txt";
        System.out.println("Introduce una semilla para cifrar");
        String semilla  = leer.nextLine();
        secureRandom.setSeed(semilla.getBytes());
        KeyPair clavesRSA = generarClaveSecreta();

        cifrarFichero(fichero, fichCifrado, clavesRSA.getPublic());//cifro con la publica
        descifrarFichero(fichCifrado, fichDescifrado, clavesRSA.getPrivate());//descifro con la privada
        System.out.println("Cifrado asimetrico completado correctamente");
    }
    public static KeyPair generarClaveSecreta(){
        KeyPair clavesRSA;
        try{
            System.out.println("Genero las claves privadas y publicas");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024, secureRandom);//tamaño de la clave
            clavesRSA = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return clavesRSA;
    }
    //método que encripta el fichero que se pasa como parámetro
    //devuelve el valor de la clave privada utilizada en encriptación
    //El fichero encriptado lo deja en el archivo de nombre fichero.cifrado
    //en el mismo directorio
    public static void cifrarFichero(File fichero, String ficheroCifrado, PublicKey claveSecreta) {
        try {
            FileInputStream fichEntrada = new FileInputStream(fichero); //fichero de entrada
            FileOutputStream fichSalida = new FileOutputStream(ficheroCifrado); //fichero de salida

            //Se Crea el objeto Cipher para cifrar, utilizando el algoritmo
            Cipher cifrador = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            //Se inicializa el cifrador en modo CIFRADO o ENCRIPTACIÓN
            cifrador.init(Cipher.ENCRYPT_MODE, claveSecreta);

            System.out.println("Cifro el fichero utilizando RSA/ECB/OAEPWithSHA-256AndMGF1Padding: " + ficheroCifrado);

            //declaración de objetos
            byte[] buffer = new byte[62]; //array de bytes
            byte[] bufferCifrado;

            int bytesLeidos ;
            while ((bytesLeidos = fichEntrada.read(buffer)) != -1) {//mientras no se llegue al final del fichero
                bufferCifrado = cifrador.doFinal(buffer, 0, bytesLeidos);
                fichSalida.write(bufferCifrado); //Graba el texto cifrado en fichero
            }
            //Cierra ficheros
            fichEntrada.close();
            fichSalida.close();
            System.out.println("Archivo cifrado guardado como: " + ficheroCifrado);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | IllegalBlockSizeException |
                 InvalidKeyException | BadPaddingException e) {
            System.err.println("Error cifrando el fichero: "+e.getMessage());
        }
    }

    public static void descifrarFichero(String cifrado, String descifrado, PrivateKey claveSecreta) {
        try {
            FileInputStream fe  = new FileInputStream(cifrado); //fichero de entrada
            FileOutputStream fs = new FileOutputStream(descifrado); //fichero de salida

            Cipher cifrador = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
          // Poner cifrador en modo DESCIFRADO
            cifrador.init(Cipher.DECRYPT_MODE, claveSecreta);

            System.out.println("Descifro el fichero: " + cifrado + " utilizando RSA/ECB/OAEPWithSHA-256AndMGF1Padding :  " + descifrado);

            byte[] bufferCifra = new byte[128]; //array de bytes
            byte[] bufferClaro;

            int bytesLeidos;
            while ((bytesLeidos = fe.read(bufferCifra))!= -1) {//mientras no se llegue al final del fichero
                //pasa texto cifrado al cifrador y lo descifra, asignándolo a bufferClaro
                bufferClaro = cifrador.doFinal(bufferCifra, 0, bytesLeidos);
                fs.write(bufferClaro); //Graba el texto claro en fichero
            }
            fe.close();
            fs.close();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException e) {
            System.err.println("Error Descifrando el fichero: "+e.getMessage());
        }
    }
}