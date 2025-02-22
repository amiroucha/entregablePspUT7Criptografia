package org.example;

import javax.crypto.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class Main {
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
        String fichCifrado = "proyectoCifrado.zip";
        String fichDescifrado = "proyectoDescifrado.zip";
        System.out.println("Introduce una semilla para cifrar");
        String semilla  = leer.nextLine();
        secureRandom.setSeed(semilla.getBytes());
        SecretKey claveSecret = generarClaveSecreta();

        cifrarFichero(fichero, fichCifrado, claveSecret);
        descifrarFichero(fichCifrado, fichDescifrado, claveSecret);
    }
    public static SecretKey generarClaveSecreta(){
        SecretKey clave;
        try{
            //1. Crear e inicializar clave
            System.out.println("Genero clave secreta AES");
            //crea un objeto para generar la clave usando algoritmo AES
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128, secureRandom); //se indica el tamaño de la clave
            clave = keyGen.generateKey(); //genera la clave privada
            //System.out.println("clave secreta AES: "+clave);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return clave;
    }
    //método que encripta el fichero que se pasa como parámetro
    //devuelve el valor de la clave privada utilizada en encriptación
    //El fichero encriptado lo deja en el archivo de nombre fichero.cifrado
    //en el mismo directorio
    public static void cifrarFichero(File fichero, String ficheroCifrado, SecretKey claveSecreta) {
        FileInputStream fichEntrada = null; //fichero de entrada
        FileOutputStream fichSalida = null; //fichero de salida
        int bytesLeidos;
        try {
            //Se Crea el objeto Cipher para cifrar, utilizando el algoritmo AES
            Cipher cifrador = Cipher.getInstance("AES");
            //Se inicializa el cifrador en modo CIFRADO o ENCRIPTACIÓN
            cifrador.init(Cipher.ENCRYPT_MODE, claveSecreta);
            System.out.println("Cifrar el fichero con AES: " + ficheroCifrado);
            //declaración de objetos
            byte[] buffer = new byte[1000]; //array de bytes
            byte[] bufferCifrado;
            fichEntrada = new FileInputStream(fichero); //objeto fichero de entrada
            fichSalida = new FileOutputStream(ficheroCifrado); //fichero de salida
            //lee el fichero de 1k en 1k y pasa los fragmentos leidos al cifrador
            bytesLeidos = fichEntrada.read(buffer, 0, 1000);
            while (bytesLeidos != -1) {//mientras no se llegue al final del fichero
                //pasa texto claro al cifrador y lo cifra, asignándolo a bufferCifrado
                bufferCifrado = cifrador.update(buffer, 0, bytesLeidos);
                fichSalida.write(bufferCifrado); //Graba el texto cifrado en fichero
                bytesLeidos = fichEntrada.read(buffer, 0, 1000);
            }
            bufferCifrado = cifrador.doFinal(); //Completa el cifrado
            fichSalida.write(bufferCifrado); //Graba el final del texto cifrado, si lo hay
            //Cierra ficheros
            fichEntrada.close();
            fichSalida.close();

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | IllegalBlockSizeException |
                 InvalidKeyException | BadPaddingException e) {
            System.err.println("Error cifrando el fichero: "+e.getMessage());
        }
    }

    public static void descifrarFichero(String cifrado, String descifrado, SecretKey claveSecreta) {
        FileInputStream fe = null; //fichero de entrada
        FileOutputStream fs = null; //fichero de salida
        int bytesLeidos;
        Cipher cifrador = null;
        try {
            cifrador = Cipher.getInstance("AES");
          // Poner cifrador en modo DESCIFRADO o DESENCRIPTACIÓN
            cifrador.init(Cipher.DECRYPT_MODE, claveSecreta);
            System.out.println("Descifrar con AES el fichero: " + cifrado + ", y dejar en " + descifrado);
            fe = new FileInputStream(cifrado);
            fs = new FileOutputStream(descifrado);
            byte[] bufferClaro;
            byte[] buffer = new byte[1000]; //array de bytes
            //lee el fichero de 1k en 1k y pasa los fragmentos leidos al cifrador
            bytesLeidos = fe.read(buffer, 0, 1000);
            while (bytesLeidos != -1) {//mientras no se llegue al final del fichero
                //pasa texto cifrado al cifrador y lo descifra, asignándolo a bufferClaro
                bufferClaro = cifrador.update(buffer, 0, bytesLeidos);
                fs.write(bufferClaro); //Graba el texto claro en fichero
                bytesLeidos = fe.read(buffer, 0, 1000);
            }
            bufferClaro = cifrador.doFinal(); //Completa el descifrado
            fs.write(bufferClaro); //Graba el final del texto claro, si lo hay
            //cierra archivos
            fe.close();
            fs.close();

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException e) {
            System.err.println("Error Descifrando el fichero: "+e.getMessage());
        }
    }
}