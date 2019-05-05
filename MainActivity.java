package com.example.toxicr0ak.chatapp;

import android.content.Intent;
import android.os.AsyncTask;
import android.provider.ContactsContract;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.spec.DHParameterSpec;

public class MainActivity extends AppCompatActivity {

    BigInteger g = BigInteger.valueOf(2L);
    BigInteger p = new BigInteger("18357791004747480842958528379279554767764672208525277991193507400601884088686409041485294022012605475183735006493571957311007350724088717676291537145404805223642304991346243867120382644793071971119314784888272224306871621518294391947554148579725185700338740654489080888391946540290022517231272700475110217059863713162435684037634639560710161609856558219003735913030933974177670933978437424257780734434796607812490480802212407458466273062378788903023678329101250947346591759196651983154250020019089500683618829709986284878516538147628272228578606738973835857158820058523459752007299749309230034883616537267183101957421");
    static SecureRandom random = new SecureRandom();
    protected static byte[] signedDHPub;
    protected static PublicKey dhPub;
    protected static PrivateKey dhPriv;
    protected  static PublicKey rsaPub;
    protected  static PrivateKey rsaPriv;

    @Override
    protected void onCreate(Bundle savedInstanceState){
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        new genAllKeys().execute();
    }



    public static String getHexString(byte[] b) throws Exception {
        String result = "";
        for (int i=0; i < b.length; i++) {
            result += Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
    }

    protected static String doSHA256(String plainstr)throws Exception{
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hashByte = sha.digest(plainstr.getBytes(StandardCharsets.UTF_8));
        String hexHash = getHexString(hashByte);
        return hexHash;
    }

    protected static KeyPair genDHKeyPair(BigInteger p,BigInteger g)throws Exception{
        DHParameterSpec dhParams = new DHParameterSpec(p,g);
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DiffieHellman");
        kpGen.initialize(dhParams, new SecureRandom());
        KeyPair keyPair = kpGen.generateKeyPair();
        return keyPair;

    }

    public static KeyPair genRSAKeyPair() throws Exception{
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = kpGen.generateKeyPair();
        return keyPair;
    }

    public static byte[] signKeyWithRSA(PublicKey dhPub, PrivateKey rsaPriv)throws Exception{
        Signature sign = Signature.getInstance("SHA1withRSA");
        sign.initSign(rsaPriv, random);
        byte[] dhPubByte = dhPub.getEncoded();
        sign.update(dhPubByte);
        byte[] signedKeyByte = sign.sign();
        return signedKeyByte;
    }

    protected class genAllKeys extends AsyncTask<Void, Void, Void>{

        protected void onPreExecute() {
            super.onPreExecute();
        }

        @Override
        protected Void doInBackground(Void... voids) {
            try {
                KeyPair dhKeyPair = genDHKeyPair(p, g);
                KeyPair rsaKeyPair = genRSAKeyPair();
                dhPriv = dhKeyPair.getPrivate();
                dhPub = dhKeyPair.getPublic();
                rsaPriv = rsaKeyPair.getPrivate();
                rsaPub = rsaKeyPair.getPublic();
                System.out.println(dhPriv);
                System.out.println(rsaPriv);
                DatabaseHelper databaseHelper = new DatabaseHelper(MainActivity.this);
                databaseHelper.insertKeys(rsaPriv.getEncoded(),rsaPub.getEncoded(),dhPriv.getEncoded(),dhPub.getEncoded());
                System.out.println("Keys have been inserted in the database!");
                System.out.println(Base64.encodeToString(dhPub.getEncoded(),Base64.DEFAULT|Base64.NO_WRAP));
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }

        @Override
        protected void onPostExecute(Void aVoid) {
            super.onPostExecute(aVoid);
        }
    }


    public class signInUser extends AsyncTask<String, Void, Boolean>{
        String username = null;
        String password = null;

        @Override
        protected void onPreExecute() {
            super.onPreExecute();
        }

        @Override
        protected Boolean doInBackground(String... strings) {
            boolean methodSucc = false;
            EditText etUsername = findViewById(R.id.username);
            EditText etPassword = findViewById(R.id.password);
            username = etUsername.getText().toString();
            String password = etPassword.getText().toString();

            try {
                System.out.println("Connecting to server... ");
                Socket socket = new Socket("192.168.0.123", 25000);
                System.out.println("Connected to server");
                InputStream inputStream = socket.getInputStream();
                System.out.println("After inputstream");
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                System.out.println("after bufferedreader");
                OutputStream outputStream = socket.getOutputStream();
                System.out.println("after outputstream");
                PrintWriter printWriter = new PrintWriter(outputStream);
                System.out.println("after printwrtier");
                String hashedPwd = doSHA256(password);
                System.out.println("hashesPwd is "+hashedPwd);
                sendMsg(printWriter,"3");
                System.out.println(" 3 has been sent to server");
                String serverInput;
                if ((serverInput = bufferedReader.readLine()).equals("3")){
                    sendMsg(printWriter,username);
                    System.out.println("username "+username+ " has been sent");
                    sendMsg(printWriter, hashedPwd);
                    System.out.println("password "+hashedPwd+" has been sent");
                    String input2;
                    input2 = bufferedReader.readLine();
                    System.out.println("serverinput is "+input2);
                    if (input2.equals("Signin Success")){
                        methodSucc = true;
                        System.out.println("methodSucc is true");
                    }
                    if (input2.equals("Signin Failure")){
                        methodSucc = false;
                        System.out.println("methodSucc is false");
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return methodSucc;
        }

        @Override
        protected void onPostExecute(Boolean aBoolean) {
            if (aBoolean){
                Intent intent = new Intent(MainActivity.this, homeScreen.class);
                intent.putExtra("username", username);
                startActivity(intent);
            }
            if (aBoolean==false){
                Toast.makeText(MainActivity.this,"User credentials are wrong. Please try again.",Toast.LENGTH_LONG).show();
            }
        }
    }

    public void registerUser(View view){
        new regUserAsync().execute();
    }

    public class regUserAsync extends AsyncTask<String, Void, Boolean>{

        String username;
        String password;

        @Override
        protected void onPreExecute() {
            super.onPreExecute();
        }

        @Override
        protected void onProgressUpdate(Void... values) {
            super.onProgressUpdate(values);
        }

        @Override
        protected Boolean doInBackground(String... strings) {

            try {
                signedDHPub = signKeyWithRSA(dhPub,rsaPriv);
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.out.println("Signed DH Public Key is "+signedDHPub);
            Socket socket;
            EditText etUsername = findViewById(R.id.username);
            EditText etPassword = findViewById(R.id.password);
            username = etUsername.getText().toString();
            password = etPassword.getText().toString();
            boolean methodSucc = false;
            try {
                System.out.println("Connecting to server... ");
                socket = new Socket("192.168.0.123",25000);
                System.out.println("Connected to server");
                InputStream inputStream = socket.getInputStream();
                System.out.println("After inputstream");
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                System.out.println("after bufferedreader");
                OutputStream outputStream = socket.getOutputStream();
                System.out.println("after outputstream");
                PrintWriter printWriter = new PrintWriter(outputStream);
                System.out.println("after printwrtier");
                DataOutputStream dataOS = new DataOutputStream(outputStream);
                System.out.println("aftre dataoutputstream");
                String hashedPwd = doSHA256(password);
                System.out.println("hashesPwd is "+hashedPwd);
                //array.add("2");
                sendMsg(printWriter,"2");
                //printWriter.println(array);
                System.out.println(" 2 has been sent to server");
                //printWriter.flush();
                //array.clear();
                String serverInput;
                if ((serverInput = bufferedReader.readLine()).equals("2")){
                    sendMsg(printWriter,username);
                    System.out.println("username "+username+ " has been sent");
                    sendMsg(printWriter, hashedPwd);
                    System.out.println("password "+hashedPwd+" has been sent");
                    String input2;
                    input2 = bufferedReader.readLine();
                    System.out.println("serverinput is "+input2);
                    if (input2.equals("2.1")){
                        dataOS.writeInt(signedDHPub.length);
                        dataOS.write(signedDHPub);
                        System.out.println("after signedDHPub"+signedDHPub+ " has been written to dataOS");
                        dataOS.writeInt(rsaPub.getEncoded().length);
                        dataOS.write(rsaPub.getEncoded());
                        System.out.println("after rsaPub.encoded"+rsaPub.getEncoded() +" has been written to dataOS");
                        dataOS.writeInt(dhPub.getEncoded().length);
                        dataOS.write(dhPub.getEncoded());
                        System.out.println("after DHPub.encoded" +dhPub.getEncoded() +" has been written to dataOS");
                        String input3 = bufferedReader.readLine();
                        System.out.println("Value of input3 is "+input3);
                        if (input3.equals("Register Success")){
                            methodSucc = true;
                            System.out.println("methodSucc is true");
                        }
                        if (input3.equals("Register Failure")){
                            methodSucc = false;
                            System.out.println("methodSucc is false");
                        }
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }

            return methodSucc;
        }

        @Override
        protected void onPostExecute(Boolean aBoolean) {
            if (aBoolean){
                Intent intent = new Intent(MainActivity.this,homeScreen.class);
                intent.putExtra("username",username);
                startActivity(intent);

            }
            if (aBoolean==false){
                Toast.makeText(MainActivity.this,"Registering failed. Please try again",Toast.LENGTH_LONG).show();
            }

        }
    }

    public void loginUser(View view) {
        new signInUser().execute();
    }
    public void sendMsg(PrintWriter pw, String msg){
        pw.println(msg);
        pw.flush();
    }
}

