package com.example.toxicr0ak.chatapp;

import android.content.Intent;
import android.os.AsyncTask;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;

public class homeScreen extends AppCompatActivity {

    HashMap<String, String> ipList = new HashMap<String, String>();
    HashMap<String, ArrayList<String>> msgQHolder = new HashMap<>();
    static ArrayList<String> arrayList =  new ArrayList<String>();
    String self;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_home_screen);
        TextView textView = findViewById(R.id.textView);
        Intent intent = getIntent();
        self = intent.getStringExtra("username");
        textView.setText("Hello, "+self);
        new whichUsersOnline().execute();
    }

    /*public class listenForConnections extends AsyncTask<Void, Void, Void>{

        @Override
        protected Void doInBackground(Void... voids) {
            ServerSocket serverSocket = null;
            {
                try {
                    serverSocket = new ServerSocket(27000);
                    while (true){
                        Socket socket = serverSocket.accept();
                        String username = ipList.get(socket.getInetAddress().getHostAddress());
                        System.out.println("Connected to "+ username);
                        InputStream inputStream = socket.getInputStream();
                        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                        String heComes;
                        ArrayList<String> msgQ = new ArrayList<>();
                        while (true){
                            if ((heComes = bufferedReader.readLine())!=null){
                                msgQ.add(heComes);
                                msgQHolder.put(username, msgQ);
                                System.out.println("username and message have been added to msgQHolder");
                            }
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
                try {
                    while (true){
                        Socket socket = serverSocket.accept();
                        System.out.println("socket connected on "+socket.getInetAddress().getHostAddress());
                        InputStream inputStream = socket.getInputStream();
                        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));

                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
                return null;
            }
    }*/

    public class whichUsersOnline extends AsyncTask<Void, Void, Boolean> {

        @Override
        protected Boolean doInBackground(Void... voids) {
            System.out.println("Connecting to server... ");
            Socket socket;
            boolean result = false;
            arrayList.clear();

            try {
                socket = new Socket("192.168.0.123", 25000);
                System.out.println("Connected to server");
                InputStream inputStream = socket.getInputStream();
                System.out.println("After inputstream");
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                System.out.println("after bufferedreader");
                OutputStream outputStream = socket.getOutputStream();
                System.out.println("after outputstream");
                PrintWriter printWriter = new PrintWriter(outputStream);
                System.out.println("after printwrtier");

                String username;

                sendMsg(printWriter, "5");
                System.out.println("After sending 5 to server");

                String serverRes;
                while ((serverRes = bufferedReader.readLine()) != null) {
                    System.out.println("serverres is: "+serverRes);
                    String[] splitStr = serverRes.split(":");
                    username = splitStr[0];
                    String usernameIp = splitStr[1];
                    ipList.put(username, usernameIp);
                    System.out.println("username is: "+username+ " and its ip is "+usernameIp);
                    printWriter.println("5.1");
                    printWriter.flush();
                    System.out.println("After 5.1 has been sent to server");
                    DataInputStream dataInputStream = new DataInputStream(inputStream);
                    byte[] userSignedDHPub = readDataIn(dataInputStream);
                    byte[] userDHPub = readDataIn(dataInputStream);
                    byte[] userSignedRSAPub = readDataIn(dataInputStream);
                    byte[] userRSAPub = readDataIn(dataInputStream);
                    byte[] serverRSAPub = readDataIn(dataInputStream);

                    KeyFactory dhkeyFactory = KeyFactory.getInstance("DiffieHellman");
                    KeyFactory rsakeyFactory = KeyFactory.getInstance("RSA");

                    X509EncodedKeySpec x509EncodedKeySpec2 = new X509EncodedKeySpec(userDHPub);
                    PublicKey restoredDHPub = dhkeyFactory.generatePublic(x509EncodedKeySpec2);

                    X509EncodedKeySpec x509EncodedKeySpec4 = new X509EncodedKeySpec(userRSAPub);
                    PublicKey restoredRSAPub = rsakeyFactory.generatePublic(x509EncodedKeySpec4);

                    X509EncodedKeySpec x509EncodedKeySpec5 = new X509EncodedKeySpec(serverRSAPub);
                    PublicKey restoredServerRSAPub = rsakeyFactory.generatePublic(x509EncodedKeySpec5);

                    boolean dhverify = verifySign(userSignedDHPub, restoredServerRSAPub, restoredDHPub);
                    boolean rsaverify = verifySign(userSignedRSAPub, restoredServerRSAPub, restoredRSAPub);

                    if (dhverify & rsaverify) {
                        System.out.println("dhverify and rsaverify and true");
                        arrayList.add(username);
                        result = true;


                    }
                    else{
                        result = false;
                    }
                }

            } catch (IOException | InvalidKeySpecException | InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            return result;
        }

        @Override
        protected void onPostExecute(Boolean aVoid) {
            if (aVoid) {
                final ListView listView = findViewById(R.id.userlist);
                System.out.println("arraylist is "+arrayList);
                ArrayAdapter<String> arrayAdapter = new ArrayAdapter<>(homeScreen.this, android.R.layout.simple_list_item_1, arrayList);
                listView.setAdapter(arrayAdapter);
                System.out.println("After setaddapter and clearing arraylist");
                listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                    @Override
                    public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                        String username = listView.getItemAtPosition(position).toString();
                        DatabaseHelper databaseHelper = new DatabaseHelper(homeScreen.this);
                        //byte[] dhPubKey = databaseHelper.extractDHPK(username);
                        Intent intent = new Intent(homeScreen.this, messageScreen.class);
                        intent.putExtra("username", username);
                        intent.putExtra("ipadr",ipList.get(username));
                        intent.putExtra("self", self);
                        //intent.putExtra("dhPub",dhPubKey);
                        startActivity(intent);
                    }
                });
            } else {
                Toast.makeText(homeScreen.this, "Some key signature/s was/were invalid", Toast.LENGTH_SHORT).show();
            }
        }
    }

    public void refreshOnlineList(View view){
        new whichUsersOnline().execute();
    }

    static boolean verifySign(byte[] signedkey, PublicKey rsaPK, PublicKey dhPK) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance("SHA1WithRSA");
        sign.initVerify(rsaPK);
        sign.update(dhPK.getEncoded());
        return(sign.verify(signedkey));
    }

    static byte[] readDataIn (DataInputStream dataInputStream) throws IOException {
        byte[] whateverByte = new byte[dataInputStream.readInt()];
        dataInputStream.readFully(whateverByte);
        return whateverByte;
    }

    public HashMap<String, ArrayList<String>> createMessageQueue(){
        ListView listView = findViewById(R.id.userlist);
        ArrayList<String> queueForUsers = new ArrayList<>();
        View view;
        TextView textView;
        HashMap<String, ArrayList<String>> hashMap = new HashMap<>();
        for (int i=0;i<listView.getCount();i++){
            view = listView.getChildAt(i);
            textView = view.findViewById(i);
            queueForUsers.add(textView.getText().toString());
        }
        for (int i=0;i<queueForUsers.size();i++){
            hashMap.put(queueForUsers.get(i),new ArrayList<String>());
        }
        return hashMap;
    }

    public static void sendMsg(PrintWriter pw, String msg){
        pw.println(msg);
        pw.flush();
    }


}
