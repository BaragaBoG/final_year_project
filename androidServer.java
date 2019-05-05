package protoProject;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.spec.DHParameterSpec;

public class andoidServer {
	
	static Thread thread =null;
	static int port = 25000;
	static ArrayList<InetAddress> clients = new ArrayList<InetAddress>();
	static HashMap<String, ArrayList<String>> msgHolder = new HashMap<>();
	
	
	public static ArrayList<Object> getUserKeys (String username)throws Exception{
		Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "************");
		ArrayList<Object> keysArray = new ArrayList<Object>();
		String query = "SELECT DHPub, RSAPub FROM androidtable WHERE Username = ?";
		PreparedStatement ps =  conn.prepareStatement(query);
		ps.setString(1, username);
		ResultSet rs = ps.executeQuery();
		if (rs.next()) {
			byte[] dhPub = rs.getBytes(1);
			byte[] rsaPub = rs.getBytes(2);
			keysArray.add(dhPub);
			keysArray.add(rsaPub);
		}
		return keysArray;
	}	
	
	
	
	public static ArrayList<String> getUserInfo(String username)throws Exception{
		Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "*********");
		String query = "SELECT IP FROM androidtable WHERE username = ?";
		PreparedStatement ps = conn.prepareStatement(query);
		ps.setString(1, username);
		String userIp;
		ArrayList<String> userInfoList = new ArrayList<String>();
		ResultSet rs = ps.executeQuery();
		if (rs.next()) {
			userIp = rs.getString(1);
			boolean status = checkStatus(username);
			if (status) {
					userInfoList.add(username);
					userInfoList.add(userIp);
					userInfoList.add("Online");
			}
			else {
				userInfoList.add(username);
				userInfoList.add(userIp);
				userInfoList.add("Offline");
			}
		}
		return userInfoList;
	}

	
	public static String getIp(String username) throws SQLException { //1
		String ip = null;
		final Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "**********");
		String query = "SELECT IP FROM androidtable WHERE USERNAME = ?";
		PreparedStatement ps = con.prepareStatement(query);
		ps.setString(1, username);
		ResultSet result = ps.executeQuery();
		if (result.next()) {
			ip = result.getString(1);
		}
		return ip;
	}
	
	public static String getName(String ipadr) throws SQLException { //1
		String name = null;
		final Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "**********");
		String query = "SELECT Username FROM androidtable WHERE IP = ?";
		PreparedStatement ps = con.prepareStatement(query);
		ps.setString(1, ipadr);
		ResultSet result = ps.executeQuery();
		if (result.next()) {
			name = result.getString(1);
		}
		return name;
	}
	
	public static boolean registerUser(String usrname, String pwd, String ip, byte[] signedKey, PublicKey rsaPK, PublicKey dhPK) throws Exception {//2
		boolean succorf = false;
		boolean verification = verifySign(signedKey, rsaPK, dhPK);
		if (verification==true) {
			String hashedPwd = doHash(pwd);
			System.out.println("Hashed Pwd is "+hashedPwd);
			final Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "*********");
			String query = "INSERT INTO androidtable(username, password, IP, DHPub, RSAPub) VALUES (?,?,?,?,?)";
			PreparedStatement ps = con.prepareStatement(query);
			ps.setString(1, usrname);
			ps.setString(2, hashedPwd);
			ps.setString(3, ip);
			ps.setBytes(4, dhPK.getEncoded());
			ps.setBytes(5, rsaPK.getEncoded());
			ps.execute();
			succorf = true;
		}	
		return succorf;
	}
	
	public static boolean signIn(String usrname, String pwd, String ip) throws Exception{//3
		boolean succ = false;
		String hashedPwd = doHash(pwd);
		final Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "**********");
		String query = "SELECT username, password, ip FROM androidtable WHERE USERNAME = ?";
		PreparedStatement ps = con.prepareStatement(query);
		ps.setString(1, usrname);
		ResultSet rs = ps.executeQuery();
		if (rs.next()) {
			String password = rs.getString(2);
			String ipadr = rs.getString(3);
			System.out.println("ipadr from database is "+ipadr);
			System.out.println("ipadr in parameter is "+ip);
			if (hashedPwd.equals(password)) {
				if ((ip.equals(ipadr))==false) {
					System.out.println("clients ip adr is different from the one that is stored in the database");
					String ipresetquery = "UPDATE androidtable SET IP = ? WHERE username = ?";
					PreparedStatement ipps = con.prepareStatement(ipresetquery);
					ipps.setString(1, ip);
					ipps.setString(2, usrname);
					ipps.executeUpdate();
				}
				succ = true;
			}
		}
		return succ;
	}
	
	static boolean compareKeys(PublicKey dhPub, PublicKey rsaPub, byte[] dbDHPub, byte[] dbRSAPub)throws Exception{
		boolean result = false;
		KeyFactory dhKeyFac = KeyFactory.getInstance("DiffieHellman");
		X509EncodedKeySpec dhx509 = new X509EncodedKeySpec(dbDHPub);
		PublicKey dbDHPK = dhKeyFac.generatePublic(dhx509);
		KeyFactory rsaKeyFac = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec rsax509 = new X509EncodedKeySpec(dbRSAPub);
		PublicKey dbRSAPK = rsaKeyFac.generatePublic(rsax509);
		if (dhPub.equals(dbDHPK) && rsaPub.equals(dbRSAPK)) {
			result = true;
		}
		else {
			result = false;
		}
		return result;
	}
	
	protected static byte[] signKey(byte[] dhPub, byte[] rsaPriv)throws Exception{
		KeyFactory rsaKeyFac = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec rsapkcs8 = new PKCS8EncodedKeySpec(rsaPriv);
		PrivateKey rsaPrivKey = rsaKeyFac.generatePrivate(rsapkcs8);
		Signature sign = Signature.getInstance("SHA1WithRSA");
		sign.initSign(rsaPrivKey);
		sign.update(dhPub);
		byte[] signedRawKey = sign.sign();
		return signedRawKey;
	}
	
	static String doHash(String str)throws Exception {
		String result = null;
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(str.getBytes(StandardCharsets.UTF_8));
		result = getHexString(digest);
		return result;
	}
	
	public static String getHexString(byte[] b) throws Exception {
		  String result = "";
		  for (int i=0; i < b.length; i++) {
		    result +=
		          Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
		  }
		  return result;
		}
	
	static boolean verifySign(byte[] signedkey, PublicKey rsaPK, PublicKey dhPK) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException { 
		Signature sign = Signature.getInstance("SHA1WithRSA");
		sign.initVerify(rsaPK);
		sign.update(dhPK.getEncoded());
		boolean verify = sign.verify(signedkey);
		return verify;
	}
	
	public static boolean checkStatus(String userIp)throws Exception{
		InetAddress inet = InetAddress.getByName(userIp);
		boolean isOnline = inet.isReachable(25000);
		return isOnline;
	}
	
	protected static KeyPair genDHKeyPair(BigInteger p,BigInteger g, SecureRandom random)throws Exception{
        DHParameterSpec dhParams = new DHParameterSpec(p,g);
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DiffieHellman");
        kpGen.initialize(dhParams, random);
        KeyPair keyPair = kpGen.generateKeyPair();
        return keyPair;
    }
	
	public static KeyPair genRSAKeyPair(SecureRandom random) throws Exception{
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(2048, random);
        KeyPair keyPair = kpGen.generateKeyPair();
        return keyPair;
    }
	
	static void sendKey(DataOutputStream dataOut, byte[] b)throws Exception{
		dataOut.writeInt(b.length);
		dataOut.write(b);
	}

	public static void main(String[] args){
		SecureRandom random;
		BigInteger g = BigInteger.valueOf(2L);
		BigInteger p = new BigInteger("2048309140943071948742620819591016954946151407768470439432032025055674053632053609636009657066179245631481017416897409865603012628734799700292029653914938266508944596763031834661063181119389344872941362364409950402324917755121196627950794007525376501682861030492141410456881161566951760450137123921808810471412213863851095029504522103063938134305443004986689907932182576100248047898579914587416147989885182985082938554521847029443627471846780892585000348057703746512668731042775139643046353713217152262240688121480610256647577878230228933739636543281633801575116095759306318190410512386261087696080332516783925031829");
		random = new SecureRandom();
		try {
			KeyPair rsaPair = genRSAKeyPair(random);
			final Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "*********");
			String query = "INSERT INTO serverrsakeys(rsaPriv, rsaPub) VALUES (?, ?)";
			PreparedStatement ps = con.prepareStatement(query);
			ps.setBytes(1, rsaPair.getPrivate().getEncoded());
			ps.setBytes(2, rsaPair.getPublic().getEncoded());
			ps.executeUpdate();
		} catch (Exception e) {
			e.printStackTrace();
		}
		ServerSocket serverSock = null;
		try {
			serverSock = new ServerSocket(port);
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		System.out.println("Server ready to accept connections on port "+port);
		while (true) {
			try {
				Socket socket = serverSock.accept();				
				System.out.println("Connected to "+socket.getInetAddress().getHostAddress());
				if (clients.contains(socket.getInetAddress())==false){
					clients.add(socket.getInetAddress());
				}
				System.out.println(clients);
				sSock sSocket = new sSock(socket);
				thread = new Thread(sSocket);
				thread.start();
				System.out.println("Thread started!");
			}
			catch(Exception e) {
				e.printStackTrace();
			}
		}
	}
}

class sSock implements Runnable{
	private Socket sock;
	static ServerSocket case4;
	static ArrayList<InetAddress> refClients = andoidServer.clients;
	
	public sSock(Socket socket) {
		this.sock = socket;
		try {
			case4 = new ServerSocket(25100);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	

	@Override
	public void run() {
			try {
				InetAddress ip = sock.getInetAddress();
				String ipadr = ip.getHostAddress();
				InputStream in = sock.getInputStream(); 
				OutputStream os = sock.getOutputStream();
				BufferedReader br = new BufferedReader(new InputStreamReader(in));//for string msgs
				PrintWriter pw = new PrintWriter(os);//for string msgs
				DataInputStream dataIn = new DataInputStream(in);//for keys in bytes
				DataOutputStream dataOut = new DataOutputStream(os);//for keys in bytes
				ArrayList<String> arraylist = new ArrayList<String>();
				ArrayList<String> clientInput = new ArrayList<String>();
				ArrayList<String> msgQ = new ArrayList<String>();
				String name = andoidServer.getName(ipadr);
				/*pw.println("10:"+andoidServer.msgHolder.get(name));
				pw.flush();*/
				String input;
				while (true) {
				if ((input = br.readLine())!=null) {
					arraylist.add(input);
					String methodID = arraylist.get(arraylist.size()-1);
					System.out.println("methodId is "+methodID+" methodID's class is "+methodID.getClass());
				 
					String clientList;
					switch (methodID) {
					case "1":  //case for ip adr get()
						String usernameAsRecvd;
						pw.println("1");
						pw.flush();
						usernameAsRecvd = br.readLine();
						String usernameIP = andoidServer.getIp(usernameAsRecvd);
						pw.println(usernameIP);
						pw.flush();
						pw.close();
						case4.close();
						break;
						
					case "2": //case for register
						pw.println("2");
						System.out.println("after sending 2 to client");
						pw.flush();						
						for (int i=0;i<2;i++) {
							String clientSays = br.readLine();
							String variable = (clientSays);
							clientInput.add(variable);
							System.out.println("in for loop, current clientInput is "+clientInput);
						}
						System.out.println("for loop has been completed");
						pw.println("2.1");
						System.out.println("2.1 has been sent ");
						pw.flush();
						byte[] signedDHByte = new byte[dataIn.readInt()];
						System.out.println("signedDHByte has been initialized");
						dataIn.readFully(signedDHByte);
						System.out.println("after signedDHByte readfully");
						byte[] rsaPubByte = new byte[dataIn.readInt()];
						System.out.println("rsaPubByte has been initialized");
						dataIn.readFully(rsaPubByte);
						System.out.println("after rsaPubByte readfully");
						byte[] dhPubByte = new byte[dataIn.readInt()];
						System.out.println("dhPubByte has been initialized");
						dataIn.readFully(dhPubByte);
						System.out.println("after dhPubByte readfully");
						KeyFactory dhKeyFac = KeyFactory.getInstance("DiffieHellman");
						X509EncodedKeySpec dhx509 = new X509EncodedKeySpec(dhPubByte);
						PublicKey dhPub = dhKeyFac.generatePublic(dhx509);
						System.out.println("after dhpub has been restored");
						KeyFactory rsaKeyFac = KeyFactory.getInstance("RSA");
						X509EncodedKeySpec rsax509 = new X509EncodedKeySpec(rsaPubByte);
						PublicKey rsaPub = rsaKeyFac.generatePublic(rsax509);
						System.out.println("after rsapub has been restored");
						boolean verify = andoidServer.verifySign(signedDHByte, rsaPub, dhPub);
						System.out.println("after verifySign()");
						if (verify==true) {
							System.out.println("verify is true");
							System.out.println(clientInput.get(0));
							System.out.println(ipadr);
							boolean register = andoidServer.registerUser(clientInput.get(0), clientInput.get(1), ipadr, signedDHByte, rsaPub, dhPub);
							System.out.println("After registerUser()");
							if (register==true) {
								pw.println("Register Success");
								System.out.println("After register success has been sent to client");
								pw.flush();
							}
						}
						else {
							System.out.println("verify is false");
							pw.println("Register Failure");
							System.out.println("after register failure has been sent to client");
							pw.flush();
						}
						clientInput.clear();
						arraylist.clear();
						System.out.println("After arraylist and clientInput has been cleared after being flushed");
						pw.close();
						case4.close();
						break;
					case "3": //case for signin
						pw.println("3");
						pw.flush();
						System.out.println("after 3 has been sent to client");						
						for (int i=0;i<2;i++) {
							String variable = br.readLine();
							clientInput.add(variable);
							System.out.println("inside for loop. current value of clientInput is "+clientInput);
						}
						System.out.println("After for loop has finished executing");
						boolean signin = andoidServer.signIn(clientInput.get(0),clientInput.get(1),ipadr);
						System.out.println("after signIn()");
						if (signin==true) {
							System.out.println("signin is true");
							pw.println("Signin Success");
							System.out.println("singin success has been to client");
							pw.flush();
						}
						if (signin == false) {
							System.out.println("signin is false");
							pw.println("Signin Failure");
							System.out.println("signin failure has been sent to client");
						}
						arraylist.clear();
						clientInput.clear();
						System.out.println("arraylist and clientInput have been cleared");
						pw.close();
						case4.close();
						
						break;
					case "4"://message queue
						Socket case4sock = case4.accept();
						System.out.println("socket case4sock has been connected");
						InputStream caseIn = case4sock.getInputStream();
						System.out.println("After caseIn");
						BufferedReader caseReader = new BufferedReader(new InputStreamReader(caseIn));
						System.out.println("After casereader");
						//OutputStream caseOut = case4sock.getOutputStream();
						System.out.println("after caseout");
						//PrintWriter caseWriter = new PrintWriter(caseOut);
						System.out.println("after casewriter");
						pw.println("4");
						System.out.println("after 4 has been to client");
						pw.flush();
						String msg = caseReader.readLine();
						System.out.println("after casereader.readline has been initlizaed.  current value is "+msg);
						while (msg!=null) {
							System.out.println("msg is not null");
							msgQ.add(msg);
							System.out.println("msg has been added to msgq. current value of msgq is "+msgQ);
						}
						System.out.println("after msessages have been added to queue and while loop is complete");
						case4.close();
						break;
					case "5": //send clientlist and their details
						String usersDetails;
						//ArrayList<Object> userinfo;						
						ArrayList<Object> objectList = new ArrayList<Object>();
						byte[] serverRSAPriv = null;	
						byte[] serverRSAPub = null;
						
						Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "vallari98");
						String baseQuery = "SELECT USERNAME, dhPub, rsaPub FROM androidtable WHERE IP = ?";
						String serverRSAQuery = "SELECT rsaPriv, rsaPub FROM serverrsakeys ORDER BY ID DESC LIMIT 1";	
						
						PreparedStatement rsaPS = conn.prepareStatement(serverRSAQuery);
						ResultSet rsaResultSet = rsaPS.executeQuery();
						if (rsaResultSet.next()) {
							serverRSAPriv = rsaResultSet.getBytes(1);
							serverRSAPub = rsaResultSet.getBytes(2);
						}
						
						System.out.println("After serverRSAKeyPair has been fetched from MySQL");
						
						PreparedStatement userPS = conn.prepareStatement(baseQuery);
						
						for (int i=0;i<refClients.size();i++) {
							String currentIp = refClients.get(i).getHostAddress();
							System.out.println("currentIp is "+currentIp);
							userPS.setString(1, currentIp);
							ResultSet rs = userPS.executeQuery();
							
							if (rs.next()) {
								if ((objectList.isEmpty())==false) {
								objectList.clear();
								System.out.println("AFter clearing objectList");
								}
								String username = rs.getString(1);
								byte[] clientDHPub = rs.getBytes(2);
								byte[] clientRSAPub = rs.getBytes(3);								
								byte[] signedClientDHPub = andoidServer.signKey(clientDHPub, serverRSAPriv);
								byte[] signedClientRSAPub = andoidServer.signKey(clientRSAPub, serverRSAPriv);
								
								usersDetails = username + ":"+currentIp;
								System.out.println("usersDetails is " +usersDetails);
								pw.println(usersDetails);
								pw.flush();
								System.out.println("After usersdetails have been sent to client");
								
								String clientSays;
								if ((clientSays = br.readLine()).equals("5.1")) {
									System.out.println("cliensays is "+clientSays);
									dataOut.writeInt(signedClientDHPub.length); //sends length of users signed dh public key for proper reading of key at client side
									dataOut.write(signedClientDHPub);//sends users signed dh public key 
									andoidServer.sendKey(dataOut, clientDHPub);								
									andoidServer.sendKey(dataOut, signedClientRSAPub);
									andoidServer.sendKey(dataOut, clientRSAPub);
									dataOut.writeInt(serverRSAPub.length);
									dataOut.write(serverRSAPub);
								}
						}
						}
						pw.close();
						System.out.println("After username, ip, and the keys have been sent.");
						//case4.close();
						System.out.println("after case4 has been closed");
						break;
					case "6": //for sending userinfo list
						pw.println("6");
						pw.flush();
						String username = br.readLine();
						ArrayList<String> userInfo = new ArrayList<String>();
						userInfo = andoidServer.getUserInfo(username);
						for (int i=0;i<userInfo.size();i++) {
						System.out.println(userInfo.get(i));
						}
						System.out.println("AFter userinfo has been sent");
						pw.close();
						case4.close();
						break;
					case "7": //for sending keys
						
						pw.println("7");
						pw.flush();
						
						byte[] serverRSAPriv2 = null;	
						byte[] serverRSAPub2 = null;
						byte[] userDHPK;
						byte[] userRSAPK;
						Connection conn2 = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "********");						
						String serverRSAQuery2 = "SELECT rsaPriv, rsaPub FROM serverrsakeys ORDER BY ID DESC LIMIT 1";						
						PreparedStatement rsaPS2 = conn2.prepareStatement(serverRSAQuery2);
						ResultSet rsaResultSet2 = rsaPS2.executeQuery();
						if (rsaResultSet2.next()) {
							serverRSAPriv2 = rsaResultSet2.getBytes(1);
							serverRSAPub2 = rsaResultSet2.getBytes(2);
						}
						System.out.println("After serverRSAKeyPair has been fetched from MySQL");
						
						String userSeUsername =br.readLine();
						System.out.println("userseusername is "+userSeUsername);
						String baseQuery2 = "SELECT dhPub, rsaPub FROM androidtable WHERE Username = ?";
						PreparedStatement userPS2 = conn2.prepareStatement(baseQuery2);
						userPS2.setString(1, userSeUsername);
						ResultSet resultSet = userPS2.executeQuery();
						if (resultSet.next()) {
							userDHPK = resultSet.getBytes(1);
							System.out.println(userDHPK);
							userRSAPK = resultSet.getBytes(2);
							System.out.println(userRSAPK);
							
							byte[] signedDHPK = andoidServer.signKey(userDHPK, serverRSAPriv2);
							byte[] signedRSAPK = andoidServer.signKey(userRSAPK, serverRSAPriv2);
							
							andoidServer.sendKey(dataOut, signedDHPK); //first signed,then normal
							andoidServer.sendKey(dataOut, userDHPK);
							andoidServer.sendKey(dataOut, signedRSAPK);
							andoidServer.sendKey(dataOut, userRSAPK);
							andoidServer.sendKey(dataOut, serverRSAPub2);
							
						}
						pw.close();
						case4.close();
						break;
					case "8": //for client-server-client comms
						pw.println("8");
						pw.flush();
						
						String receivedMsg = br.readLine();
						String[] splitStr = receivedMsg.split(":");
						String source = splitStr[0];
						String dest = splitStr[1];
						pw.println("8.1");
						pw.flush();
						byte[] encryptedBytes = new byte[dataIn.readInt()];
						dataIn.readFully(encryptedBytes);
						String hmacStr = br.readLine();
						System.out.println("encrypted message is: "+new String(encryptedBytes)+" and its HMAC is "+hmacStr);
						pw.println("8.2");
						pw.flush();
						
						String destIp = andoidServer.getIp(dest);//forward message
						Socket socket = new Socket(destIp,30000);
						
						DataOutputStream forwardOut = new DataOutputStream(socket.getOutputStream());
						PrintWriter forwardPW = new PrintWriter(socket.getOutputStream());
						BufferedReader forwardBR = new BufferedReader(new InputStreamReader(socket.getInputStream()));
						forwardPW.println("8.5");
						forwardPW.flush();
						if (forwardBR.readLine().equals("8.5")) {
							forwardOut.writeInt(encryptedBytes.length);
							forwardOut.write(encryptedBytes);
							forwardPW.println(hmacStr);
							forwardPW.flush();
							System.out.println("encrypted bytes and its hmac have been sent");
						}
						
								/*String receivedMsg = br.readLine();
								System.out.println(receivedMsg);
								String[] splitStr = receivedMsg.split(":");
								String source = splitStr[0];
								String dest = splitStr[1];
								String contents = splitStr[2];
								String destIp = andoidServer.getIp(dest);
								System.out.println(destIp);
								System.out.println("source, dest, and contents are: "+source+" "+dest+" "+contents);
								PrintWriter print = new PrintWriter(new Socket(destIp,30000).getOutputStream());
								print.println(contents);
								print.flush();
								System.out.println("Contents have been sent");
								print.close();**/
												
								/**boolean status = andoidServer.checkStatus(destIp);
								if (status) {
									Socket destSock = new Socket(destIp,30000);
									OutputStream outStream = destSock.getOutputStream();
									PrintWriter printW = new PrintWriter(outStream);
									printW.println("8.3:"+source+":"+contents);
									printW.flush();
									System.out.println("8.3 bit has been done");
									printW.close();
									destSock.close();
								}
								else {
									Socket destSock = new Socket(destIp,30000);
									OutputStream outStream = destSock.getOutputStream();
									PrintWriter printW = new PrintWriter(outStream);
									//ArrayList<String> messageQueue = new ArrayList<String>();
									msgQ.add(contents);
									andoidServer.msgHolder.put(dest, msgQ);
									//printW.println("8.6:"+source+":"+msgQ);
									//printW.flush();
									System.out.println("8.6 bit has been done");
									printW.close();
									destSock.close();							
								//}
								}
							
							/**else {
								System.out.println(whose);
								ArrayList<String> outputList = andoidServer.msgHolder.get(whose);
								System.out.println(outputList);
								if (outputList!=null && outputList.isEmpty()==false) {
									for (int i=0;i<outputList.size();i++) {
										pw.println(outputList.get(i));
										pw.flush();
									}
									System.out.println("Contents of outputlist have been sent to client");
								}
							}**/
									
						pw.close();
						//case4.close();
						break;
					default:
						System.out.println("No input from client");
						case4.close();
						break;
						
					}
					arraylist.clear();
				}
				dataOut.close();
				dataIn.close();
				}
			}
			catch(Exception e) {
				e.printStackTrace();
			}
		}
	}

//}
