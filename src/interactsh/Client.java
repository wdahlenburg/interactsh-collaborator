package interactsh;

import burp.IBurpExtenderCallbacks;
import burp.BurpExtender;
import burp.IResponseInfo;
import javax.crypto.*;
import javax.crypto.spec.*;
import com.github.shamil.Xid;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.spec.MGF1ParameterSpec;
import java.security.*;
import java.util.*;

public class Client {
    public PrivateKey privateKey;
    private PublicKey publicKey;
    private IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private Xid xid;
    private String secretKey;
    private String correlationId;

    // Defaults
    private String server = "https://interact.sh";
    private String host = "interact.sh";
    private int port = 443;
    private boolean scheme = true;
    private String authorization = null;

    public Client(){
        server = burp.gui.Config.getUrl();
        host = burp.gui.Config.getHost();
        scheme = burp.gui.Config.getScheme();
        authorization = burp.gui.Config.getAuth();
        try {
            port = Integer.parseInt(burp.gui.Config.getPort());
        } catch (NumberFormatException ne){
            port = 443;
        }
    }

    public boolean registerClient() throws Exception {
        String pubKey = Base64.getEncoder().encodeToString(getPublicKey().getBytes(StandardCharsets.UTF_8));
        secretKey = UUID.randomUUID().toString();
        xid = Xid.get();
        correlationId = xid.toString();

        try {
            JSONObject registerData = new JSONObject();
            registerData.put("public-key", pubKey);
            registerData.put("secret-key", secretKey);
            registerData.put("correlation-id", correlationId);

            String request = "POST /register HTTP/1.1\r\n"
                    + "Host: " + host + "\r\n"
                    + "User-Agent: Interact.sh Client\r\n"
                    + "Content-Type: application/json\r\n"
                    + "Content-Length: " + registerData.toString().length() + "\r\n";
            if(!(authorization == null || authorization.isEmpty())){
                request += "Authorization: " + authorization + "\r\n";
            }
            request += "Connection: close\r\n\r\n"
                    + registerData.toString();

            byte[] response = callbacks.makeHttpRequest(host, port, scheme, request.getBytes(StandardCharsets.UTF_8));
            IResponseInfo responseInfo = BurpExtender.getHelpers().analyzeResponse(response);
            if (responseInfo.getStatusCode() == 200) {
                return true;
            }
        }catch (Exception ex){
            callbacks.printOutput(ex.getMessage());
        }
        return false;
    }

    public boolean poll() throws IOException, InterruptedException {
        String request = "GET /poll?id=" + correlationId + "&secret=" + secretKey + " HTTP/1.1\r\n"
                + "Host: " + host + "\r\n"
                + "User-Agent: Interact.sh Client\r\n";
        if(!(authorization == null || authorization.isEmpty())){
            request += "Authorization: " + authorization + "\r\n";
        }
        request += "Connection: close\r\n\r\n";

        byte[] response = callbacks.makeHttpRequest(host, port, scheme, request.getBytes(StandardCharsets.UTF_8));
        IResponseInfo responseInfo = BurpExtender.getHelpers().analyzeResponse(response);
        if (responseInfo.getStatusCode() != 200) {
            callbacks.printOutput("Poll for " + correlationId + " was unsuccessful: " + responseInfo.getStatusCode());
            return false;
        }

        String responseStr = new String(response);
        String responseBody = responseStr.split("\r\n\r\n")[1];
        try {
            JSONObject jsonObject = new JSONObject(responseBody);
            String aesKey = jsonObject.getString("aes_key");
            String key = decryptAesKey(aesKey);

            JSONArray data = jsonObject.getJSONArray("data");
            for (int i = 0; i < data.length(); i++){
                String d = data.getString(i);

                String decryptedData = decryptData(d, key);

                InteractEntry entry = new InteractEntry(decryptedData);
                burp.BurpExtender.addToTable(entry);
                callbacks.printOutput(entry.toString());
            }

        } catch(Exception ex){
            callbacks.printOutput(ex.getMessage());
        }
        return true;
    }

    public void deregister(){
        callbacks.printOutput("Deregistering " + correlationId);
        try {
            JSONObject deregisterData = new JSONObject();
            deregisterData.put("correlation-id", correlationId);
            deregisterData.put("secret-key", secretKey);

            String request = "POST /deregister HTTP/1.1\r\n"
                    + "Host: " + host + "\r\n"
                    + "User-Agent: Interact.sh Client\r\n"
                    + "Content-Type: application/json\r\n"
                    + "Content-Length: " + deregisterData.toString().length() + "\r\n";
            if(!(authorization == null || authorization.isEmpty())){
                request += "Authorization: " + authorization + "\r\n";
            }
            request += "Connection: close\r\n\r\n"
                    + deregisterData.toString();

            callbacks.makeHttpRequest(host, port, scheme, request.getBytes(StandardCharsets.UTF_8));
        }catch (Exception ex){
            callbacks.printOutput(ex.getMessage());
        }
    }

    public String getInteractDomain(){
        if (correlationId == null || correlationId.isEmpty()){
            return "";
        } else {
            String fullDomain = correlationId;

            // Fix the string up to 33 characters
            Random random = new Random();
            while (fullDomain.length() < 33) {
                fullDomain += (char)(random.nextInt(26) + 'a');
            }
            fullDomain += "." + host;
            return fullDomain;
        }
    }

    public void generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        publicKey = kp.getPublic();
        privateKey = kp.getPrivate();
    }

    private String getPublicKey(){
        String pubKey = "-----BEGIN PUBLIC KEY-----\n";
        String [] chunks = splitStringEveryN(Base64.getEncoder().encodeToString(publicKey.getEncoded()), 64);
        for (String chunk: chunks) {
            pubKey += chunk + "\n";
        }
        pubKey += "-----END PUBLIC KEY-----\n";
        return pubKey;
    }

    private String decryptAesKey(String encrypted) throws Exception
    {
        byte[] cipherTextArray = Base64.getDecoder().decode(encrypted);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        byte[] decrypted = cipher.doFinal(cipherTextArray);

        return new String(decrypted);
    }

    private static String decryptData(String input, String key) throws Exception {
        byte[] cipherTextArray = Base64.getDecoder().decode(input);
        byte[] iv = Arrays.copyOfRange(cipherTextArray, 0, 16);
        byte[] cipherText = Arrays.copyOfRange(cipherTextArray, 16, cipherTextArray.length - 1);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(cipherText);

        return new String(decrypted);
    };

    private String[] splitStringEveryN(String s, int interval) {
        int arrayLength = (int) Math.ceil(((s.length() / (double)interval)));
        String[] result = new String[arrayLength];

        int j = 0;
        int lastIndex = result.length - 1;
        for (int i = 0; i < lastIndex; i++) {
            result[i] = s.substring(j, j + interval);
            j += interval;
        }
        result[lastIndex] = s.substring(j);

        return result;
    }
}
