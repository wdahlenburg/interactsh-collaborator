package interactsh;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
import org.json.JSONObject;

import com.github.shamil.Xid;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class Client {
    public PrivateKey privateKey;
    private PublicKey publicKey;
    private String secretKey;

    // Defaults
    private String host = "oast.pro";
    private int port = 443;
    private boolean scheme = true;
    private boolean is_registered = false;
    private String authorization = null;
    private String pubKey;
    private String correlationId;

    public Client() {
        this.generateKeys();

        this.correlationId = Xid.get().toString();

        host = burp.gui.Config.getHost();
        scheme = burp.gui.Config.getScheme();
        authorization = burp.gui.Config.getAuth();
        secretKey = UUID.randomUUID().toString();
        pubKey = Base64.getEncoder().encodeToString(getPublicKey().getBytes(StandardCharsets.UTF_8));
        try {
            port = Integer.parseInt(burp.gui.Config.getPort());
        } catch (NumberFormatException ne) {
            port = 443;
        }
    }

    public boolean isRegistered(){
        return this.is_registered;
    }

    public boolean register() {
        burp.BurpExtender.api.logging().logToOutput("Registering " + correlationId);
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
            if (!(authorization == null || authorization.isEmpty())) {
                request += "Authorization: " + authorization + "\r\n";
            }
            request += "Connection: close\r\n\r\n"
                    + registerData.toString();

            HttpRequest httpRequest = HttpRequest.httpRequest(HttpService.httpService(host, port, scheme), request);
            HttpResponse resp = burp.BurpExtender.api.http().sendRequest(httpRequest).response();

            if (resp.statusCode() == 200) {
                this.is_registered = true;
                return true;
            } else {
                burp.BurpExtender.api.logging().logToError("Register correlation " + correlationId
                        + " was unsuccessful. Status Code: " + resp.statusCode());
            }
        } catch (Exception ex) {
            burp.BurpExtender.api.logging().logToError(ex);
        }
        return false;
    }

    public boolean poll() {
        String request = "GET /poll?id=" + correlationId + "&secret=" + secretKey + " HTTP/1.1\r\n"
                + "Host: " + host + "\r\n"
                + "User-Agent: Interact.sh Client\r\n";
        if (!(authorization == null || authorization.isEmpty())) {
            request += "Authorization: " + authorization + "\r\n";
        }
        request += "Connection: close\r\n\r\n";

        HttpRequest httpRequest = HttpRequest.httpRequest(HttpService.httpService(host, port, scheme), request);
        HttpResponse resp = burp.BurpExtender.api.http().sendRequest(httpRequest).response();
        if (resp.statusCode() != 200) {
            burp.BurpExtender.api.logging()
                    .logToOutput("Poll for " + correlationId + " was unsuccessful: " + resp.statusCode());
            return false;
        }

        String responseBody = resp.bodyToString();
        try {
            JSONObject jsonObject = new JSONObject(responseBody);
            String aesKey = jsonObject.getString("aes_key");
            String key = this.decryptAesKey(aesKey);

            if (!jsonObject.isNull("data")) {
                JSONArray data = jsonObject.getJSONArray("data");
                for (int i = 0; i < data.length(); i++) {
                    String d = data.getString(i);

                    String decryptedData = decryptData(d, key);

                    InteractEntry entry = new InteractEntry(decryptedData);
                    burp.BurpExtender.addToTable(entry);
                    burp.BurpExtender.api.logging().logToOutput(entry.toString());
                }
            }
        } catch (Exception ex) {
            burp.BurpExtender.api.logging().logToError(ex.getMessage());
        }
        return true;
    }

    public void deregister() {
        burp.BurpExtender.api.logging().logToOutput("Deregistering " + correlationId);
        try {
            JSONObject deregisterData = new JSONObject();
            deregisterData.put("correlation-id", correlationId);
            deregisterData.put("secret-key", secretKey);

            String request = "POST /deregister HTTP/1.1\r\n"
                    + "Host: " + host + "\r\n"
                    + "User-Agent: Interact.sh Client\r\n"
                    + "Content-Type: application/json\r\n"
                    + "Content-Length: " + deregisterData.toString().length() + "\r\n";
            if (!(authorization == null || authorization.isEmpty())) {
                request += "Authorization: " + authorization + "\r\n";
            }
            request += "Connection: close\r\n\r\n"
                    + deregisterData.toString();

            HttpRequest httpRequest = HttpRequest.httpRequest(HttpService.httpService(host, port, scheme), request);
            burp.BurpExtender.api.http().sendRequest(httpRequest).response();
        } catch (Exception ex) {
            burp.BurpExtender.api.logging().logToError(ex.getMessage());
        }
    }

    public String getInteractDomain() {
        if (correlationId == null || correlationId.isEmpty()) {
            return "";
        } else {
            String fullDomain = correlationId;

            // Fix the string up to 33 characters
            Random random = new Random();
            while (fullDomain.length() < 33) {
                fullDomain += (char) (random.nextInt(26) + 'a');
            }

            fullDomain += "." + host;
            return fullDomain;
        }
    }

    public void generateKeys(){
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
    
            publicKey = kp.getPublic();
            privateKey = kp.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            burp.BurpExtender.api.logging().logToError("Unable to generate client key pair");
            burp.BurpExtender.api.logging().logToError(e);
        }
    }

    private String getPublicKey() {
        String pubKey = "-----BEGIN PUBLIC KEY-----\n";
        String[] chunks = splitStringEveryN(Base64.getEncoder().encodeToString(publicKey.getEncoded()), 64);
        for (String chunk : chunks) {
            pubKey += chunk + "\n";
        }
        pubKey += "-----END PUBLIC KEY-----\n";
        return pubKey;
    }

    private String decryptAesKey(String encrypted) throws Exception {
        byte[] cipherTextArray = Base64.getDecoder().decode(encrypted);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT);
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
    }

    private String[] splitStringEveryN(String s, int interval) {
        int arrayLength = (int) Math.ceil(((s.length() / (double) interval)));
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
