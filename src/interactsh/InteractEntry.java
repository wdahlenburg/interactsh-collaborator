package interactsh;

import org.json.*;

// {"protocol":"dns","unique-id":"c4jup534f3acspvifdr0cru63feyyyyyn","full-id":"c4jup534f3acspvifdr0cru63feyyyyyn","q-type":"A","raw-request":";; opcode: QUERY, status: NOERROR, id: 52297\n;; flags: cd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n\n;; QUESTION SECTION:\n;c4jup534f3acspvifdr0cru63feyyyyyn.interact.sh.\tIN\t A\n","raw-response":";; opcode: QUERY, status: NOERROR, id: 52297\n;; flags: qr aa cd; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 2\n\n;; QUESTION SECTION:\n;c4jup534f3acspvifdr0cru63feyyyyyn.interact.sh.\tIN\t A\n\n;; ANSWER SECTION:\nc4jup534f3acspvifdr0cru63feyyyyyn.interact.sh.\t3600\tIN\tA\t46.101.25.250\n\n;; AUTHORITY SECTION:\nc4jup534f3acspvifdr0cru63feyyyyyn.interact.sh.\t3600\tIN\tNS\tns1.interact.sh.\nc4jup534f3acspvifdr0cru63feyyyyyn.interact.sh.\t3600\tIN\tNS\tns2.interact.sh.\n\n;; ADDITIONAL SECTION:\nns1.interact.sh.\t3600\tIN\tA\t46.101.25.250\nns2.interact.sh.\t3600\tIN\tA\t46.101.25.250\n","remote-address":"172.253.196.66","timestamp":"2021-08-26T19:35:24.221293174Z"}
// {"protocol":"http","unique-id":"c4jv8mb4f3adocqjsqe0cru9esoyyyyyn","full-id":"c4jv8mb4f3adocqjsqe0cru9esoyyyyyn","raw-request":"GET /foobar123 HTTP/1.1\r\nHost: c4jv8mb4f3adocqjsqe0cru9esoyyyyyn.interact.sh\r\nConnection: close\r\nAccept: */*\r\nConnection: close\r\nUser-Agent: curl/7.58.0\r\n\r\n","raw-response":"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\nServer: interact.sh\r\n\r\n\u003chtml\u003e\u003chead\u003e\u003c/head\u003e\u003cbody\u003enyyyyyose9urc0eqsjqcoda3f4bm8vj4c\u003c/body\u003e\u003c/html\u003e","remote-address":"127.0.0.1","timestamp":"2021-08-26T20:07:52.353891791Z"}
// {"protocol":"smtp","unique-id":"c4l8o21gbfmkbnhdg64gwbkgvwnbfasfu","full-id":"c4l8o21gbfmkbnhdg64gwbkgvwnbfasfu","raw-request":"Received: from s5.eternalimpact.info (s5.eternalimpact.info. [167.86.101.24])\r\n        by interact.sh. (interactsh) with SMTP\r\n        for \u003cfoobar@c4l8o21gbfmkbnhdg64gwbkgvwnbfasfu.interact.sh\u003e; Sat, 28 Aug 2021 19:19:09 +0000 (UTC)\r\nReceived: from authenticated-user (s5.eternalimpact.info [167.86.101.24])\r\n\t(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits))\r\n\t(No client certificate requested)\r\n\tby s5.eternalimpact.info (Postfix) with ESMTPSA id 54FE3662239\r\n\tfor \u003cfoobar@c4l8o21gbfmkbnhdg64gwbkgvwnbfasfu.interact.sh\u003e; Sat, 28 Aug 2021 19:19:09 +0000 (UTC)\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple;\r\n\td=s5.eternalimpact.info; s=mail; t=1630178349;\r\n\tbh=lGmaGoj8Xo5ZgiHMqYPGvoKVjIfZP2peFYgc3GXX3J8=;\r\n\th=Date:To:From:Subject:List-Unsubscribe:From;\r\n\tb=NYlC8/IVvPiH+HJQnCG5W+9O6/VNukJU++1MK6jCkhBaqeYOa4RC1lmpqjHQ14iWr\r\n\t 40Mzw81IEAE+BI/4iT71OcFWZZ6ajPApTGKonRuaZFxHY3hQxDOMAhWHeZP4v51BGz\r\n\t FESaLeZdlxn2hsJhnfFxbZRybVxYrUKXb1J38cn2wRSlHTZXWp4hHgB41lYGAsjpLn\r\n\t A8B0wKpg82zwh0ZhJjLWVT4aJEh48Oho2wtUhioFVtdIpV2PTDuDhqihJR6PV3W+Yl\r\n\t i6b+DqSrP1DxShtmb6rLTAXl5jy6jNDLLLTU8xC99CECazpfz4OCSGZNhcBM9iVN66\r\n\t UimRj6zMBZ8fQ==\r\nDate: Sat, 28 Aug 2021 19:19:09 +0000\r\nTo: foobar@c4l8o21gbfmkbnhdg64gwbkgvwnbfasfu.interact.sh\r\nFrom: Anonymousemail \u003cnoreply@anonymousemail.me\u003e\r\nSubject: Test\r\nMessage-ID: \u003c8d2a3a8f07c5bd642e12f7ea4a48245a@anonymousemail.me\u003e\r\nList-Unsubscribe: \u003cmailto:contact@anonymousemail.me?subject=unsubscribe\u003e, \u003chttps://anonymousemail.me/unsubscribe.php?email=foobar@c4l8o21gbfmkbnhdg64gwbkgvwnbfasfu.interact.sh\u003e\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative;\r\n boundary=\"b1_EqDzWEjs9wsJui8L4dcucWKaDQWeApjhHmbfkHMab0\"\r\nContent-Transfer-Encoding: 7bit\r\n\r\nThis is a multi-part message in MIME format.\r\n\r\n--b1_EqDzWEjs9wsJui8L4dcucWKaDQWeApjhHmbfkHMab0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nHello World\r\n\r\n--b1_EqDzWEjs9wsJui8L4dcucWKaDQWeApjhHmbfkHMab0\r\nContent-Type: text/html; charset=us-ascii\r\n\r\n\u003cp\u003e\u003cspan style=\"color:#c0392b\"\u003ePowered by \u003cstrong\u003eAnonymousemail\u003c/strong\u003e\u0026nbsp;\u0026rarr; \u003c/span\u003e\u003ca href=\"https://anonymousemail.cc/premium.php?source=email\" style=\"text-decoration:none;\"\u003e\u003cspan style=\"color:#df7401\"\u003eJoin Us!\u003c/span\u003e\u003c/a\u003e\u003c/p\u003eHello World\r\n\r\n\r\n--b1_EqDzWEjs9wsJui8L4dcucWKaDQWeApjhHmbfkHMab0--\r\n\r\n","smtp-from":"noreply@anonymousemail.me","remote-address":"167.86.101.24","timestamp":"2021-08-28T19:19:09.654451626Z"}
public class InteractEntry {
    public String protocol;
    public String uid;
    public String details;
    public String address;
    public String timestamp;

    public InteractEntry(String event) throws JSONException {
        JSONObject jsonObject = new JSONObject(event);
        protocol = jsonObject.getString("protocol");
        uid = jsonObject.getString("unique-id");
        address = jsonObject.getString("remote-address");
        timestamp = jsonObject.getString("timestamp");
        details = processDetails(protocol, jsonObject);
    }

    private String processDetails(String protocol, JSONObject obj) throws JSONException {
        String result;
        switch (protocol) {
            case "dns":
                result = "Query Type: " + obj.getString("q-type") + "\n\n";
                result += "Request: \n" + obj.getString("raw-request") + "\n";
                result += "Response: \n" + obj.getString("raw-response") + "\n";
                break;
            case "ftp":
                result = "FTP From: " + obj.getString("remote-address") + "\n\n";
                result += "Request: \n" + obj.getString("raw-request") + "\n";
                break;
            case "http":
                result = "Request: \n" + obj.getString("raw-request") + "\n";
                result += "Response: \n" + obj.getString("raw-response") + "\n";
                break;
            case "ldap":
                result = "LDAP From: " + obj.getString("remote-address") + "\n\n";
                result += "Request: \n" + obj.getString("raw-request") + "\n";
                break;
            case "responder":
            case "smb":
                result = "Request: \n" + obj.getString("raw-request") + "\n";
                break;
            case "smtp":
                result = "SMTP From: " + obj.getString("smtp-from") + "\n\n";
                result += "Request: \n" + obj.getString("raw-request") + "\n";
                break;
            default:
                result = "UNSUPPORTED PROTOCOL";
        }
        return result;
    }

    public String toString() {
        return "Protocol: " + protocol + "\n"
                + "UID: " + uid + "\n"
                + "Address: " + address + "\n"
                + "Timestamp: " + timestamp + "\n";
    }
}
