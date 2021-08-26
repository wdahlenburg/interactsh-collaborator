package interactsh;
import org.json.*;

// {"protocol":"dns","unique-id":"c4jup534f3acspvifdr0cru63feyyyyyn","full-id":"c4jup534f3acspvifdr0cru63feyyyyyn","q-type":"A","raw-request":";; opcode: QUERY, status: NOERROR, id: 52297\n;; flags: cd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n\n;; QUESTION SECTION:\n;c4jup534f3acspvifdr0cru63feyyyyyn.interact.sh.\tIN\t A\n","raw-response":";; opcode: QUERY, status: NOERROR, id: 52297\n;; flags: qr aa cd; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 2\n\n;; QUESTION SECTION:\n;c4jup534f3acspvifdr0cru63feyyyyyn.interact.sh.\tIN\t A\n\n;; ANSWER SECTION:\nc4jup534f3acspvifdr0cru63feyyyyyn.interact.sh.\t3600\tIN\tA\t46.101.25.250\n\n;; AUTHORITY SECTION:\nc4jup534f3acspvifdr0cru63feyyyyyn.interact.sh.\t3600\tIN\tNS\tns1.interact.sh.\nc4jup534f3acspvifdr0cru63feyyyyyn.interact.sh.\t3600\tIN\tNS\tns2.interact.sh.\n\n;; ADDITIONAL SECTION:\nns1.interact.sh.\t3600\tIN\tA\t46.101.25.250\nns2.interact.sh.\t3600\tIN\tA\t46.101.25.250\n","remote-address":"172.253.196.66","timestamp":"2021-08-26T19:35:24.221293174Z"}
// {"protocol":"http","unique-id":"c4jv8mb4f3adocqjsqe0cru9esoyyyyyn","full-id":"c4jv8mb4f3adocqjsqe0cru9esoyyyyyn","raw-request":"GET /foobar123 HTTP/1.1\r\nHost: c4jv8mb4f3adocqjsqe0cru9esoyyyyyn.interact.sh\r\nConnection: close\r\nAccept: */*\r\nConnection: close\r\nUser-Agent: curl/7.58.0\r\n\r\n","raw-response":"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\nServer: interact.sh\r\n\r\n\u003chtml\u003e\u003chead\u003e\u003c/head\u003e\u003cbody\u003enyyyyyose9urc0eqsjqcoda3f4bm8vj4c\u003c/body\u003e\u003c/html\u003e","remote-address":"127.0.0.1","timestamp":"2021-08-26T20:07:52.353891791Z"}
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
        switch(protocol){
            case "dns":
                result = "Query Type: " + obj.getString("q-type") + "\n\n";
                result += "Request: \n" + obj.getString("raw-request") + "\n";
                result += "Response: \n" + obj.getString("raw-response") + "\n";
                break;
            case "http":
                result = "Request: \n" + obj.getString("raw-request") + "\n";
                result += "Response: \n" + obj.getString("raw-response") + "\n";
                break;
            default:
                result = "UNSUPPORTED PROTOCOL";
        }
        return result;
    }

    public String toString(){
        return "Protocol: " + protocol + "\n"
                + "UID: " + uid + "\n"
                + "Address: " + address + "\n"
                + "Timestamp: " + timestamp + "\n";
    }
}
