// settlement_round validity gauntlet -- Java impl.
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
public class SrRunner {
	static boolean rpiOk(JsonNode v){ if(v==null||v.isBoolean()) return false; if(!v.isIntegralNumber()) return false; return v.asLong()>0; }
	public static void main(String[] a) throws Exception {
		ObjectMapper om=new ObjectMapper(); JsonNode d=om.readTree(new java.io.File(a[0]));
		int ok=0; var fails=new java.util.ArrayList<String>();
		for(JsonNode r: d.get("settlement_round_reject_vectors")){
			if(!rpiOk(r.get("receipt").get("settlement_round"))) ok++; else fails.add(r.get("vector_id").asText()+": bad round ACCEPTED");
		}
		JsonNode acc=null;
		for(JsonNode v: d.get("vectors")){ JsonNode sr=v.path("receipt").get("settlement_round"); if(sr!=null&&sr.isIntegralNumber()){ acc=v; break; } }
		if(rpiOk(acc.get("receipt").get("settlement_round"))) ok++; else fails.add(acc.get("vector_id").asText()+": valid round REJECTED");
		int total=d.get("settlement_round_reject_vectors").size()+1;
		for(String f:fails) System.out.println("  FAIL "+f);
		System.out.println("SETTLEMENT-ROUND-GAUNTLET java "+ok+"/"+total);
		if(ok!=total||!fails.isEmpty()) System.exit(1);
	}
}
