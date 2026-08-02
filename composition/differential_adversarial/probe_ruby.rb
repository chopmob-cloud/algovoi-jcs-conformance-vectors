# Differential adversarial substrate -- Ruby canon probe (json-canonicalization).
# Contract: see probe_python.py. Emits "<id>\t h:<hex> | R:<reason>" per case.
require "json"
require "json/canonicalization"
require "digest"

d = JSON.parse(File.read(ARGV[0], encoding: "utf-8"))
out = []
d["cases"].each do |c|
  v =
    begin
      val = JSON.parse(c["raw"])            # native parser
      begin
        "h:" + Digest::SHA256.hexdigest(val.to_json_c14n)
      rescue StandardError
        "R:canon"
      end
    rescue StandardError
      "R:parse"
    end
  out << "#{c['id']}\t#{v}"
end
puts out.join("\n")
