#!/usr/bin/env python3
import base64, hashlib, hmac, json, os, struct, sys
from pathlib import Path

EXPECTED_PRE = "84af8a3e6d71548b0aa4bcf4235a2261a4055dd5941b23fa15cf7ac74b3e8281"
EXPECTED_POST = "aa528bfdc0ff8bb8f7ebaaff33d40d1835b5015ce49892a02d48a13161f320ca"
EXPECTED_PLAIN = "1d3d95c3f8e642d6fd418809c37fca86202650c149667a34286c4e4aa004610f"
EXPECTED_BUNDLE_ID = "SPF_ADTECH_MANAGEMENT_SLACK_V146_LANDING_BUNDLE_20260918"

def rotl(x,n): return ((x << n) & 0xffffffff) | (x >> (32-n))
def qr(x,a,b,c,d):
    x[a]=(x[a]+x[b])&0xffffffff; x[d]^=x[a]; x[d]=rotl(x[d],16)
    x[c]=(x[c]+x[d])&0xffffffff; x[b]^=x[c]; x[b]=rotl(x[b],12)
    x[a]=(x[a]+x[b])&0xffffffff; x[d]^=x[a]; x[d]=rotl(x[d],8)
    x[c]=(x[c]+x[d])&0xffffffff; x[b]^=x[c]; x[b]=rotl(x[b],7)
def block(key,counter,nonce):
    st=list(struct.unpack("<4I",b"expand 32-byte k"))+list(struct.unpack("<8I",key))+[counter]+list(struct.unpack("<3I",nonce))
    x=st[:]
    for _ in range(10):
        qr(x,0,4,8,12);qr(x,1,5,9,13);qr(x,2,6,10,14);qr(x,3,7,11,15)
        qr(x,0,5,10,15);qr(x,1,6,11,12);qr(x,2,7,8,13);qr(x,3,4,9,14)
    return b"".join(struct.pack("<I",(x[i]+st[i])&0xffffffff) for i in range(16))
def xor_stream(key,nonce,data):
    out=bytearray(len(data)); ctr=1
    for off in range(0,len(data),64):
        ks=block(key,ctr,nonce); ctr+=1
        for i,b in enumerate(data[off:off+64]): out[off+i]=b^ks[i]
    return bytes(out)
def sha(s): return hashlib.sha256(s.encode("utf-8")).hexdigest()
def entries(files):
    e=[]
    for f in files:
        src=str(f.get("source","")); raw=src.encode("utf-8")
        e.append({"name_sha256":sha(str(f.get("name",""))),"type":str(f.get("type","")),"source_sha256":hashlib.sha256(raw).hexdigest(),"source_bytes":len(raw)})
    return sorted(e,key=lambda x:(x["name_sha256"],x["type"]))
def aggregate(files):
    e=entries(files)
    return hashlib.sha256(json.dumps(e,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def main():
    if len(sys.argv)!=5:
        print("USAGE: decrypt_bundle.py ENC PRE_CONTENT BUNDLE_OUT UPDATE_OUT",file=sys.stderr); return 2
    key_b64=os.environ.get("ADTECH_BUNDLE_KEY_B64","")
    if not key_b64: print("MISSING_ADTECH_BUNDLE_KEY_B64"); return 3
    master=base64.b64decode(key_b64)
    if len(master)!=32: print("BUNDLE_KEY_LENGTH_FAIL"); return 4
    enc=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    nonce=base64.b64decode(enc["nonce_b64"]); ct=base64.b64decode(enc["ciphertext_b64"]); aad=enc["aad"].encode()
    enc_key=hashlib.sha256(master+b"|enc").digest(); mac_key=hashlib.sha256(master+b"|mac").digest()
    tag=hmac.new(mac_key,aad+nonce+ct,hashlib.sha256).hexdigest()
    if not hmac.compare_digest(tag,enc["tag_hex"]): print("BUNDLE_HMAC_FAIL"); return 5
    plain=xor_stream(enc_key,nonce,ct)
    if hashlib.sha256(plain).hexdigest()!=EXPECTED_PLAIN: print("BUNDLE_PLAINTEXT_HASH_FAIL"); return 6
    bundle=json.loads(plain)
    if bundle.get("bundle_id")!=EXPECTED_BUNDLE_ID or bundle.get("expected_postimage_fingerprint")!=EXPECTED_POST:
        print("BUNDLE_IDENTITY_FAIL"); return 7
    Path(sys.argv[3]).write_bytes(plain)

    pre=json.loads(Path(sys.argv[2]).read_text(encoding="utf-8")); pre_files=pre.get("files") or []
    if len(pre_files)!=9 or aggregate(pre_files)!=EXPECTED_PRE:
        print("PREIMAGE_GUARD_FAIL"); return 8
    add=bundle.get("files") or []
    if len(add)!=7: print("CANDIDATE_FILE_COUNT_FAIL"); return 9
    existing={str(f.get("name","")) for f in pre_files}; add_names={str(f.get("name","")) for f in add}
    if existing & add_names: print("PROTECTED_EXISTING_NAME_COLLISION"); return 10
    for f in add:
        raw=str(f["source"]).encode("utf-8")
        if hashlib.sha256(raw).hexdigest()!=f["source_sha256"] or len(raw)!=int(f["source_bytes"]):
            print("CANDIDATE_SOURCE_HASH_FAIL"); return 11
    merged=list(pre_files)+[{"name":f["name"],"type":f["type"],"source":f["source"]} for f in add]
    post=aggregate(merged)
    if len(merged)!=16 or post!=EXPECTED_POST:
        print("POSTIMAGE_PRECOMPUTE_FAIL"); return 12
    Path(sys.argv[4]).write_text(json.dumps({"files":merged},separators=(",",":")),encoding="utf-8")
    print(json.dumps({"state":"V146_LANDING_PREFLIGHT_PASS","pre_fingerprint":EXPECTED_PRE,"pre_file_count":9,"added_file_count":7,"post_fingerprint":EXPECTED_POST,"post_file_count":16,"protected_existing_files_preserved":True,"production_mutation_count":0},separators=(",",":")))
    return 0
if __name__=="__main__": raise SystemExit(main())
