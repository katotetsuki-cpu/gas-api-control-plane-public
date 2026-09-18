#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path

EXPECTED_PRE = "84af8a3e6d71548b0aa4bcf4235a2261a4055dd5941b23fa15cf7ac74b3e8281"
EXPECTED_POST = "3147db172d15155870e2429d3306d7dce9b5fd7b6d924ac1215a05b8deaf33bb"
EXPECTED_PRE_COUNT = 9
EXPECTED_POST_COUNT = 16
EXPECTED = {
  "AdTech_Management_V140_00_Config_Core": ("SERVER_JS","69203e7ce31c4f6a563cf488435d12270f406fbae79fabc6ecd161b7c902d8c9",7953),
  "AdTech_Management_V140_10_Source_Calculation": ("SERVER_JS","c3bc8877e61bfd24d95369c5bf90c9ed2d8229bbf599587a87916ad62a4dc72e",10986),
  "AdTech_Management_V140_20_Hygiene_Message": ("SERVER_JS","0fe74ed459bdf3e414fe28dc346bc431fb94c0b2c70a4ebac888c561374281e5",16698),
  "AdTech_Management_V140_30_Runtime_Transport": ("SERVER_JS","32b8aeb5e9f61047d82b404ca610a7eda0b53ab6fe0300c34ad761e7c916f701",11831),
  "AdTech_Management_V140_35_Legacy_State_Baseline": ("SERVER_JS","fde61ed671226eea707deef6b5e2941d7aa231594c742bb0ca3c5a238e98ca26",3292),
  "AdTech_Management_V140_40_Trigger_Migration": ("SERVER_JS","cc16073bb95b0c998e26753d2f7ac1d4702f97bcdccbf5f4c40f93ea99157861",2497),
  "AdTech_Management_V140_50_Natural_Bootstrap": ("SERVER_JS","e6e1603acdf87bb85f2e6bd9e355377daf4682133b36a7f30880e89483306d17",8184),
}

def sha(s): return hashlib.sha256(s.encode("utf-8")).hexdigest()
def entries(files):
  out=[]
  for f in files:
    src=str(f.get("source",""))
    out.append({"name_sha256":sha(str(f.get("name",""))),"type":str(f.get("type","")),"source_sha256":sha(src),"source_bytes":len(src.encode("utf-8"))})
  return sorted(out,key=lambda x:(x["name_sha256"],x["type"]))
def aggregate(files):
  e=entries(files)
  return hashlib.sha256(json.dumps(e,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def main():
  if len(sys.argv)!=4:
    print("USAGE: adtech_gas_land_v1.py PRE_CONTENT BUNDLE UPDATE_OUT",file=sys.stderr); return 2
  pre=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
  bundle=json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
  pre_files=pre.get("files") or []
  if len(pre_files)!=EXPECTED_PRE_COUNT or aggregate(pre_files)!=EXPECTED_PRE:
    print("PREIMAGE_GUARD_FAIL"); return 3
  if bundle.get("bundle_id")!="SPF_ADTECH_MANAGEMENT_SLACK_V144_LANDING_BUNDLE_20260918":
    print("BUNDLE_ID_FAIL"); return 4
  bfiles=bundle.get("files") or []
  if len(bfiles)!=len(EXPECTED): print("BUNDLE_FILE_COUNT_FAIL"); return 5
  names=set()
  for f in bfiles:
    name=str(f.get("name","")); typ=str(f.get("type","")); src=str(f.get("source",""))
    if name not in EXPECTED: print("BUNDLE_UNEXPECTED_NAME"); return 6
    etype,esha,ebytes=EXPECTED[name]
    if typ!=etype or sha(src)!=esha or len(src.encode("utf-8"))!=ebytes:
      print("BUNDLE_SOURCE_IDENTITY_FAIL"); return 7
    names.add(name)
  if names!=set(EXPECTED): print("BUNDLE_NAME_SET_FAIL"); return 8
  existing={str(f.get("name","")) for f in pre_files}
  if existing & names:
    print("PROTECTED_EXISTING_NAME_COLLISION"); return 9
  merged=list(pre_files)+[{"name":str(f["name"]),"type":str(f["type"]),"source":str(f["source"])} for f in bfiles]
  if len(merged)!=EXPECTED_POST_COUNT or aggregate(merged)!=EXPECTED_POST:
    print("POSTIMAGE_PRECOMPUTE_FAIL"); return 10
  Path(sys.argv[3]).write_text(json.dumps({"files":merged},separators=(",",":")),encoding="utf-8")
  print(json.dumps({"state":"LANDING_PAYLOAD_READY","pre_fingerprint":EXPECTED_PRE,"pre_file_count":len(pre_files),"added_file_count":len(bfiles),"post_fingerprint":EXPECTED_POST,"post_file_count":len(merged),"protected_existing_files_preserved":True,"mutation_count":0},separators=(",",":")))
  return 0
if __name__=="__main__": raise SystemExit(main())
