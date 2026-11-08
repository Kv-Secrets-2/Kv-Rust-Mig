"""Policy request storage oracle on disposable fixture copies."""
import json
from pathlib import Path
import sys
from kv import policy_requests as p
from kv.config import load_config, save_config
root = Path(sys.argv[1])
action = sys.argv[2]
def seed():
    Path(p.policy_request_store_path(root)).unlink(missing_ok=True)
    for name, now in (("one",4102440000),("two",4102440000),("expired",0),("decided",4102440000)):
        p.create_policy_request(root,argv=["python3",name+".py"],cwd=str(root),
            pattern="python3 "+name+".py",request_id="pol_"+name,now=now,
            actor={"source":"mcp","client_name":"münchen"},reason="review\nthis")
    doc=p._read_store(root)
    doc["requests"][0]["test_float"]=1.25
    doc["requests"][-1]["status"]=42
    p._write_store(root,doc)
if action == "init":
    from kv.vault_origin import record_created
    sdir=root/".secrets"
    sdir.chmod(0o700)
    for path in sdir.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)
    record_created(root)
elif action == "seed":
    seed()
elif action == "flow":
    result={"list":p.list_policy_requests(root,include_all=True,now=1001),
            "fingerprint":p.request_fingerprint(p.get_policy_request(root,"pol_one",now=1001)),
            "missing":p.get_policy_request(root,"missing",now=1001)}
    result["blocked"]=[p.block_policy_request(root,"pol_one",reason=" a reason ",now=1001),
                       p.block_policy_request(root,"pol_one",now=1001)]
    result["remaining"]=p.prune_policy_requests(root,now=1001)
    print(json.dumps(result))
elif action in ("stale","tamper"):
    request=p.get_policy_request(root,"pol_one")
    reviewed=p.request_fingerprint(request)
    snapshot=load_config(root)
    if action == "stale":
        changed=load_config(root)
        changed["test_change"]=True
        save_config(root,changed)
    else:
        doc=p._read_store(root)
        doc["requests"][0]["reason"]="changed after review"
        p._write_store(root,doc)
    try:
        p.allow_policy_request(root,"pol_one",root,snapshot=snapshot,expected_fingerprint=reviewed)
        print(json.dumps({"error":None}))
    except (ValueError,PermissionError) as exc:
        print(json.dumps({"error":str(exc)}))
elif action == "read":
    try:
        print(json.dumps({"requests":p.list_policy_requests(root,include_all=True,now=1001)}))
    except (ValueError,PermissionError) as exc:
        print(json.dumps({"error":str(exc)}))
else:
    raise ValueError(action)
