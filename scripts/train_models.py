import hashlib, json, pickle, time
import numpy as np
from _common import ROOT, log
from uniaethel.config import config_hash, load_config
from uniaethel.data import load_capture, split_files
from uniaethel.evaluation.runner import classify_incidents, evidence_for
from uniaethel.fusion.attack_vector import set_rejection_thresholds
from uniaethel.fusion.decision import LADDER, PRIMARY, calibrate_all
from uniaethel.pipeline import Pipeline

T0 = time.time()
cfg = load_config(ROOT / "configs/default.yaml")
pipe = Pipeline(cfg)
train0 = [load_capture(f, cfg) for f in split_files(cfg, "train")]
base = pipe.fit_graph(train0)                                   
train = [load_capture(f, cfg, baseline=base) for f in split_files(cfg, "train")]
log.info("train: %d benign captures, %d windows", len(train), sum(len(c["F"]) for c in train))
pipe.fit(train)                                                 
log.info("engines fitted on benign only; TCN loss %.3f -> %.3f; Ledoit-Wolf shrinkage %.3f",
         pipe.tcn.loss_history[0], pipe.tcn.loss_history[-1], pipe.maha.shrinkage_)
base = pipe.baseline_relationships
val_files = split_files(cfg, "val")
val_benign = [load_capture(f, cfg, baseline=base) for f in val_files if "/normal_" in f]  
pipe.calibrate(val_benign)
log.info("per-host calibration on %d benign validation captures", len(val_benign))


# for tuning - they are a stress test reported separately (docs/EXPERIMENTS.md).
import yaml
man = {c["file"]: c for c in yaml.safe_load(open(ROOT / "data/MANIFEST.yaml"))["captures"]}
tune_files = [f for f in val_files if not man[str(f).replace(str(ROOT) + "/", "")]["hard_negative_for"]]
caps, evs, es = evidence_for(tune_files, pipe, cfg, baseline=base)
log.info("threshold tuning on %d validation captures (normal + attacks; hard negatives excluded)", len(tune_files))
frozen = calibrate_all(es, cfg, LADDER, log=lambda m: log.info(m))
inc = classify_incidents(es, frozen[PRIMARY], cfg, None, None)
known = inc[inc["truth"].isin(["C2", "RECON", "DDOS", "EXFIL"])]
tau_c, delta = set_rejection_thresholds([(a, t) for a, t in zip(known["_agg"], known["truth"])],
                                        cfg["attack_vector"]["target_known_reject"])
acc = float((known["argmax"] == known["truth"]).mean()) if len(known) else float("nan")
log.info("validation: %d known-class incidents, argmax accuracy %.2f -> tau_class=%.4f delta_margin=%.4f",
         len(known), acc, tau_c, delta)
av = {"tau_class": tau_c, "delta_margin": delta, "val_argmax_accuracy": acc, "val_known_incidents": int(len(known))}
params = {n: {"engines": f.config.engines, "weights": f.weights.tolist(), "tau_sev": f.tau_sev,
              "validation": {k: v for k, v in f.val.items() if isinstance(v, (int, float, bool))}} for n, f in frozen.items()}
blob = json.dumps({"decision": params, "attack_vector": av, "config_hash": config_hash(cfg)}, sort_keys=True, indent=1, default=float)
(ROOT / "results/models").mkdir(parents=True, exist_ok=True)
(ROOT / "results/frozen_params.json").write_text(blob)
digest = hashlib.sha256(blob.encode()).hexdigest()
(ROOT / "results/FREEZE.txt").write_text(f"frozen_params.json sha256={digest}\nconfig_hash={config_hash(cfg)}\n"
                                         f"primary={PRIMARY}\nfrozen_at_unix={time.time():.0f}\ntest captures scored before freeze: 0\n")
pickle.dump({"pipe": pipe, "frozen": frozen, "cfg": cfg, "attack_vector": av}, open(ROOT / "results/models/bundle.pkl", "wb"))
log.info("FROZEN sha256=%s... (%.0f s)", digest[:16], time.time() - T0)
