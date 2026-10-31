"""Derive the owned observer/worker fix from exact source inputs.

Third-party/runtime baselines remain private inputs; this tool never touches
firmware or enables native admission. It adds no persistent runtime storage.
"""
import argparse
import hashlib
from pathlib import Path


PINS = {
    "runtime": "96643bf30bae6ad65d7e32465cb39c9a9d6392e990535fa3d248284b8143f7b0",
    "header": "3a1e2e7a7e74ba0b61cb3130235993095adcc0382bf40685a5c14f5aec93f249",
    "events": "79cfd3f94094fab36a9f2943ab4c080c31a30b56ae15d29a8d8189b120a469b0",
}

GENERATION_SNAPSHOT = """int csnd_ap_event_generation(uint32_t event,uint32_t *generation) {
    int status=CSND_AP_NOT_READY;
    if(generation)*generation=0;
    if(event!=SS_ELECTRONIC_EXPOSURE || !generation)return SS_INVALID;
    if(!acquire())return CSND_AP_BUSY;
    if(csnd_ap_state.initialized) {
        if(storage_blocked())status=SS_STORAGE;
        else if(!csnd_ap_state.state.slots[0].enabled ||
                !csnd_ap_state.state.slots[0].custom || csnd_ap_mechanical_pending())
            status=SS_DISABLED;
        else {*generation=csnd_ap_state.state.generation;status=SS_OK;}
    }
    /* Event observer: no native getter, IO, allocation or durable drain. */
    __atomic_store_n(&csnd_ap_state.busy,0,__ATOMIC_RELEASE);
    return status;
}
"""


def derive(runtime: bytes, header: bytes, events: bytes):
    inputs = dict(runtime=runtime, header=header, events=events)
    for name, data in inputs.items():
        if hashlib.sha256(data).hexdigest() != PINS[name]:
            raise ValueError("Unsupported source identity: " + name)
    r, h, e = (inputs[name].decode("utf-8") for name in ("runtime", "header", "events"))
    anchor = "int csnd_ap_playback_ticket(uint32_t event,uint32_t *generation,uint32_t *route) {"
    if r.count(anchor) != 1:
        raise ValueError("Runtime ticket anchor changed")
    r = r.replace(anchor, GENERATION_SNAPSHOT + anchor)
    old_comment = """/* Bounded event observer: no WAV/PCM borrow, IO, allocation or durable drain.
 * Outputs are zero/SUPPRESS on failure. Worker must revalidate generation and
 * route; successive native getter values are not an atomic exposure tuple. */"""
    new_comment = """/* Nonblocking private-only observer snapshot. No native policy getter, IO,
 * allocation, durable drain or PCM borrow. Output is zero on failure. */
int csnd_ap_event_generation(uint32_t event,uint32_t *generation);
/* Worker-only policy ticket. No PCM borrow/IO/allocation or durable drain;
 * native getters may lock and are successive, not an atomic exposure tuple.
 * Event callbacks must use csnd_ap_event_generation instead. */"""
    if h.count(old_comment) != 1:
        raise ValueError("Runtime observer contract changed")
    h = h.replace(old_comment, new_comment)
    old = """ er_u32 gen=0,route=0,epoch=csnd_event_revision();
 if(!remember(k,epoch))return;
 if(!LD(run.diag[D_READY])){INC(run.diag[D_SUPPRESSED]);return;}
 int status=((ticket_fn)&csnd_ap_playback_ticket)(k.slot,&gen,&route);
 if(status||!gen||route!=k.slot+2){ST(run.diag[D_LAST_STATUS],(er_u32)status);INC(run.diag[D_SUPPRESSED]);return;}"""
    new = """ er_u32 gen=0,epoch=csnd_event_revision();
 if(!remember(k,epoch))return;
 if(!LD(run.diag[D_READY])){INC(run.diag[D_SUPPRESSED]);return;}
 int status=csnd_ap_event_generation(k.slot,&gen);
 if(status||!gen){ST(run.diag[D_LAST_STATUS],(er_u32)status);INC(run.diag[D_SUPPRESSED]);return;}"""
    if e.count(old) != 1:
        raise ValueError("Event admission anchor changed")
    e = e.replace(old, new)
    return {"src/ap_runtime.c": r.encode(), "include/ap_runtime.h": h.encode(),
            "src/event_runtime.c": e.encode()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in PINS:
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    outputs = derive(*(getattr(args, name).read_bytes() for name in PINS))
    args.output.mkdir(parents=True, exist_ok=False)
    for name, data in outputs.items():
        target = args.output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


if __name__ == "__main__":
    main()
