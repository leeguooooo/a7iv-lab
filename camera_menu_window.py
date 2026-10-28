"""Mac host adapter for the fixed stock-6.02 two-instruction RAM window.

Injected authenticated device only: no discovery, authentication, STOP, reboot,
SD activation, or installation CLI. Successful patch publication still needs a
known service exit, same-body normal-mode reappearance and an operator handoff.
The 600-second native timer is conditional cleanup, not an independent watchdog.
"""
import hashlib
import json
from pathlib import Path
import struct
import time
from dataclasses import dataclass

from camera_stream_execution import BootstrapChannel, LIBRARIES, SLOT, LAUNCH, validate_launch, durable_new

ROOT=Path(__file__).resolve().parent
JOB=ROOT/'output/menu-stock-window-offline-01'
MANIFEST_SHA='5032bbab664187c140a81f42a8cd6811b4e07fea199c9958693e946a91237f1c'
MODULE_SHA='d860f9548cd36c5d5f27d268c52de2012e8299769ba50014e9ab6130c2572b47'
BASE_FIELDS=('version','phase','error','euid','pid','ppid','loader_pid','cleanup','maps_bytes','polls',
             'target_addr','base_addr','machine_version','patched','restored','hold_seconds','flags','mem_status','restore_status')
APP_FIELDS=('app_pid','app_target_addr','app_base_addr','app_machine_version','app_patched','app_restored',
            'app_mem_status','app_restore_status','app_write_attempted')
STATUS_FIELDS=('app_maps_bytes','proc_candidates','identity_checks','lib_identity_status','app_identity_status',
               'snapshot_before_status','snapshot_end_status')
OBSERVATIONS=('usb_stream','network_stream','slot1_mount','media_error','target_version','query_error','inhibited','debug_exclusion')
FIELDS=BASE_FIELDS+APP_FIELDS+STATUS_FIELDS+tuple(f'{phase}_{n}' for phase in ('before','end') for n in OBSERVATIONS)
FRAME=struct.Struct('<8s16s51q')
LENGTHS={'launch':104,'ready':432,'patched':432,'result':432,'exec_failure':8}


@dataclass(frozen=True)
class MenuAssets:
    """Hashes come from the caller's reviewed/sealed offline plan, not a device."""
    directory: Path
    manifest_sha256: str
    module_sha256: str


def asset_reference(assets=None):
    value=assets or MenuAssets(JOB,MANIFEST_SHA,MODULE_SHA)
    require(isinstance(value,MenuAssets),'Reviewed MenuAssets required')
    path=Path(value.directory).absolute()
    require(path.resolve().is_relative_to(ROOT/'output') and not path.is_symlink(), 'Menu assets outside workspace')
    require(all(isinstance(s,str) and len(s)==64 and all(c in '0123456789abcdef' for c in s)
                for s in (value.manifest_sha256,value.module_sha256)), 'Bound asset SHA-256 required')
    return value,path


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def checked_job(assets=None):
    reference,job=asset_reference(assets)
    require(sha(job/'manifest.json')==reference.manifest_sha256,'Frozen menu manifest changed')
    m=json.loads((job/'manifest.json').read_text())
    require(m['schema']=='camera-menu-stock-window-offline/1' and m['admission']=='OFFLINE_NOT_BODY_BOUND'
            and m['profile']=='menu_stock_6.02_saved_ELFs','Fixed stock menu profile required')
    for name,digest in m['sources'].items():
        p=ROOT/name
        require(p.resolve().is_relative_to(ROOT) and not p.is_symlink() and sha(p)==digest,'Menu source changed')
    for name,row in m['artifacts'].items():
        p=job/name
        require(p.name==name and p.is_file() and not p.is_symlink() and p.stat().st_size==row['bytes']
                and sha(p)==row['sha256'],'Menu artifact changed')
    module=(job/'libJit.so').read_bytes()
    require(0<len(module)<=65520 and hashlib.sha256(module).hexdigest()==reference.module_sha256,'Fixed menu module changed')
    require(m['result']['format']=='<8s16s51q' and m['result']['fields']==list(FIELDS)
            and m['result']['bytes']==FRAME.size==432,'Menu ABI changed')
    model=json.loads((job/'native-model-report.json').read_text())
    require(model['all_passed'] is True and model['manifest_sha256']==reference.manifest_sha256
            and model['case_count']==29 and all(c['passed'] is True for c in model['cases'])
            and model['emulator_sha256']==sha(ROOT/'tools/emulate_menu_window_offline.py'),
            'Native model evidence stale or incomplete')
    return m,module


def decode(raw,nonce):
    require(isinstance(raw,bytes) and len(raw)==FRAME.size,'Complete 432-byte menu record required')
    magic,got,*values=FRAME.unpack(raw)
    require(magic==b'M4DWL002' and got==nonce and len(nonce)==16,'Menu record identity differs')
    r=dict(zip(FIELDS,values))
    require(r['version']==1 and r['phase'] in (1,2,3,4,5,6,90) and -4095<=r['error']<=0,
            'Unsupported menu result contract')
    require(0<=r['flags']<=1021 and not r['flags']&~1021,'Unknown menu flags')
    for name in ('patched','restored','app_patched','app_restored','app_write_attempted'):
        require(r[name] in (0,1),'Invalid menu Boolean')
    require(bool(r['flags']&128)==bool(r['patched']) and bool(r['flags']&256)==bool(r['restored'])
            and (not r['patched'] or r['flags']&512)
            and (not r['restored'] or r['flags']&512)
            and (not r['app_patched'] or r['app_write_attempted'])
            and (not r['app_restored'] or r['app_write_attempted']), 'Contradictory menu write flags')
    require(r['hold_seconds']>=0 and r['pid']>1 and r['loader_pid']>1
            and r['pid']!=r['loader_pid'] and r['ppid']==1 and r['euid']==0 and r['cleanup']==0,
            'Menu process identity/lifecycle rejected')
    return r


def same_worker(a,b):
    return all(a[k]==b[k] for k in ('euid','pid','ppid','loader_pid','cleanup'))


def ready_proof(r,loader):
    zero=tuple(k for k in BASE_FIELDS[8:]+APP_FIELDS+STATUS_FIELDS[:5] if k!='flags')
    require(r['phase']==1 and r['error']==0 and r['flags']==13 and r['loader_pid']==loader
            and all(r[k]==0 for k in zero)
            and r['snapshot_before_status']==r['snapshot_end_status']==-11
            and all(r[f'{phase}_{n}']==-1 for phase in ('before','end') for n in OBSERVATIONS),
            'Menu readiness differs from the reviewed zero-write initial state')


def patched_proof(r,ready):
    require(same_worker(r,ready) and r['phase']==5 and r['error']==0 and r['flags']==765
            and r['patched']==r['app_patched']==r['app_write_attempted']==1
            and r['restored']==r['app_restored']==0 and r['app_pid']>1 and r['app_pid']!=r['pid']
            and r['target_addr']==r['base_addr']+8016 and r['app_target_addr']==r['app_base_addr']+40219336
            and r['base_addr']>=0 and r['app_base_addr']>=0
            and r['target_addr']>0 and r['app_target_addr']>0
            and r['target_addr']%4==r['app_target_addr']%4==0
            and r['machine_version']==0x0602 and r['app_machine_version']==0x00060002
            and r['proc_candidates']==1
            and all(r[k]==0 for k in ('mem_status','app_mem_status','lib_identity_status','app_identity_status',
                                      'snapshot_before_status','snapshot_end_status')),
            'Both stock-6.02 patch publications must be proven')


def terminal_proof(r,ready,patched=None):
    require(same_worker(r,ready) and r['phase'] in (6,90),'Bound terminal menu record required')
    if r['phase']==6:
        require(r['error']==0 and r['flags']==1021 and r['hold_seconds']>=600
                and r['patched']==r['restored']==r['app_patched']==r['app_restored']==r['app_write_attempted']==1,
                'Contradictory native menu success')
    else:require(r['error']<0,'Native error phase without error')
    if patched is not None:
        require(all(r[k]==patched[k] for k in ('app_pid','app_target_addr','app_base_addr','target_addr','base_addr')),
                'Menu targets changed since handoff')
    lib_safe=(not r['flags']&512 and r['patched']==0) or (
        r['restored']==1 and r['restore_status']==r['lib_identity_status']==r['mem_status']==0)
    app_safe=(r['app_write_attempted']==r['app_patched']==0) or (
        r['app_restored']==1 and r['app_restore_status']==r['app_identity_status']==r['app_mem_status']==0)
    return {'native_terminal_observed':True,'both_RAM_targets_proven_safe':bool(lib_safe and app_safe),
            'native_error':r['error'],'firmware_installation_proven':False,
            'state':'RAM_TERMINAL_SAFE' if lib_safe and app_safe else 'RAM_STATE_UNKNOWN_MANUAL_REVIEW',
            'automatic_reupload':False,'automatic_START':False,'automatic_reboot':False}


class MenuChannel(BootstrapChannel):
    def __init__(self,device,nonce,clock=time.monotonic):
        super().__init__(device,nonce,clock)
        self.directory='/tmp_wbshd/m4dual_'+nonce.hex();self.start_attempted=False

    def read(self,name,missing=False):
        require(name in LENGTHS,'Fixed menu publications only')
        self._select(name)
        return self._packet(17,b'\0\xff\0',LENGTHS[name],missing)

    def start_once(self,evidence):
        if self.start_attempted:raise RuntimeError('Menu START already attempted; no replay')
        self.start_attempted=True
        durable_new(Path(evidence)/'start-intent.json',{'nonce':self.nonce.hex(),'automatic_retry':False})
        self._select('start')
        raw=b'M4DSTART'+self.nonce+struct.pack('<Q',1)
        if self._packet(16,b'\0\xff\0'+raw,0)!=b'':
            self.healthy=False;raise ValueError('Menu START response changed')


def _poll(channel,name,seconds,evidence,clock,sleep):
    deadline=clock()+seconds
    while clock()<deadline:
        raw=channel.read(name,missing=True)
        if raw is not None:
            durable_new(Path(evidence)/(name+'-received.json'),{'bytes':len(raw),'raw_hex':raw.hex()})
            require(len(raw)==LENGTHS[name],'Incomplete native menu publication; no retry')
            return raw
        if name!='result':
            final=channel.read('result',missing=True)
            if final is not None:
                durable_new(Path(evidence)/(name+'-early-result.json'),{'bytes':len(final),'raw_hex':final.hex()})
                raise RuntimeError('Menu worker ended before requested phase')
        if channel.read('exec_failure',missing=True) is not None:raise RuntimeError('Menu worker exec failed')
        sleep(0.1)
    raise TimeoutError('Menu publication deadline; no replay')


def start_authenticated(device,evidence,*,ram_authorized=False,body_verified=False,
                        source_is_hardware=False,capture_one=None,assets=None,capture_assets=None,
                        clock=time.monotonic,sleep=time.sleep):
    """Caller must hold the device lease and durably record RAM_MAY_BE_ACTIVE.

    This returns only a patch observation. Do not tell the user to start an
    update until a known service exit, same-body normal reappearance and the
    conservative time budget have also been verified. Never powercycle merely
    because a host countdown expires.
    """
    require(ram_authorized is True and body_verified is True,'Explicit volatile-window approval and body preflight required')
    require(type(source_is_hardware) is bool,'Explicit evidence kind required')
    reference,job=asset_reference(assets)
    meta,module=checked_job(assets);nonce=bytes.fromhex(meta['nonce']);folder=Path(evidence)
    require(folder.is_dir() and not folder.is_symlink(),'Fresh local evidence directory required')
    if capture_one is None:
        from camera_firmware_capture import capture_one_authenticated
        capture_one=capture_one_authenticated
    durable_new(job/'physical-attempt.json',{'nonce':meta['nonce'],'module_sha256':reference.module_sha256,
        'source_is_hardware':source_is_hardware,'state':'RESERVED_BEFORE_ANY_PROTOCOL_REQUEST','automatic_retry':False})
    channel=None;stage='READ_ONLY_FULL_LIBRARY_CAPTURE'
    try:
        captures={}
        profiles=(('pre_app',98212632,'1e1b9202eaa69198f20df03dbfdab2f103b206cc4ebcd2e7bd817e6a710018a2'),
                  ('pre_ufp',22768,'f2e7d27602e3f7b236fc41dd93fccf53ba24f0793fd454e7fec171ae378beca7'))
        for name,size,expected in profiles:
            options={} if capture_assets is None else {'assets':capture_assets}
            value=capture_one(device,name,folder/name,source_is_hardware=source_is_hardware,clock=clock,sleep=sleep,**options)
            native=value['native']
            require(value['profile']==name and value['bytes']==size and value['sha256']==expected
                    and value['source_is_hardware'] is source_is_hardware and value['nonce']!=meta['nonce']
                    and native['phase']==6 and native['flags']==63 and native['error']==native['cleanup']==0
                    and native['offset']==size and native['first_sha256']==native['second_sha256']==expected,
                    'Complete file capture differs from stock profile; no next request')
            captures[name]=value
        durable_new(folder/'complete-library-captures.json',captures)
        channel=MenuChannel(device,nonce,clock)
        for path,expected in LIBRARIES.items():
            require(hashlib.sha256(channel.read_loader(path)).hexdigest()==expected,'Loader library changed')
        require(channel.read_loader(SLOT) is None,'Existing module slot belongs to another operation')
        stage='MENU_MODULE_MAY_HAVE_BEEN_UPLOADED'
        channel.upload_once(module,reference.module_sha256,folder/'module-attempt.json')
        loader=validate_launch(_poll(channel,'launch',30,folder,clock,sleep),nonce)
        ready=decode(_poll(channel,'ready',30,folder,clock,sleep),nonce)
        ready_proof(ready,loader)
        durable_new(folder/'ready.json',ready)
        started=clock();stage='MENU_START_MAY_HAVE_BEEN_SENT';channel.start_once(folder)
        patched=decode(_poll(channel,'patched',330,folder,clock,sleep),nonce);patched_proof(patched,ready)
        final=channel.read('result',missing=True)
        if final is not None:
            durable_new(folder/'terminal-before-handoff.json',{'bytes':len(final),'raw_hex':final.hex()})
        require(final is None,'Menu window already ended before handoff')
        now=clock();remaining=600-(now-started)
        require(now>=started and remaining>=120,'Insufficient conservative time; no installation handoff')
        report={'state':'PATCH_OBSERVED_AWAITING_KNOWN_EXIT_AND_NORMAL_BODY','nonce':meta['nonce'],
                'asset_reference':{'directory':str(job),'manifest_sha256':reference.manifest_sha256,
                                   'module_sha256':reference.module_sha256},
                'ready':ready,'patched':patched,'conservative_seconds_remaining':remaining,
                'source_is_hardware':source_is_hardware,'full_live_file_capture_reports':captures,
                'service_exit_completed':False,'normal_body_reappearance_verified':False,
                'SD_package_or_installation_acceptance_proven':False,'installation_authorized':False,
                'timer_is_independent_watchdog':False,'automatic_retry':False}
        durable_new(folder/'handoff.json',report)
        return report
    except BaseException as error:
        if channel is not None:channel.healthy=False
        durable_new(folder/'stopped.json',{'stage':stage,'error_type':type(error).__name__,
            'RAM_state_requires_receipt_or_manual_review':True,'automatic_retry':False,
            'automatic_STOP':False,'automatic_reboot':False,'automatic_host_rollback':False})
        raise


def collect_authenticated(device,evidence,handoff,*,body_verified=False,
                          firmware_never_started_confirmed=False,
                          assets=None,clock=time.monotonic,sleep=time.sleep):
    """Existing window publications only; no upload/START/reconnect/exit path.

    The caller separately owns the authenticated session and device lease.
    Never call this during a possible full-SDK update merely to seek a timer
    receipt. Elapsed time, missing tmpfs records or a reboot are not byte-restore
    evidence from this protocol.
    """
    require(body_verified is True and firmware_never_started_confirmed is True,
            'Same-body read-only collection requires confirmation no firmware update started')
    reference,job=asset_reference(assets)
    meta,_=checked_job(assets);nonce=bytes.fromhex(meta['nonce'])
    require(handoff.get('asset_reference')=={'directory':str(job),'manifest_sha256':reference.manifest_sha256,
                                          'module_sha256':reference.module_sha256}, 'Menu asset handoff binding changed')
    require(handoff['nonce']==meta['nonce'] and handoff['state']=='PATCH_OBSERVED_AWAITING_KNOWN_EXIT_AND_NORMAL_BODY',
            'Original patch observation required')
    folder=Path(evidence);folder.mkdir(mode=0o700)
    channel=MenuChannel(device,nonce,clock)
    try:
        for name in ('ready','patched'):
            raw=channel.read(name,missing=True)
            require(raw is not None,'Original window publications missing; no restoration inference')
            durable_new(folder/(name+'-received.json'),{'bytes':len(raw),'raw_hex':raw.hex()})
            require(decode(raw,nonce)==handoff[name],'Original native publication changed')
        raw=_poll(channel,'result',720,folder,clock,sleep)
        result=decode(raw,nonce)
        proof=terminal_proof(result,handoff['ready'],handoff['patched'])
        durable_new(folder/'terminal-proof.json',proof|{'native':result,'module_uploads':0,'START_attempts':0})
        require(proof['both_RAM_targets_proven_safe'],'RAM restoration unknown; manual review required')
        return proof|{'native':result}
    except BaseException as error:
        channel.healthy=False
        durable_new(folder/'stopped.json',{'error_type':type(error).__name__,'module_uploads':0,
            'START_attempts':0,'automatic_retry':False,'automatic_reboot':False,
            'elapsed_time_is_not_restoration_proof':True})
        raise
