"""Fixed metadata collection on an already authenticated caller-owned device.

No authentication, STOP, block reads, RAM patch, flash or journal transition.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
import time

from camera_device_lease import DEFAULT_LOCK
from camera_install_journal import InstallJournal
from camera_install_patch_session import _held_lease
from camera_operation_guard import DEFAULT_SESSIONS, assert_operation_allowed
from camera_stream_execution import BootstrapChannel, LIBRARIES, SLOT, durable_new, validate_launch
from camera_install_runtime import _partitions

ROOT=Path(__file__).resolve().parent
CLAIMS=ROOT/'output/install-runtime-metadata-nonce-claims'
MAGIC=b'M4META02'
VERSION=2
LEGACY_MAGIC=b'M4META01'
BOOT_ID_BYTES=40
ALIAS_BYTES=1768
BOOT_ID_PATTERN=re.compile(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
START_MAGIC=b'M4MSTART'
FRAME=struct.Struct('<8s16s11q32s32s')
START_FRAME=struct.Struct('<8s16sQ')
ALIAS=struct.Struct('<4Q128s128s')
NUMBERS=(1,3,5,7,8,15)
PRE_SCOPE='PRE_INSTALL_RUNTIME_METADATA_READ_ONLY'
EPOCH_SCOPE='INSTALL_PATCH_PENDING_AP_BOOT_EPOCH_READ_ONLY'
FIELDS=('version','phase','error','euid','pid','ppid','loader_pid','cleanup','flags','proc_bytes','alias_bytes')
LENGTHS=dict(launch=104,ready=176,result=176,exec_failure=8,**{'partitions.bin':65536,'aliases.bin':ALIAS_BYTES})


def require(ok,message):
    if not ok:raise ValueError(message)


def _hash(raw):return hashlib.sha256(raw).hexdigest()
def _json(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
def _path(path):
    p=Path(path).absolute()
    require('..' not in p.parts and all(not x.is_symlink() for x in (p,*p.parents)), 'Canonical nonsymlink path required')
    return p


@dataclass(frozen=True)
class MetadataAssets:
    job_dir: Path
    manifest_sha256: str
    module_sha256: str
    native_model_sha256: str
    bootstrap_model_sha256: str


@dataclass(frozen=True)
class PreparedMetadataAssets:
    assets: MetadataAssets
    reference_json: str
    manifest_json: str
    module: bytes
    @property
    def reference(self):return json.loads(self.reference_json)
    @property
    def manifest(self):return json.loads(self.manifest_json)


def _claims(prepared):
    nonce=prepared.manifest['nonce']
    return (CLAIMS/(nonce+'.json'),_path(prepared.assets.job_dir)/'physical-attempt.json')


def preflight_assets(assets,*,owned_reservation=None):
    from tools.verify_install_runtime_metadata_offline import verify
    from tools.emulate_install_runtime_metadata_offline import CASES,BOOTSTRAP_CASES
    require(isinstance(assets,MetadataAssets),'Reviewed MetadataAssets required')
    d=_path(assets.job_dir)
    required={'manifest.json':assets.manifest_sha256,'libJit.so':assets.module_sha256,
        'native-model-report.json':assets.native_model_sha256,'bootstrap-model-report.json':assets.bootstrap_model_sha256}
    for name,expected in required.items():
        require(type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected),'Exact reviewed SHA256 required')
        require(_hash(_path(d/name).read_bytes())==expected,'Reviewed artifact changed: '+name)
    verification=verify(d);m=json.loads((d/'manifest.json').read_bytes());module=(d/'libJit.so').read_bytes()
    require(_hash(module)==assets.module_sha256,'Module changed during acquisition')
    expected_model_bindings=dict(debug_worker_sha256=_hash(_path(d/'worker.debug.elf').read_bytes()),
        emulator_sha256=_hash(_path(ROOT/'tools/emulate_install_runtime_metadata_offline.py').read_bytes()),
        contract_sha256=_hash(_path(ROOT/'camera_install_runtime_metadata.py').read_bytes()),
        profile_sha256=_hash(_path(ROOT/'tools/install_runtime_metadata_profile.py').read_bytes()))
    for name,cases in (('native-model-report.json',CASES),('bootstrap-model-report.json',BOOTSTRAP_CASES)):
        report=json.loads((d/name).read_bytes())
        require(report['all_passed'] is True and report['manifest_sha256']==assets.manifest_sha256
            and report['source_bindings']==m['sources'] and report['artifact_bindings']==m['artifacts']
            and report['verification_sha256']==_hash(_json(verification).encode())
            and all(report.get(key)==expected for key,expected in expected_model_bindings.items())
            and report['cases']==list(cases) and report['hardware_operations']==0
            and report['real_ARM_process'] is False
            and report['coverage_complete_for_declared_matrix'] is True
            and report['declared_cases']==list(cases) and len(report['results'])==len(cases)
            and all(result['passed'] is True and result.get('case',result.get('scenario'))==name
                    for result,name in zip(report['results'],cases)),'Complete current compiled model closure required')
    reference=dict(job_dir=str(d),nonce=m['nonce'],**{key:getattr(assets,key) for key in
        ('manifest_sha256','module_sha256','native_model_sha256','bootstrap_model_sha256')})
    prepared=PreparedMetadataAssets(assets,_json(reference),_json(m),module)
    namespaces=('install-runtime-metadata-nonce-claims','install-patch-read-nonce-claims',
        'install-volatile-patch-nonce-claims','firmware-file-capture-nonce-claims')
    own=set()
    if owned_reservation is not None:
        require(owned_reservation['record']['asset_reference']==reference,'Reservation assets differ')
        require(set(owned_reservation)=={'record','global_claim','job_claim'} and owned_reservation['record'].get('schema')=='camera-install-runtime-metadata-reservation/1' and owned_reservation['record'].get('automatic_retry') is False,'Owned reservation schema differs')
        require(tuple(owned_reservation[key]['path'] for key in ('global_claim','job_claim'))==tuple(map(str,_claims(prepared))),'Owned claim paths differ')
        own={Path(owned_reservation[key]['path']) for key in ('global_claim','job_claim')}
        for key in ('global_claim','job_claim'):
            item=owned_reservation[key];raw=_path(item['path']).read_bytes()
            require(_hash(raw)==item['sha256'] and json.loads(raw)==owned_reservation['record'],'Reservation changed')
    for path in (*_claims(prepared),*(ROOT/'output'/n/(m['nonce']+'.json') for n in namespaces)):
        require(path in own or (not path.exists() and not path.is_symlink()),'Metadata job/nonce already consumed')
    for marker in ('host-entry-intent.json','module-attempt.json','upload-attempt.json'):
        require(not (d/marker).exists() and not (d/marker).is_symlink(),'Metadata attempt marker already present')
    return prepared


def _context(lease,journal,body_sha256,plan_sha256):
    identity=_held_lease(lease)
    require(isinstance(journal,InstallJournal),'Caller journal required')
    current=InstallJournal.open(journal.session_dir)
    require(current.events==journal.events and current.state in ('PLANNED','SD_STAGED')
        and current.binding==dict(body_sha256=body_sha256,plan_sha256=plan_sha256,model='ILCE-7M4'),'Current pre-RAM journal/body/plan required')
    assert_operation_allowed(journal,allowed_states=('PLANNED','SD_STAGED'))
    if journal.session_dir.parent.resolve()!=DEFAULT_SESSIONS.resolve():assert_operation_allowed(sessions_root=DEFAULT_SESSIONS)
    return dict(scope=PRE_SCOPE,lease_identity=identity,journal_event_sha256=current.events[-1]['event_sha256'],
        body_sha256=body_sha256,plan_sha256=plan_sha256,session_dir=str(journal.session_dir))


def reserve_assets(prepared,evidence,*,lease,journal,body_sha256,plan_sha256):
    return _reserve_assets(prepared,evidence,lambda:_context(lease,journal,body_sha256,plan_sha256))


def _reserve_assets(prepared,evidence,context_check):
    context=context_check()
    require(prepared.manifest['nonce'] not in context.get('prior_nonces',()),'Epoch nonce reuses prior job')
    require(preflight_assets(prepared.assets)==prepared,'Assets changed before reservation')
    folder=_path(evidence);require(folder.is_dir() and not any(folder.iterdir()),'Fresh empty evidence folder required')
    record=dict(schema='camera-install-runtime-metadata-reservation/1',asset_reference=prepared.reference,
        evidence=str(folder),context=context,automatic_retry=False)
    _path(CLAIMS);CLAIMS.mkdir(parents=True,exist_ok=True,mode=0o700)
    paths=_claims(prepared)
    for path in paths:
        require(context_check()==context,'Lease/history changed')
        durable_new(path,record)
    return dict(record=record,**{key:dict(path=str(path),sha256=_hash(path.read_bytes())) for key,path in zip(('global_claim','job_claim'),paths)})


def decode_frame(raw,*,nonce,loader_pid,phase,forensic_legacy=False):
    require(type(raw) is bytes and len(raw)==FRAME.size,'Complete native metadata frame required')
    magic,observed,*values,proc_sha,alias_sha=FRAME.unpack(raw)
    require((magic==MAGIC or (forensic_legacy is True and magic==LEGACY_MAGIC))
        and observed==bytes.fromhex(nonce),'Metadata frame identity differs')
    row=dict(zip(FIELDS,values))
    require(row['version']==(1 if magic==LEGACY_MAGIC else VERSION) and row['phase']==phase and row['error']==0 and row['euid']==0
        and 1<row['pid']<=0x7fffffff and row['ppid']==1 and row['loader_pid']==loader_pid
        and row['cleanup']==0 and row['pid']!=loader_pid,'Native lifecycle differs')
    require(row['flags']==(13 if phase==1 else 61),'Metadata lifecycle flags differ')
    if phase==1:require(row['proc_bytes']==row['alias_bytes']==0 and proc_sha==alias_sha==bytes(32),'Ready already contains data')
    else:require(0<row['proc_bytes']<=65536 and row['alias_bytes']==(1728 if magic==LEGACY_MAGIC else ALIAS_BYTES),'Bounded metadata sizes required')
    return row,proc_sha,alias_sha


def validate_receipt(receipt,*,reference,reservation,forensic_legacy=False):
    require(receipt['asset_reference']==reference and receipt['reservation']==reservation,'Receipt bindings differ')
    raw=receipt['raw_publications'];require(set(raw)=={'launch','ready','result'},'Full handshake required')
    loader=validate_launch(bytes.fromhex(raw['launch']),bytes.fromhex(reference['nonce']))
    ready,_,_=decode_frame(bytes.fromhex(raw['ready']),nonce=reference['nonce'],loader_pid=loader,phase=1,forensic_legacy=forensic_legacy)
    final,ps,als=decode_frame(bytes.fromhex(raw['result']),nonce=reference['nonce'],loader_pid=loader,phase=7,forensic_legacy=forensic_legacy)
    require(final['version']==ready['version'] and final['pid']==ready['pid'],'Worker changed')
    proc=bytes.fromhex(receipt['partitions_raw_hex']);aliases=bytes.fromhex(receipt['aliases_raw_hex'])
    require(len(proc)==final['proc_bytes'] and len(aliases)==final['alias_bytes'] and hashlib.sha256(proc).digest()==ps
        and hashlib.sha256(aliases).digest()==als,'Native payload hash/size differs')
    boot_id=None
    if final['version']==VERSION:
        boot=aliases[1728:]
        require(len(boot)==BOOT_ID_BYTES and boot[36:]==bytes(4) and BOOT_ID_PATTERN.fullmatch(boot[:36])
            and any(c!=ord('0') for c in boot[:36] if c!=ord('-')), 'Canonical nonzero boot UUID required')
        boot_id=boot[:36].decode('ascii')
    else:
        require(forensic_legacy is True and receipt.get('source_is_hardware') is False,
            'V1 metadata is forensic only and cannot declare hardware origin')
    rows=_partitions(proc);targets={};stats={}
    for index,number in enumerate(NUMBERS):
        n,length,mode,rdev,target,st=ALIAS.unpack_from(aliases,index*ALIAS.size)
        require(n==number and 0<length<128 and not any(target[length:]) and b'\0' not in target[:length], 'Alias bytes malformed')
        actual=target[:length].decode('ascii');name='nflasha'+str(number)
        require(actual in ('c'+name,'p'+name,'/dev/c'+name,'/dev/p'+name),'Unapproved actual alias target')
        canonical=actual if actual.startswith('/dev/') else '/dev/'+actual
        require(mode&0o170000==0o60000 and struct.unpack_from('<I',st,16)[0]==mode and struct.unpack_from('<Q',st,32)[0]==rdev,'Block stat ABI differs')
        major=((rdev>>8)&0xfff)|((rdev>>32)&0xfffff000);minor=(rdev&0xff)|((rdev>>12)&0xffffff00)
        require(canonical[5:] in rows and (rows[canonical[5:]]['major'],rows[canonical[5:]]['minor'])==(major,minor),'Observed alias rdev/proc differs')
        require('c'+name in rows and 'p'+name in rows and rows['c'+name]['bytes']==rows['p'+name]['bytes'],'cn/pn views missing or unequal')
        targets[name]=canonical;stats[name]=dict(raw_target_hex=target[:length].hex(),mode=mode,rdev=rdev,major=major,minor=minor)
    require(receipt.get('state')=='RUNTIME_METADATA_OBSERVED' and receipt.get('installation_authorized') is False
        and receipt.get('write_admission') is False and receipt.get('restoration_proven') is False,'Observation-only receipt required')
    return dict(alias_targets=targets,alias_stats=stats,boot_id=boot_id,metadata_version=final['version'],boot_epoch_available=boot_id is not None,partitions_sha256=_hash(proc),aliases_sha256=_hash(aliases),loader_pid=loader,
        source_is_hardware=False,write_admission=False,installation_authorized=False)


class MetadataChannel(BootstrapChannel):
    def __init__(self,device,nonce,clock=time.monotonic):
        super().__init__(device,nonce,clock);self.directory='/tmp_wbshd/m4irm_'+nonce.hex();self.started=False
    def _packet(self,*args,**kwargs):
        self.context_guard();return super()._packet(*args,**kwargs)
    def read(self,name,missing=False):
        require(name in LENGTHS,'Fixed final publication required');self._select(name)
        return self._packet(17,b'\0\xff\0',LENGTHS[name],missing)
    def start_once(self,evidence):
        require(not self.started,'START consumed');self.started=True;durable_new(Path(evidence)/'start-intent.json',dict(nonce=self.nonce.hex(),automatic_retry=False))
        self._select('start');require(self._packet(16,b'\0\xff\0'+START_FRAME.pack(START_MAGIC,self.nonce,VERSION),0)==b'','START response differs')


def _capture_metadata(device,evidence,*,assets,reservation,lease,journal,body_sha256,plan_sha256,context_check,
        metadata_read_authorized=False,source_is_hardware=False,channel_factory=None,clock=time.monotonic,sleep=time.sleep):
    require(metadata_read_authorized is True,'Explicit metadata read authorization required')
    require(channel_factory is None or callable(channel_factory),'Callable injected channel required')
    hardware=channel_factory is None
    if hardware:
        require(source_is_hardware is True and _path(lease.path)==_path(DEFAULT_LOCK)
            and _path(journal.session_dir.parent)==_path(DEFAULT_SESSIONS),'Default transport requires canonical real context')
    prepared=preflight_assets(assets,owned_reservation=reservation);folder=_path(evidence)
    record=reservation['record'];require(record['evidence']==str(folder),'Reservation evidence differs')
    def guard():
        require(context_check()==record['context'],'Reserved lease/history changed')
    guard();require(prepared.reference==record['asset_reference'],'Reserved assets differ')
    require(not any(folder.iterdir()),'Fresh evidence folder required')
    durable_new(folder/'execution-intent.json',dict(reservation=reservation,source_is_hardware=hardware,automatic_retry=False))
    channel=(MetadataChannel if hardware else channel_factory)(device,bytes.fromhex(prepared.manifest['nonce']),clock)
    channel.context_guard=guard
    stage='loader';raws={}
    def read(name,missing=False,save_as=None):
        guard();raw=channel.read(name,missing=missing)
        if raw is not None:durable_new(folder/((save_as or name).replace('.','-')+'-received.json'),dict(raw_hex=raw.hex(),bytes=len(raw)))
        return raw
    def poll(name):
        deadline=clock()+120
        for _ in range(1201):
            guard();failure=read('exec_failure',True)
            require(failure is None,'Native exec failure publication')
            raw=read(name,True)
            if raw is not None:return raw
            if name in ('launch','ready'):
                early=read('result',True,save_as='early-result-before-'+name)
                require(early is None,'Early native terminal before '+name)
            require(clock()<deadline,'Metadata deadline expired');sleep(.1)
        raise ValueError('Metadata poll bound exhausted')
    try:
        for name,pin in LIBRARIES.items():
            guard();require(_hash(channel.read_loader(name))==pin,'Loader library changed')
        guard();require(channel.read_loader(SLOT) is None,'Loader slot occupied')
        guard();require(preflight_assets(assets,owned_reservation=reservation)==prepared,'Assets changed before upload')
        stage='upload';channel.upload_once(prepared.module,assets.module_sha256,folder/'upload-attempt.json')
        stage='launch';raws['launch']=poll('launch');loader=validate_launch(raws['launch'],bytes.fromhex(prepared.manifest['nonce']))
        stage='ready';raws['ready']=poll('ready');decode_frame(raws['ready'],nonce=prepared.manifest['nonce'],loader_pid=loader,phase=1)
        require(read('result',True) is None,'Terminal present before START')
        stage='START';guard();channel.start_once(folder)
        stage='result';raws['result']=poll('result');decode_frame(raws['result'],nonce=prepared.manifest['nonce'],loader_pid=loader,phase=7)
        stage='payload';proc=read('partitions.bin');aliases=read('aliases.bin')
        receipt=dict(schema='camera-install-runtime-metadata-receipt/1',state='RUNTIME_METADATA_OBSERVED',asset_reference=prepared.reference,reservation=reservation,
            raw_publications={n:b.hex() for n,b in raws.items()},partitions_raw_hex=proc.hex(),aliases_raw_hex=aliases.hex(),
            source_is_hardware=hardware,installation_authorized=False,write_admission=False,restoration_proven=False,automatic_retry=False)
        guard();validate_receipt(receipt,reference=prepared.reference,reservation=reservation)
        durable_new(folder/'metadata-receipt.json',receipt);guard();return receipt
    except BaseException as error:
        channel.healthy=False
        durable_new(folder/'metadata-unknown.json',dict(stage=stage,error_type=type(error).__name__,automatic_retry=False,source_is_hardware=hardware))
        raise


def capture_authenticated(device,evidence,*,assets,reservation,lease,journal,body_sha256,plan_sha256,
        metadata_read_authorized=False,source_is_hardware=False,channel_factory=None,clock=time.monotonic,sleep=time.sleep):
    return _capture_metadata(device,evidence,assets=assets,reservation=reservation,lease=lease,journal=journal,
        body_sha256=body_sha256,plan_sha256=plan_sha256,metadata_read_authorized=metadata_read_authorized,
        source_is_hardware=source_is_hardware,channel_factory=channel_factory,clock=clock,sleep=sleep,
        context_check=lambda:_context(lease,journal,body_sha256,plan_sha256))


def _pending_epoch_sources(pending_reference,initial_runtime_reference,withdrawal_reference,*,binding,history,session_dir):
    from camera_install_receipts import validate_completed_pending,validate_completed_runtime
    from camera_install_card_withdraw import validate_withdrawal_receipt
    pending=validate_completed_pending(pending_reference,binding=binding,history=history,session_dir=session_dir)
    initial=validate_completed_runtime(initial_runtime_reference,binding=binding,history=history,session_dir=session_dir)
    withdrawal=validate_withdrawal_receipt(withdrawal_reference,binding=binding,history=history,session_dir=session_dir,
        pending_reference=pending_reference,stage_reference=withdrawal_stage_reference(withdrawal_reference))
    intents=[i for i,event in enumerate(history) if event['state']=='INSTALL_PATCH_MAY_BE_ACTIVE']
    require(len(intents)==1 and initial['ancestor_index']<intents[0]<pending['ancestor_index'],
            'Initial boot observation must precede the original patch intent')
    require(initial.get('metadata_version')==VERSION and isinstance(initial.get('boot_id'),str)
            and BOOT_ID_PATTERN.fullmatch(initial['boot_id'].encode('ascii')),
            'Original PRE_RAM metadata V2 boot UUID required')
    old=pending['receipt']['asset_reference']
    prior_nonces=[old['patch']['nonce'],*(old['captures'][name]['nonce'] for name in ('pre_app','pre_ufp')),
        initial['receipt']['asset_reference']['metadata']['nonce']]
    return dict(initial_boot_id=initial['boot_id'],prior_nonces=prior_nonces,sources_declared_hardware=all(
        value['source_is_hardware'] is True for value in (pending,initial,withdrawal)))


def withdrawal_stage_reference(withdrawal_reference):
    from camera_install_cancel import _json_reference
    return _json_reference(withdrawal_reference)[2]['stage_reference']


def _pending_epoch_context(lease,journal,body_sha256,plan_sha256,*,pending_reference,initial_runtime_reference,
        withdrawal_reference,operator_never_started_confirmed,summary):
    from camera_install_cancel import _json_reference
    require(operator_never_started_confirmed is True,'Explicit never-started-update confirmation required')
    identity=_held_lease(lease)
    require(isinstance(journal,InstallJournal),'Original pending journal required')
    current=InstallJournal.open(journal.session_dir)
    require(current.events==journal.events and current.state=='INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'
        and current.binding==dict(body_sha256=body_sha256,plan_sha256=plan_sha256,model='ILCE-7M4')
        and current.events[-1]['details'].get('install_patch_artifact')==pending_reference
        and not any(e['state']=='FLASH_MAY_HAVE_STARTED' for e in current.events),
        'Exact original pending no-FLASH context required')
    for reference in (pending_reference,initial_runtime_reference,withdrawal_reference):_json_reference(reference)
    assert_operation_allowed(journal,allowed_states=('INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT',))
    if journal.session_dir.parent.resolve()!=DEFAULT_SESSIONS.resolve():assert_operation_allowed(sessions_root=DEFAULT_SESSIONS)
    return dict(scope=EPOCH_SCOPE,lease_identity=identity,journal_event_sha256=current.events[-1]['event_sha256'],
        body_sha256=body_sha256,plan_sha256=plan_sha256,session_dir=str(journal.session_dir),
        pending_reference=pending_reference,initial_runtime_reference=initial_runtime_reference,
        withdrawal_reference=withdrawal_reference,operator_never_started_confirmed=True,**summary)


def reserve_pending_epoch_assets(prepared,evidence,*,lease,journal,body_sha256,plan_sha256,
        pending_reference,initial_runtime_reference,withdrawal_reference,operator_never_started_confirmed=False):
    """Reserve only the exact pending preparation's AP epoch observation."""
    require(operator_never_started_confirmed is True,'Explicit never-started-update confirmation required')
    summary=_pending_epoch_sources(pending_reference,initial_runtime_reference,withdrawal_reference,
        binding=journal.binding,history=journal.events,session_dir=journal.session_dir)
    return _reserve_assets(prepared,evidence,lambda:_pending_epoch_context(lease,journal,body_sha256,plan_sha256,
        pending_reference=pending_reference,initial_runtime_reference=initial_runtime_reference,
        withdrawal_reference=withdrawal_reference,operator_never_started_confirmed=True,summary=summary))


def capture_pending_epoch_authenticated(device,evidence,*,assets,reservation,lease,journal,body_sha256,plan_sha256,
        pending_reference,initial_runtime_reference,withdrawal_reference,operator_never_started_confirmed=False,
        metadata_read_authorized=False,source_is_hardware=False,channel_factory=None,clock=time.monotonic,sleep=time.sleep):
    """Read fixed metadata while pending; never inspect original PIDs or reboot."""
    require(operator_never_started_confirmed is True,'Explicit never-started-update confirmation required')
    summary=_pending_epoch_sources(pending_reference,initial_runtime_reference,withdrawal_reference,
        binding=journal.binding,history=journal.events,session_dir=journal.session_dir)
    require(channel_factory is not None or summary['sources_declared_hardware'] is True,
            'Default epoch collection requires trusted original runtime, pending and withdrawal sources')
    return _capture_metadata(device,evidence,assets=assets,reservation=reservation,lease=lease,journal=journal,
        body_sha256=body_sha256,plan_sha256=plan_sha256,metadata_read_authorized=metadata_read_authorized,
        source_is_hardware=source_is_hardware,channel_factory=channel_factory,clock=clock,sleep=sleep,
        context_check=lambda:_pending_epoch_context(lease,journal,body_sha256,plan_sha256,
            pending_reference=pending_reference,initial_runtime_reference=initial_runtime_reference,
            withdrawal_reference=withdrawal_reference,operator_never_started_confirmed=True,summary=summary))
