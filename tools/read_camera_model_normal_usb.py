"""Normal Sony MSC inquiry/model read only. No updater/service/module actions."""
from pathlib import Path
import argparse,contextlib,datetime,io,json,os,sys
R=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(mode=0o700,parents=False,exist_ok=False)
 report={'scope':'Normal MSC inquiry and existing model getter only','time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'service_mode_entered':False,'updater_initialized':False,'code_uploaded':False,'DMA_submitted':False,'NOR_requests':0,'settings_writes':0,'firmware_writes':0,'model_getter_invocations':0}
 try:
  sys.path.insert(0,str(R/'Sony-PMCA-RE'))
  with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
   from pmca.commands.usb import importDriver,listDevices
   from pmca.usb.sony import SonyMscExtCmdDevice,SonyExtCmdCamera
   with importDriver('libusb') as driver:
    devices=list(listDevices(driver,quiet=True));report['sony_devices_seen']=len(devices)
    if len(devices)!=1 or not isinstance(devices[0],SonyMscExtCmdDevice):raise RuntimeError('Require exactly one normal Sony MSC camera')
    report['model_getter_invocations']=1;info=SonyExtCmdCamera(devices[0]).getCameraInfo();report['model']=info.modelName
    if info.modelName!='ILCE-7M4':raise RuntimeError('Unexpected model')
    report['state']='NORMAL_MSC_MODEL_READ_VERIFIED'
 except Exception as e:
  report['state']='READ_NOT_VERIFIED';report['error_type']=type(e).__name__;report['error_message_private']=str(e)
 finally:
  path=out/'report.json';path.write_text(json.dumps(report,indent=2)+'\n');path.chmod(0o600)
  if os.geteuid()==0 and os.environ.get('SUDO_UID') and os.environ.get('SUDO_GID'):
   uid,gid=int(os.environ['SUDO_UID']),int(os.environ['SUDO_GID']);os.chown(path,uid,gid);os.chown(out,uid,gid)
 print(json.dumps({k:v for k,v in report.items() if k!='error_message_private'}))
 if report['state']!='NORMAL_MSC_MODEL_READ_VERIFIED':raise SystemExit(1)
if __name__=='__main__':main()
