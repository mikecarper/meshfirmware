// Presentation only: callers validate/seal archives before displaying coverage.
// Never copy archived values, raw replies or arbitrary error text into the UI.
import { commonCliReplyState } from './common-cli.js';

const commands={
  'get public.key':['identity_public_key','Public identity'],
  'get prv.key':['identity_private_key','Private identity'],
  'get name':['name','Node name'],'get radio':['radio','Primary radio settings'],
  'get lat':['lat','Latitude'],'get lon':['lon','Longitude'],'get tx':['tx','TX power'],
  'get repeat':['repeat','Repeating'],'get rxdelay':['rxdelay','RX delay'],
  'get txdelay':['txdelay','TX delay'],'get af':['af','Airtime factor'],
  'get multi.acks':['multi_acks','Multiple acknowledgements'],
  'get advert.interval':['advert_interval','Local advertisement interval'],
  'get flood.advert.interval':['flood_advert_interval','Flood advertisement interval'],
  'get flood.max':['flood_max','Flood hop limit'],
  'get flood.max.advert':['flood_max_advert','Advertisement flood hop limit'],
  'get flood.max.unscoped':['flood_max_unscoped','Unscoped flood hop limit'],
  'get flood.channel.data':['flood_channel_data','Flood channel-data policy'],
  'get allow.read.only':['allow_read_only','Read-only access'],
  'get telemetry.access':['telemetry_access','Telemetry access'],
  'get radio2':['radio2','Secondary radio settings'],
  'get radio2.cross':['radio2_cross','Radio crossing'],
  'get cad':['cad','Channel activity detection'],
  'get radio.cad':['radio_cad','Radio CAD timings'],
  'get radio.rxgain':['radio_rxgain','RX gain'],
  'get radio.fem.rxgain':['radio_fem_rxgain','Front-end RX gain'],
  'get radio.fem.txgain':['radio_fem_txgain','Front-end TX gain'],
  'get radio.rxps.config':['radio_rxps','RX power-saving configuration'],
  'get radio.rxps.rfrx_disabled':['radio_rxps_rfrx_disabled','RX power-saving RF switch policy'],
  'get bluetooth':['bluetooth_status','Bluetooth state'],
  'get bluetooth.name':['bluetooth_name','Bluetooth name'],
  'get display.rotation':['display_rotation','Display rotation'],
  'get powersaving':['power_saving','Power saving'],
  'get usb.logging':['usb_logging','USB logging preference'],
  'get usb.logging.always':['usb_logging_always','Always-on USB logging preference'],
  'get usb.debug':['usb_debug','USB debug preference'],
  'get system.watchdog':['system_watchdog','System watchdog setting'],
  'get password':['password','Administrator password'],
  'get guest.password':['guest_password','Guest password'],
  'get wifi.ssid':['wifi_ssid','Wi-Fi network name'],
  'get wifi.pwd':['wifi_password','Wi-Fi password'],
  'get acl':['acl','Access permissions'],
  'get storage.layout':['storage_layout','Storage-layout information'],
  ver:['firmware_version','Firmware version information'],
  version:['firmware_version','Firmware version information'],
  board:['board','Board information'],'get role':['role','Node role information'],
};
const sections={
  identity_public_key:['identity_public_key','Public identity'],
  identity_private_key:['identity_private_key','Private identity'],
  identity_stability:['identity_stability','Identity stability check'],
  self_info:['self_info','Core node settings'],device_info:['device_info','Firmware and device information'],
  settings:['settings','Core node settings'],contacts:['contacts','Contacts'],channels:['channels','Channels and channel secrets'],
  autoadd:['autoadd','Automatic contact-add preferences'],tuning:['tuning','Radio tuning'],
  default_flood_scope:['default_flood_scope','Default flood scope'],custom_vars:['custom_vars','Custom preferences'],
  battery_and_storage:['battery_and_storage','Battery and storage information'],
  regions:['regions','Region hierarchy, flood permissions, home and default scope'],
};
for(const value of Object.values(commands))sections[value[0]]=value;
const visibleStates=new Set(['complete','unsupported','error','disabled','not_applicable']);
const baseline=[
  {label:'Firmware and bootloader files',reason:'This JSON stores settings, not firmware images.'},
  {label:'Stored messages',reason:'The message queue is not read or consumed.'},
  {label:'Runtime logs',reason:'Logs are not exported.'},
];
const reasonFor=state=>state==='error'?'The read failed; no value was saved.':state==='disabled'?'Export is disabled by the firmware.':'The firmware does not expose this value.';
const replyText=value=>typeof value==='string'?value:value&&typeof value==='object'?(typeof value.text==='string'?value.text:typeof value.raw==='string'?value.raw:null):null;
const lookup=(map,key)=>Object.hasOwn(map,key)?map[key]:null;

export function backupCoverage(archive,nativeArchive=null){
  const native=nativeArchive?.payload?.sections?nativeArchive.payload:archive?.payload?.sections?archive.payload:null;
  const payload=archive?.payload?.sections?{}:archive?.payload||{};
  const common=payload.role==='common-cli'||native?.source?.capture_api==='meshcore-cli-common-cli';
  const companion=payload.role==='companion'||native?.source?.capture_api==='companion-api';
  const records=new Map();let specificSettingsMissing=false;
  const add=(descriptor,state,priority=1,reason=null)=>{
    if(!descriptor||!visibleStates.has(state))return;
    const [id,label]=descriptor,old=records.get(id);if(old&&old.priority>priority)return;
    if(old?.priority===priority&&old.state==='error'&&state!=='error')return;
    if(old?.priority===priority&&['unsupported','disabled'].includes(old.state)&&state==='complete')return;
    records.set(id,{label,state,priority,reason:reason||reasonFor(state)});
  };
  const query=(command,value,priority=1,explicitState=null)=>{
    const descriptor=lookup(commands,command);if(!descriptor)return;
    let state=explicitState;
    if(!state){const raw=replyText(value);state=value&&typeof value==='object'&&value.ok===false?'error':raw===null?'error':commonCliReplyState(raw,command).state;}
    add(descriptor,state,priority);
  };
  if(payload.publicKey)add(sections.identity_public_key,'complete');
  if(common){
    for(const [command,value]of Object.entries(payload.replies||{}))if(command!=='region')query(command,value);
    if(!Object.hasOwn(payload.replies||{},'get prv.key'))add(sections.identity_private_key,'unsupported');
  }
  if(companion){
    add(sections.identity_private_key,payload.privateKey?'complete':'unsupported');
    if(payload.self)add(sections.self_info,'complete');if(payload.info)add(sections.device_info,'complete');
    for(const field of ['contacts','channels'])if(Array.isArray(payload[field]))add(sections[field],'complete');
    for(const [field,key]of [['autoadd','autoadd'],['tuning','tuning'],['custom_vars','custom'],['default_flood_scope','scope']])if(Object.hasOwn(payload.options||{},key))add(sections[field],typeof payload.options[key]==='string'?'complete':'unsupported');
    for(const [command,value]of Object.entries(payload.cli||{})){
      if(command==='get bluetooth.name'&&value&&typeof value==='object'&&typeof value.name==='string'&&typeof value.default==='boolean')add(commands[command],'complete');else query(command,value);
    }
    if(payload.batteryAndStorage)add(sections.battery_and_storage,payload.batteryAndStorage.unavailable?'error':'complete');
  }
  if(common||payload.regions){
    const record=payload.regions;add(sections.regions,record?.state==='complete'?'complete':record?.state==='error'?'error':'unsupported',2);
  }
  for(const [id,section]of Object.entries(native?.sections||{})){
    if(!section||typeof section!=='object')continue;
    if(id==='settings'){
      const states=section.query_states||{},specific=Object.entries(states).some(([command,value])=>lookup(commands,command)&&value?.state&&value.state!=='complete');specificSettingsMissing=specific;
      for(const [command,value]of Object.entries(section.data||{}))query(command,value,2);
      for(const [command,value]of Object.entries(states))query(command,null,3,value?.state);
      if(!specific&&section.state!=='complete')add(sections.settings,section.state,3);
      continue;
    }
    const descriptor=lookup(commands,section.command)||lookup(sections,id);add(descriptor,section.state,3);
  }
  for(const id of native?.completeness?.missing_required||[]){if(id!=='settings'||!specificSettingsMissing){const descriptor=lookup(sections,id),existing=descriptor&&records.get(descriptor[0]);add(descriptor,existing&&existing.state!=='complete'?existing.state:'unsupported',4);}}
  for(const id of native?.completeness?.optional_errors||[])add(lookup(sections,id),'error',4);
  const regionRecord=native?.sections?.regions||payload.regions,region=records.get('regions');
  if(region&&region.state!=='complete'&&region.state!=='not_applicable'&&region.state!=='disabled'){
    const reason=typeof regionRecord?.reason==='string'?regionRecord.reason:'';
    if(/private|transport keys?/i.test(reason)){
      add(['private_region_keys','Private-region transport keys'],'unsupported',4,'The firmware does not export these keys.');
      add(sections.regions,region.state,4,'A region map containing private-key regions cannot be exported for restore.');
    }else if(/truncat|160.byte|159.byte|buffer|saturat/i.test(reason))add(sections.regions,region.state,4,'The firmware export limit prevented capture of the full region map.');
    else if(region.state!=='error')add(sections.regions,'unsupported',4,'Tree, home and default-scope data were not all captured.');
  }
  const included=[],notIncluded=baseline.map(item=>({...item})),failed=[];
  for(const value of records.values()){
    if(value.state==='complete'){included.push(value.label);continue;}
    if(value.state==='not_applicable')continue;
    const item={label:value.label,reason:value.reason};notIncluded.push(item);if(value.state==='error')failed.push({...item});
  }
  if(native?.excluded?.unexposed_preferences)notIncluded.push({label:'Preferences without an export command',reason:'Only values exposed by the connected firmware can be captured.'});
  const ordinaryExclusions=new Set([...baseline.map(item=>item.label),'Preferences without an export command']);
  const display=item=>{
    if(ordinaryExclusions.has(item.label))return item.label;
    const reason=item.reason==='The firmware does not expose this value.'?'not supported by firmware':item.reason==='The read failed; no value was saved.'?'read failed; no value saved':item.reason==='Export is disabled by the firmware.'?'export disabled by firmware':item.reason==='Tree, home and default-scope data were not all captured.'?'saved tree/home/default data unavailable':item.reason.replace(/\.$/,'');
    return `${item.label} (${reason})`;
  };
  return {included,notIncluded,failed,
    notIncludedText:'Not backed up: '+notIncluded.map(display).join('; '),
    summaryText:included.length?'Captured values are saved in the JSON.':'No configuration values were captured.'};
}
