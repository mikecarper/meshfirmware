// Reviewed USB CLI shortcuts, not a command template or arbitrary command batch.
// Sources: MeshCore CommonCLI.cpp, WirelessControl.h and companion MyMesh.cpp.
// The caller owns application/role checks, consent, serialization and redaction.
const encoder = new TextEncoder();
const unsafeText = /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u;
const unsafeName = /[\[\]\/\\:,?*]/u;
const plan = (commands, label, options = {}) => ({commands, secret:false, label, ...options});

function text(value, label, max, {empty=false}={}) {
  // Do not echo invalid input: it may be a password or contain terminal escapes.
  if(typeof value !== 'string' || unsafeText.test(value))throw new Error(`${label} must be a single line without control or invisible characters.`);
  if((!empty && !value.trim()) || encoder.encode(value).length > max)throw new Error(`${label} must be ${empty?'0':'1'}–${max} UTF-8 bytes.`);
  return value;
}

// Full Companion serves /update on 8080; infrastructure normally uses 80.
// Show only the structured endpoint, never the surrounding firmware reply.
export function quickHotspotUrl(reply) {
  const match=/^Started:\s+(http:\/\/((?:\d{1,3}\.){3}\d{1,3})(?::(?:80|8080))?\/update)(?=[;\s]|$)/i.exec(reply);
  if(!match||match[2].split('.').some(octet=>Number(octet)>255||String(Number(octet))!==octet)||match[2]==='0.0.0.0')throw new Error('The hotspot did not report a recognized update address.');
  const url=new URL(match[1]);
  if(url.protocol!=='http:'||url.hostname!==match[2]||url.pathname!=='/update'||url.username||url.password||url.search||url.hash||!['','80','8080'].includes(url.port))throw new Error('The hotspot did not report a recognized update address.');
  return url.href;
}

export function quickSettingPlan(action, values={}) {
  if(!values || typeof values !== 'object' || Array.isArray(values))throw new Error('Invalid quick-setting values.');
  switch(action) {
    case 'logging-on':
      return plan(['set usb.logging on'], 'USB logging on', {warning:'USB logging can make the serial console noisy and switch a Companion from binary to text mode.'});
    case 'logging-off':
      return plan(['set usb.logging off'], 'USB logging off');
    case 'wifi-status':
      return plan(['get wifi.status'], 'Wi-Fi status');
    case 'wifi-on':
    case 'wifi-off': {
      // Infrastructure's wireless switch applies to this boot and never forces
      // a management lockout. Companion enablement is a saved preference.
      const enabled=action==='wifi-on', companion=values.role==='companion';
      return plan([companion?`set wifi.enabled ${enabled?1:0}`:`set wifi ${enabled?'on':'off'}`],
        `Wi-Fi ${enabled?'on':'off'}`, {disconnects:true, warning:companion
          ? 'Saves Wi-Fi enablement. Some boards require a manual reboot; wireless connections may change.'
          : 'Changes Wi-Fi for this boot only. Active Wi-Fi services may stop or reconnect; no forced shutdown is used.'});
    }
    case 'wifi-ota-ap':
      // IMPORTANT: main UI must restrict this action to an identified ESP32.
      // On nRF52, start ota instead enters Bluetooth DFU.
      return plan(['start ota ap'], 'Start Wi-Fi update hotspot', {disconnects:true,
        warning:'Starts the firmware-upload hotspot and may interrupt Wi-Fi, MQTT or ESP-NOW. Keep USB connected.'});
    case 'name': {
      const name=text(values.name,'Name',31);
      if(unsafeName.test(name))throw new Error('Name cannot contain [ ] / \\ : , ? or *.');
      return plan([`set name ${name}`], 'Save node name');
    }
    case 'password': {
      const password=text(values.password,'Admin password',15);
      return plan([`password ${password}`], 'Save admin password', {secret:true,
        warning:'Changes the admin password. Existing management sessions may need to sign in again; use 8–15 printable ASCII characters to also use it for a Wi-Fi hotspot.'});
    }
    case 'wifi-save': {
      const ssid=text(values.ssid,'Wi-Fi name',31);
      const password=text(values.password??'','Wi-Fi password',63,{empty:true});
      if(values.openNetwork!==undefined && typeof values.openNetwork!=='boolean')throw new Error('Open-network choice must be explicit.');
      if(values.openNetwork && password)throw new Error('An open network cannot also have a Wi-Fi password.');
      // A blank password is not an instruction to erase the saved secret.
      // A separate explicit choice is required to select an open network.
      const commands=[...(password?[`set wifi.pwd ${password}`]:values.openNetwork?['set wifi.pwd']:[]),`set wifi.ssid ${ssid}`];
      return plan(commands, 'Save Wi-Fi network', {secret:true,disconnects:true,
        warning:(values.openNetwork?'An open Wi-Fi network was explicitly selected. ':!password?'The saved Wi-Fi password is unchanged. ':'')
          +'Running Wi-Fi or MQTT may reconnect after these separate saves. This does not enable a disabled Wi-Fi service.'});
    }
    default:
      throw new Error('Choose a supported quick setting.');
  }
}
