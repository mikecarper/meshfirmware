export const rakVersion='v1.18.0.2-halo-keymind-cascade-dev-a723af94';
export const rakHardware='RAK WisBlock / WisMesh (RAK 4631)';
export const rakUnified='RAK_4631_repeater_unified_lora_ota';
export const rakLegacy='RAK_4631_repeater_bridge_rs232_serial1_lora_ota_no_external_sensors';

// The seven exact release targets shown in the reported 14-choice dropdown.
export function rakCatalogItems() {
  const targets=[rakLegacy,
    'RAK_4631_repeater_bridge_rs232_serial2_lora_ota_no_external_sensors',
    'RAK_4631_repeater_ethernet',
    'RAK_4631_repeater_lora_ota_no_external_sensors',
    'RAK_4631_repeater_rak15001_slot_c_lora_ota',rakUnified,
    'RAK_4631_repeater_w25q16_lora_ota'];
  return targets.flatMap(target=>['full','reduced'].map(sensors=>{
    const name=`${target}-${sensors}-ota-${rakVersion}.zip`;
    return {project:'MeshCore',provider:'Keymind Cascade',hardware:rakHardware,
      architecture:'nrf52',role:'repeater',action:'flash',version:rakVersion,
      title:'Repeater',subtitle:`${target}-${sensors}-ota`,name,
      url:`https://github.com/mikecarper/MeshCore/releases/download/lora-ota-2-${rakVersion}/${name}`,
      releaseNotes:`EXACT TARGET - ${target}. Match the exact build.`};
  }));
}
