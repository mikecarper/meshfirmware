# This is technincal overview on why MeshCore works better than the other LoRa networks in North America.

## Center Frequency Selection
https://github.com/meshtastic/firmware/blob/master/src/DisplayFormatters.cpp The hash of this gets you the freqency slot

How the slot will be picked; take a hash of the name, mod operation on that number, given the number of channels the that are avilable given the operating freqency range.
```
function SLOT_FROM_PRESET(name, numChannels){
  // normalize input
  name = String(name || '').replace(/\s+/g, ''); // remove spaces
  name = name.replace(/Moderate/gi, 'Mod');      // truncate "Moderate" -> "Mod"

  numChannels = Number(numChannels);
  if (!isFinite(numChannels) || numChannels <= 0) return NaN;

  // djb2 with uint32 wrap
  var h = 5381 >>> 0;
  for (var i = 0; i < name.length; i++){
    h = (((h << 5) + h) + name.charCodeAt(i)) >>> 0; // h*33 + c
  }
  return (h % numChannels) + 1;  // 1-based slot
}
```
LongFast is slot 20 (906.8750) because of the name and the bandwidth. It was not planned out. 

## Bandwidth Selection & Spreading Factor
https://meshtastic.org/docs/overview/radio-settings/#presets

This is picking the widest bandwidth possible for the presets. The wider the bandwidth the easier it is to encounter noise. In north america there are peaks every 200khz, so almost every preset will have noise. 
![sdr](https://github.com/user-attachments/assets/a916f9fe-f783-45e6-ae25-7670e844592c)

Picking a narrow bandwidth and adjusting the spreading factor to get desired the kbps is the better way forward. Smaller bandwidths like 62.5khz means you can fit inbetween the noise. 
<img width="1100" height="668" alt="image" src="https://github.com/user-attachments/assets/3b32cb25-2475-46b6-8486-f117d964b461" />
MeshCore recommended settings use 62.5khz as the bandwidth
