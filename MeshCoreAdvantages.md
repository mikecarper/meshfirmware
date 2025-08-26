


# Technical overview on why MeshCore works better than the other LoRa networks in North America.

## Center Frequency Selection
https://github.com/meshtastic/firmware/blob/master/src/DisplayFormatters.cpp The hash of this gets you the frequency slot

How the slot will be picked; take a hash of the name, mod operation on that number, given the number of channels the that are available given the operating frequency range.
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
This is picking the widest bandwidth possible for the presets. The wider the bandwidth the easier it is to encounter noise. In North America there are peaks every 200khz, so almost every preset will have noise. 
![sdr](https://github.com/user-attachments/assets/a916f9fe-f783-45e6-ae25-7670e844592c)

Picking a narrow bandwidth and adjusting the spreading factor to get desired the kbps is the better way forward. Smaller bandwidths like 62.5khz means you can fit in between the noise. 
<img width="1100" height="668" alt="image" src="https://github.com/user-attachments/assets/3b32cb25-2475-46b6-8486-f117d964b461" />
MeshCore recommended settings use 62.5khz as the bandwidth

## Coding Rate
https://meshtastic.org/docs/configuration/radio/lora/#coding-rate  
This is a black box;. not a lot of information is given. All we can see is that for the slower long presets this gets changed to 4/8.

With MeshCore it's recommended to keep this at 4/5; but if you have a portable node like the t1000e you can change this to 4/8 and it's 100% compatible with the 4/5 network; they will be able to talk to each other with different coding rates. 

## Routers/Repeaters & Hops
https://meshtastic.org/blog/choosing-the-right-device-role/#router-and-repeater  
The network is not designed to handle a dense network of routers/repeaters. It only works with a small number of routers/repeaters. https://www.youtube.com/watch?v=htjwtnjQkkE&pp  

Having lots of routers/repeaters will cause issues with your 3 hops disappearing. 
https://meshtastic.org/docs/configuration/tips/#hop-count  
https://meshtastic.org/docs/software/meshtasticator/#simulation-insights  

MeshCore takes a different approach, the max hop count is 64 and putting repeaters on your rooftop is encouraged. You can manually change the tx delay factor if issues arise with too many repeaters in an area. 

## Telemetry
https://meshtastic.org/docs/configuration/module/telemetry/  
By looking at MQTT we've discovered that over 50% of the data is automated telemetry packets. This eats up channel usage and because the network is always busy it makes it more unreliable as you add in more nodes once you hit a tipping point. 

MeshCore uses a pull model where you can pull data from a remote node by request. Usually a human is required to have packets go over the network. 
