// Structural UI contracts only. No browser, network or hardware access.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const html=await readFile(new URL('../index.html',import.meta.url),'utf8');
const css=await readFile(new URL('../src/style.css',import.meta.url),'utf8');
// A small tag stack is enough for this static document and avoids adding a
// browser/DOM dependency. Quoted > characters do not terminate opening tags.
function parseDocument(source){
  const root={tag:'#document',attrs:{},parent:null,children:[]},stack=[root],nodes=[],byId=new Map();
  const voids=new Set(['area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr']);
  for(let offset=0;offset<source.length;){
    const start=source.indexOf('<',offset);if(start<0)break;
    if(source.startsWith('<!--',start)){const end=source.indexOf('-->',start+4);assert.notEqual(end,-1,'Unclosed HTML comment');offset=end+3;continue;}
    let end=start+1,quote='';
    for(;end<source.length;end++){const char=source[end];if(quote){if(char===quote)quote='';}else if(char==='"'||char==="'")quote=char;else if(char==='>')break;}
    assert.ok(end<source.length,'Unclosed HTML tag');offset=end+1;
    const token=source.slice(start,offset),match=/^<\s*(\/)?\s*([A-Za-z][\w:-]*)\b([\s\S]*?)>$/.exec(token);if(!match)continue;
    const tag=match[2].toLowerCase();
    if(match[1]){const index=stack.findLastIndex(node=>node.tag===tag);assert.ok(index>0,`Unexpected closing ${tag}`);stack.length=index;continue;}
    const attrs={};for(const attribute of match[3].matchAll(/([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g))attrs[attribute[1].toLowerCase()]=attribute[2]??attribute[3]??attribute[4]??'';
    const node={tag,attrs,parent:stack.at(-1),children:[],start};node.parent.children.push(node);nodes.push(node);
    if(attrs.id){assert.ok(!byId.has(attrs.id),`Duplicate id ${attrs.id}`);byId.set(attrs.id,node);}
    if(!voids.has(tag)&&!token.endsWith('/>'))stack.push(node);
  }
  return {root,nodes,byId};
}
const {nodes,byId}=parseDocument(html),has=(node,attribute)=>Object.hasOwn(node.attrs,attribute);
const get=id=>{const node=byId.get(id);assert.ok(node,`Missing #${id}`);return node;};
const ancestors=node=>{const result=[];for(let parent=node.parent;parent;parent=parent.parent)result.push(parent);return result;};
const inside=(node,parent)=>ancestors(node).includes(parent);
const closedAncestors=node=>ancestors(node).filter(parent=>parent.tag==='details'&&!has(parent,'open'));
const hasClass=(node,name)=>(node.attrs.class||'').split(/\s+/).includes(name);

test('USB selection is the first initially visible main-page control in the compact header',()=>{
  const header=get('flasher'),button=get('select-port'),main=nodes.find(node=>node.tag==='main');
  assert.equal(header.tag,'header');assert.ok(hasClass(header,'page-header'));assert.ok(inside(button,header));
  const controls=nodes.filter(node=>inside(node,main)&&['button','select','input','textarea'].includes(node.tag)&&node.attrs.type!=='hidden'&&!has(node,'hidden')&&!ancestors(node).some(parent=>has(parent,'hidden'))&&closedAncestors(node).length===0);
  assert.equal(controls[0],button);assert.equal(closedAncestors(button).length,0);
  assert.ok(!nodes.some(node=>hasClass(node,'hero')),'Large introductory hero must not precede the controls');
});

test('flashing another device is the primary action before optional reconnect, hidden until startup verification is pending',()=>{
  const button=get('start-new-radio'),select=get('select-port'),hint=get('new-radio-hint');
  assert.equal(button.tag,'button');assert.equal(button.attrs.type,'button');assert.equal(button.parent,select.parent);
  assert.ok(button.start<select.start&&select.start<get('browser-status').start);assert.equal(closedAncestors(button).length,0);
  for(const attribute of ['hidden','disabled','data-lock'])assert.ok(has(button,attribute));
  assert.ok(hasClass(button,'primary'));assert.ok(!hasClass(button,'secondary'));assert.ok(!hasClass(button,'step-button'));assert.ok(!button.children.some(node=>hasClass(node,'action-number')));
  assert.equal(button.attrs['aria-describedby'],hint.attrs.id);assert.ok(has(hint,'hidden'));assert.ok(inside(hint,get('flasher')));
  assert.match(html.slice(button.start).split('</button>')[0],/>Flash a new device$/);assert.match(html.slice(hint.start).split('</p>')[0],/Flash another device, or optionally verify the previous radio’s startup\./);
});

test('essential firmware inputs and both write-stage buttons stay at the top without opening extras',()=>{
  const workflow=nodes.find(node=>hasClass(node,'workflow')),choices=get('firmware-choices'),advanced=get('advanced-options');
  assert.ok(workflow,'Missing compact workflow card');assert.ok(hasClass(workflow,'card'));
  assert.equal(choices.tag,'details');assert.ok(has(choices,'open'));assert.ok(hasClass(choices,'primary-inputs'));
  for(const id of ['provider','hardware','role','version','artifact','prepare','flash']){
    const node=get(id);assert.ok(inside(node,workflow),`#${id} must stay in the top workflow`);assert.equal(closedAncestors(node).length,0,`#${id} cannot require an advanced panel`);assert.ok(node.start<advanced.start,`#${id} must precede extras`);
  }
  assert.ok(has(get('flash'),'disabled'),'Initial page must never offer an unprepared flash');
});

test('firmware file browsing and the selected build download sit beside the main firmware selector',()=>{
  const field=get('artifact-field'),browse=get('firmware-files'),download=get('download-selected-build'),choices=get('firmware-choices');
  const row=browse.parent;assert.ok(hasClass(row,'firmware-file-links'));assert.equal(download.parent,row);assert.ok(inside(row,field));assert.ok(inside(row,choices));
  assert.equal(closedAncestors(browse).length,0,'Browsing public files must not require opening an advanced panel');
  assert.ok(browse.start>get('artifact-choice-hint').start&&browse.start<get('prepare').start,'File links should follow the selector before numbered preparation');
  assert.equal(browse.tag,'a');assert.equal(download.tag,'a');assert.ok(!has(browse,'hidden'));assert.ok(has(download,'hidden'),'No exact file can be downloaded before one is selected');assert.ok(!has(download,'href'));
  const destination=new URL(browse.attrs.href);assert.equal(destination.href,'https://mikecarper.github.io/MeshCore/firmware_picker/#firmware-picker-1-results');assert.equal(destination.search,'','The initial public link must not contain device data');
  for(const link of [browse,download]){assert.equal(link.attrs.target,'_blank');assert.deepEqual(link.attrs.rel.split(/\s+/).sort(),['noopener','noreferrer']);assert.ok(hasClass(link,'text-link'));assert.ok(!hasClass(link,'step-button'));assert.ok(!has(link,'data-lock'),'Public browsing must not be gated by USB access');assert.ok(!link.children.some(node=>hasClass(node,'action-number')));}
  assert.match(html.slice(browse.start).split('</a>')[0],/>Firmware files ↗$/);assert.match(html.slice(download.start).split('</a>')[0],/>Download selected build ↗$/);
  assert.ok(inside(get('download-firmware'),get('image-details')),'The existing fallback download must remain in image details');
});

test('advanced, backup, console and capability controls are collapsed by default',()=>{
  for(const id of ['advanced-options','backups','console','capabilities']){const node=get(id);assert.equal(node.tag,'details',id);assert.ok(!has(node,'open'),`#${id} must start collapsed`);}
  for(const id of ['connection-options','custom-firmware','bootloader-options','nrf-actions','migration-options','verification-options','esp-retry-options','image-details']){
    const node=get(id);assert.equal(node.tag,'details',id);assert.ok(!has(node,'open'),id);assert.ok(inside(node,get('advanced-options')),`#${id} belongs under extras`);
  }
  for(const id of ['auto-detect-board','auto-backup','auto-finish'])assert.ok(has(get(id),'checked'),`Collapsing #${id} must not change its safe default`);
});

test('skipping backup is an explicit visible unchecked choice before the review actions',()=>{
  const option=get('skip-backup-option'),choice=get('skip-backup'),warning=get('skip-backup-warning'),workflow=nodes.find(node=>hasClass(node,'workflow'));
  const actions=nodes.find(node=>hasClass(node,'review-actions')),label=choice.parent;
  assert.equal(option.tag,'div');assert.ok(hasClass(option,'skip-backup-option'));assert.ok(inside(option,workflow));assert.equal(closedAncestors(option).length,0);
  assert.equal(choice.tag,'input');assert.equal(choice.attrs.type,'checkbox');assert.ok(!has(choice,'checked'),'Backing up remains the default');assert.ok(has(choice,'data-lock'),'An active USB operation must lock the skip choice');
  assert.equal(label.tag,'label');assert.ok(inside(choice,option));assert.match(html.slice(label.start).split('</label>')[0],/Skip backup · go straight to step 4/);
  assert.equal(choice.attrs['aria-describedby'],warning.attrs.id);assert.ok(option.start>get('expert-fields').start&&option.start<actions.start,'The deliberate skip choice belongs beside the main flash workflow');
  assert.ok(!nodes.some(node=>inside(node,option)&&hasClass(node,'action-number')),'Skipping backup must not create another numbered step');
});

test('the skip-backup warning is accessible, conditional and does not claim device checks are skipped',()=>{
  const option=get('skip-backup-option'),warning=get('skip-backup-warning');
  assert.equal(warning.tag,'p');assert.ok(has(warning,'hidden'));assert.ok(inside(warning,option));assert.equal(closedAncestors(warning).length,0);assert.equal(warning.attrs.role,'status');assert.equal(warning.attrs['aria-live'],'polite');
  const text=html.slice(warning.start).split('</p>')[0];assert.match(text,/No backup will be created/);assert.match(text,/Firmware and device checks still run before the final flash confirmation/);
  assert.ok(declarationsFor('.skip-backup-option label').some(rule=>rule.display==='flex'&&rule['justify-content']==='flex-start'),'The opt-out remains left aligned');
  assert.ok(declarationsFor('.skip-backup-option.enabled').some(rule=>rule.background&&rule['border-color']),'The active opt-out needs an explicit warning treatment');
});

test('status, warnings, progress and required expert offsets cannot be trapped in closed extras',()=>{
  for(const id of ['notice','automatic-summary','image-warning','progress','progress-label','expert-fields'])assert.equal(closedAncestors(get(id)).length,0,`#${id} must remain visible when needed`);
  assert.equal(get('notice').attrs.role,'status');assert.equal(get('notice').attrs['aria-live'],'polite');
  assert.equal(get('progress-label').attrs['aria-live'],'polite');assert.ok(inside(get('expert-offset'),get('expert-fields')));
  assert.ok(inside(get('archive-picker'),get('custom-firmware')));assert.ok(inside(get('download-migration'),get('migration-options')));
  for(const id of ['confirm-dialog','question-dialog']){assert.equal(get(id).tag,'dialog');assert.equal(closedAncestors(get(id)).length,0);}
  assert.ok(!has(get('confirm-submit'),'disabled'),'Confirmation uses an enabled action button, not a typing gate');
});

test('operation confirmation keeps warnings and explicit action buttons without text entry',()=>{
  const dialog=get('confirm-dialog'),form=dialog.children.find(node=>node.tag==='form'),submit=get('confirm-submit');
  assert.ok(form);assert.equal(form.attrs.method,'dialog');
  for(const id of ['confirm-title','confirm-detail','confirm-warning'])assert.ok(inside(get(id),form),`#${id} remains visible in the confirmation form`);
  assert.ok(hasClass(get('confirm-warning'),'notice'),'Warnings must remain prominent');
  assert.ok(!nodes.some(node=>inside(node,form)&&['input','textarea','select'].includes(node.tag)),'No confirmation may require typing or another field');
  for(const id of ['confirm-token-fields','token-label','confirm-token'])assert.ok(!byId.has(id),`Obsolete #${id} must not remain in the document`);
  const buttons=nodes.filter(node=>inside(node,form)&&node.tag==='button');assert.equal(buttons.length,2);
  const cancel=buttons.find(node=>node.attrs.value==='cancel');assert.ok(cancel);assert.match(html.slice(cancel.start).split('</button>')[0],/>Cancel$/);
  assert.equal(submit.attrs.value,'confirm');assert.ok(inside(submit,form));assert.ok(!has(submit,'disabled'));
  assert.match(html.slice(submit.start).split('</button>')[0],/>Confirm operation$/);
});

test('active firmware writing has a separate initially closed progress dialog without dismissal actions',()=>{
  const dialog=get('flash-progress-dialog'),title=get('flash-progress-title'),warning=get('flash-progress-warning'),bar=get('flash-progress'),percent=get('flash-progress-percent'),stage=get('flash-progress-stage'),file=get('flash-progress-file');
  assert.equal(dialog.tag,'dialog');assert.equal(dialog.attrs.closedby,'none','Active write progress must not offer browser dismissal');assert.ok(!has(dialog,'open'),'The large progress window is opened only for an actual write');assert.equal(dialog.attrs['aria-labelledby'],title.attrs.id);assert.equal(dialog.attrs['aria-describedby'],warning.attrs.id);
  for(const child of [title,warning,bar,percent,stage,file])assert.ok(inside(child,dialog));
  assert.equal(title.tag,'h2');assert.match(html.slice(title.start).split('</h2>')[0],/>Flashing firmware$/);
  assert.match(html.slice(percent.start).split('</p>')[0],/>0%$/);assert.equal(bar.tag,'progress');assert.equal(bar.attrs.max,'1');assert.equal(bar.attrs.value,'0');assert.equal(bar.attrs['aria-label'],'Firmware transfer progress');
  assert.equal(stage.attrs.role,'status');assert.equal(stage.attrs['aria-live'],'polite');assert.equal(file.tag,'p');
  assert.equal(warning.tag,'strong');assert.match(html.slice(warning.start).split('</strong>')[0],/>Keep this tab open\. Do not unplug the radio or turn off power\.$/);
  assert.ok(nodes.some(node=>inside(node,dialog)&&node.tag==='p'&&/100% means the transfer finished\. Application startup is verified separately\./.test(html.slice(node.start).split('</p>')[0])),'Transfer completion must not claim verified startup');
  assert.ok(!nodes.some(node=>inside(node,dialog)&&['form','a','input','select','textarea'].includes(node.tag)),'The write-progress modal must not contain a dismissal form or other inputs');
  const stop=get('flash-stop-auto'),stopNote=get('flash-stop-auto-note'),buttons=nodes.filter(node=>inside(node,dialog)&&node.tag==='button');
  assert.deepEqual(buttons,[stop],'Only a conditional stop-after-write action is allowed, never close/cancel');assert.equal(stop.attrs.type,'button');assert.ok(has(stop,'hidden'));assert.ok(!has(stop,'disabled')&&!has(stop,'data-lock'),'Stopping future automatic steps must remain usable during the current write');assert.ok(hasClass(stop,'secondary'));assert.match(html.slice(stop.start).split('</button>')[0],/>Stop after this write$/);
  assert.ok(inside(stopNote,dialog));assert.ok(has(stopNote,'hidden'));assert.match(html.slice(stopNote.start).split('</p>')[0],/>Stops later automatic steps, not the current write\.$/);
  assert.ok(!inside(get('progress'),dialog)&&!inside(get('progress-label'),dialog),'The existing small inline progress remains on the main workflow');
  assert.equal(get('progress').attrs['aria-label'],'Operation progress');assert.equal(closedAncestors(get('progress')).length,0);
});

test('release notes and catalog metadata stay behind a collapsed Firmware details disclosure',()=>{
  const details=get('firmware-details'),metadata=get('catalog-detail'),workflow=nodes.find(node=>hasClass(node,'workflow'));
  assert.equal(details.tag,'details');assert.ok(!has(details,'open'));assert.ok(inside(details,workflow));assert.ok(inside(metadata,details));
  assert.ok(details.start>get('progress-label').start,'Optional metadata must not interrupt required actions and progress');
  assert.match(html.slice(details.start).split('</summary>')[0],/>Firmware details/);
  assert.equal(closedAncestors(get('image-warning')).length,0,'Hiding release notes must not hide write warnings');
});

test('the connected nRF52 bootloader status is separate from firmware choices and hidden until supported detection',()=>{
  const offer=get('nrf-bootloader-offer'),status=get('nrf-bootloader-status'),button=get('prepare-bootloader-update'),warning=get('nrf-bootloader-warning'),workflow=nodes.find(node=>hasClass(node,'workflow')),device=nodes.find(node=>hasClass(node,'device-display'));
  assert.equal(offer.tag,'div');assert.ok(hasClass(offer,'bootloader-offer'));assert.ok(has(offer,'hidden'));assert.ok(inside(offer,workflow));assert.equal(closedAncestors(offer).length,0);
  assert.ok(device.start<offer.start&&offer.start<get('firmware-choices').start,'Version status belongs beside the connected device, before application selection');
  assert.ok(inside(status,offer));assert.equal(status.attrs.role,'status');assert.equal(status.attrs['aria-live'],'polite');
  assert.ok(inside(button,offer));assert.equal(button.tag,'button');assert.equal(button.attrs.type,'button');assert.ok(has(button,'hidden'));assert.ok(has(button,'data-lock'));assert.ok(hasClass(button,'secondary'));assert.ok(!hasClass(button,'step-button'));
  assert.equal(button.attrs['aria-describedby'],warning.attrs.id);assert.ok(inside(warning,offer));assert.match(html.slice(warning.start).split('</p>')[0],/Back up first/);assert.match(html.slice(warning.start).split('</p>')[0],/reinstalling the exact compatible application/);assert.match(html.slice(warning.start).split('</p>')[0],/never resets.*writes firmware automatically/);
  assert.ok(!nodes.some(node=>inside(node,offer)&&hasClass(node,'action-number')),'A conditional bootloader offer cannot add a mandatory numbered step');
});

// Read individual declaration blocks, including responsive overrides, rather
// than freezing the stylesheet's formatting or unrelated visual choices.
const styleRules=[...css.replace(/\/\*[\s\S]*?\*\//g,'').matchAll(/([^{}]+)\{([^{}]*)\}/g)].map(([,selectors,body])=>({
  selectors:selectors.trim().split(',').map(selector=>selector.trim()),
  declarations:Object.fromEntries([...body.matchAll(/([\w-]+)\s*:\s*([^;]+)(?:;|$)/g)].map(([,property,value])=>[property,value.trim()]))
}));
const declarationsFor=selector=>styleRules.filter(rule=>rule.selectors.includes(selector)).map(rule=>rule.declarations);
function assertProperty(selector,property,expected){
  const values=declarationsFor(selector).filter(rule=>Object.hasOwn(rule,property)).map(rule=>rule[property]);
  assert.ok(values.length,`Missing ${selector} ${property}`);
  for(const value of values)assert.equal(value,expected,`${selector} ${property} must remain left-aligned, including responsive overrides`);
}

test('the flashing popup includes a bounded, keyboard-scrollable plain-text console below its power warning',()=>{
  const dialog=get('flash-progress-dialog'),output=get('flash-progress-log'),heading=get('flash-progress-log-title');
  assert.equal(output.tag,'pre');assert.ok(inside(output,dialog));assert.ok(inside(heading,dialog));assert.equal(output.attrs['aria-label'],'Flashing console');assert.equal(output.attrs['aria-labelledby'],heading.attrs.id);assert.equal(output.attrs.tabindex,'0');assert.equal(output.attrs['aria-live'],'off');assert.ok(output.start>get('flash-progress-warning').start);assert.equal(closedAncestors(output).length,0);
  assert.ok(declarationsFor('#flash-progress-log').some(rule=>rule.width==='100%'&&rule.overflow==='auto'&&rule['white-space']==='pre-wrap'&&rule['overflow-wrap']==='anywhere'&&rule['max-height']?.includes('dvh')&&parseFloat(rule['font-size'])>=13),'Console text must be readable, internally scrollable and wrap on narrow screens');
});

test('write progress is very large, static and readable while still fitting a phone viewport',()=>{
  const modal='#flash-progress-dialog';assert.ok(declarationsFor(modal).some(rule=>parseFloat(rule['max-width'])>=900&&rule.width==='calc(100% - 30px)'&&rule['max-height']==='calc(100dvh - 30px)'&&rule.overflow==='auto'),'The large progress modal must fit and scroll on narrow or short screens');
  assert.ok(declarationsFor('#flash-progress-title').some(rule=>/^clamp\(28px,\s*4vw,\s*40px\)$/.test(rule['font-size']||'')),'The write heading must be prominent');
  assert.ok(declarationsFor('#flash-progress-percent').some(rule=>/^clamp\(64px,\s*12vw,\s*96px\)$/.test(rule['font-size']||'')&&Number(rule['font-weight'])>=800&&rule['font-variant-numeric']==='tabular-nums'),'Transfer percentage needs a very large steady numeral');
  assert.ok(declarationsFor('#flash-progress').some(rule=>rule.width==='100%'&&parseFloat(rule.height)>=24),'Active writing needs a much thicker progress bar');
  assert.ok(declarationsFor('progress').some(rule=>parseFloat(rule.height)===5),'The ordinary main-page progress bar must retain its compact size');
  assert.ok(declarationsFor('#flash-progress-warning').some(rule=>rule.display==='block'&&/^clamp\(18px,\s*2\.5vw,\s*24px\)$/.test(rule['font-size']||'')&&rule.background&&rule['border-left']),'Do-not-interrupt guidance must be large and visually distinct');
  for(const selector of ['#flash-progress-title','#flash-progress-file','#flash-progress-warning'])assert.ok(declarationsFor(selector).some(rule=>rule['overflow-wrap']==='anywhere'),'Long write details must wrap instead of overflowing phones');
  for(const rule of styleRules.filter(rule=>rule.selectors.some(selector=>selector.startsWith('#flash-progress')))){
    assert.ok(!Object.hasOwn(rule.declarations,'animation')&&!Object.hasOwn(rule.declarations,'transition'),'Write progress must not pulse or animate its warning');
  }
});

test('the next required action has a scoped static highlight and a readable button label',()=>{
  const control='.next-action:not(:disabled)',button='button.next-action:not(:disabled)',badge=`${button}::after`;
  const highlight=declarationsFor(control);assert.ok(highlight.some(rule=>/^#[0-9a-f]{6}$/i.test(rule['border-color']||'')&&/0 0 0 3px\s+#[0-9a-f]{6}/i.test(rule['box-shadow']||'')),'The next enabled control needs a strong border and ring');
  assert.ok(highlight.some(rule=>(rule['box-shadow']||'').split(',').length>=2),'A separate static shadow must reinforce the next action');
  const label=declarationsFor(badge);assert.ok(label.some(rule=>rule.content==='"Next"'),'Buttons must explicitly say Next, not rely on color alone');
  assert.ok(label.some(rule=>rule.display==='inline-flex'&&rule.background&&rule.color&&parseFloat(rule['font-weight'])>=700),'The badge needs readable contrasting text');
  for(const rule of styleRules.filter(rule=>rule.selectors.some(selector=>selector.includes('.next-action')))){
    assert.ok(rule.selectors.every(selector=>selector.includes('.next-action')&&selector.includes(':not(:disabled)')),'Highlighting must stay scoped to enabled next-action controls');
    for(const property of ['animation','transition','outline','outline-offset','transform'])assert.ok(!Object.hasOwn(rule.declarations,property),`Next-action styling must not add motion or replace keyboard focus (${property})`);
  }
  for(const selector of ['button:focus-visible','input:focus-visible','select:focus-visible'])assert.ok(declarationsFor(selector).some(rule=>/^[1-9]\d*(?:\.\d+)?px\s+solid\s+/.test(rule.outline||'')),'Existing keyboard focus must remain independently visible');
});

test('next-action badges stay in normal wrapping flow on narrow screens without covering labels',()=>{
  const button='button.next-action:not(:disabled)',badge=`${button}::after`,buttonRules=declarationsFor(button),badgeRules=declarationsFor(badge);
  assert.ok(buttonRules.some(rule=>rule['flex-wrap']==='wrap'&&rule['min-width']==='0'),'The highlighted button must shrink and wrap on phones');
  assert.ok(badgeRules.some(rule=>rule['max-width']==='100%'&&rule.flex==='0 0 auto'),'The short badge stays within its button without forcing a wide layout');
  for(const rule of badgeRules){assert.ok(!Object.hasOwn(rule,'position')&&!Object.hasOwn(rule,'inset')&&!Object.hasOwn(rule,'right'),'The badge must not overlay a button label');assert.ok(!Object.hasOwn(rule,'width')&&!Object.hasOwn(rule,'min-width'),'The badge must not force a fixed wide size');}
  assert.ok(declarationsFor('.review-actions .step-button').some(rule=>rule.width==='100%'&&rule['min-width']==='0'),'Main workflow buttons retain their narrow-screen full-width layout');
});

test('radio reselection has an initially hidden urgent callout beside the original USB chooser',()=>{
  const header=get('flasher'),callout=get('reconnect-callout'),title=get('reconnect-title'),detail=get('reconnect-detail'),chooser=get('select-port'),label=get('select-port-label');
  assert.ok(!hasClass(header,'reconnect-needed'),'The large reconnect presentation is conditional, not the ordinary page header');
  assert.equal(callout.tag,'div');assert.ok(has(callout,'hidden'));assert.equal(callout.attrs.role,'alert');assert.equal(callout.attrs['aria-live'],'assertive');assert.ok(inside(callout,header));
  assert.ok(inside(title,callout));assert.match(html.slice(title.start).split('</strong>')[0],/Select the same radio again/i);
  assert.ok(inside(detail,callout));assert.equal(detail.tag,'p');assert.ok(callout.start<chooser.start,'The urgent instruction must appear before the action it describes');
  assert.equal(closedAncestors(callout).length,0);assert.equal(closedAncestors(chooser).length,0,'Reconnection cannot require an advanced panel');
  assert.ok(inside(label,chooser));assert.ok(hasClass(label,'action-label'),'Only the editable label may change; the chooser and its step badge remain intact');
  assert.equal(nodes.filter(node=>node.attrs.id==='select-port').length,1);assert.ok(!nodes.some(node=>inside(node,callout)&&['button','input','select'].includes(node.tag)),'The callout must not duplicate the browser USB chooser');
  assert.ok(!has(callout,'tabindex')&&!has(chooser,'autofocus'),'A reconnect cue must not steal keyboard focus');
});

test('the shared reconnect callout and chooser label can distinguish startup verification without claiming initial success',()=>{
  const callout=get('reconnect-callout'),title=get('reconnect-title'),detail=get('reconnect-detail'),label=get('select-port-label'),chooser=get('select-port');
  assert.ok(has(callout,'hidden'),'No post-flash verification result may be shown on page load');
  assert.equal(title.tag,'strong');assert.equal(detail.tag,'p');assert.equal(label.tag,'span');
  assert.ok(inside(title,callout)&&inside(detail,callout)&&inside(label,chooser),'Runtime verification text must reuse the prominent callout and existing chooser, not introduce a second port request');
  for(const node of [title,detail,label])assert.ok(!node.children.length,'Runtime copy should replace plain text without removing step numbers or controls');
  assert.match(html.slice(label.start).split('</span>')[0],/>Choose USB port$/,'Before any transfer, the button must not claim a verification step');
  const initial=html.slice(callout.start).split('</div>')[0];assert.ok(!/Firmware verified|Verification complete|APPLICATION USB port/.test(initial),'Startup success and application-reconnect instructions depend on runtime state');
  assert.equal(nodes.filter(node=>node.attrs.id==='select-port').length,1,'Verification must not add a duplicate chooser button');
});

test('required radio reselection uses a very large scoped callout and touch target without flashing animation',()=>{
  const panel='.page-header.reconnect-needed',button=`${panel} #select-port`,badge=`${button} .action-number`;
  assert.ok(declarationsFor(panel).some(rule=>/^3px\s+solid\s+/.test(rule.border||'')&&Object.hasOwn(rule,'background')),'The reconnect header needs a strong visible boundary and background');
  const titleRules=[...declarationsFor('#reconnect-title'),...declarationsFor('.reconnect-callout strong'),...declarationsFor(`${panel} #reconnect-title`)];
  assert.ok(titleRules.some(rule=>{const match=/^clamp\((\d+)px,\s*[^,]+,\s*(\d+)px\)$/.exec(rule['font-size']||'');return match&&Number(match[1])>=28&&Number(match[2])>=40&&Number(rule['font-weight'])>=800;}),'The urgent headline must be markedly larger than ordinary explanatory copy');
  const buttonRules=declarationsFor(button);assert.ok(buttonRules.some(rule=>parseFloat(rule['min-height']||'0')>=90&&parseFloat(rule['font-size']||'0')>=22),'The reselect button needs a very large text and touch target');
  assert.ok(buttonRules.some(rule=>rule.width==='100%'&&rule['min-width']==='0'),'The large reconnect button must shrink to fit narrow screens');
  assert.ok(declarationsFor(badge).some(rule=>parseFloat(rule.height||'0')>=56&&parseFloat(rule['font-size']||'0')>=40),'The persistent step 1 badge should grow with the urgent action');
  for(const rule of styleRules.filter(rule=>rule.selectors.some(selector=>selector.includes('reconnect-needed')))){
    assert.ok(rule.selectors.every(selector=>selector.includes('reconnect-needed')),'Large reconnect styles must not change the ordinary compact controls');
    assert.ok(!Object.hasOwn(rule.declarations,'animation'),'Urgency must not depend on flashing or pulsing');
    assert.ok(!/^(?:none|0)(?:\s|$)/.test(rule.declarations.outline||''),'The reconnect treatment must preserve keyboard focus visibility');
  }
});

test('verified startup has its own prominent green treatment distinct from the amber reconnect request',()=>{
  const panel='.page-header.verification-complete',header=get('flasher'),success=declarationsFor(panel),reconnect=declarationsFor('.page-header.reconnect-needed');
  assert.ok(!hasClass(header,'verification-complete'),'Successful startup must be established at runtime, never claimed by the initial page');
  assert.ok(success.some(rule=>rule.width==='100%'&&parseFloat(rule.padding)>=20&&/^3px\s+solid\s+/.test(rule.border||'')&&rule.background),'Verified startup needs a prominent bounded status panel');
  assert.ok(success.some(rule=>reconnect.every(other=>rule.background!==other.background&&rule.border!==other.border)),'Success must look different from an outstanding reconnect request');
  assert.ok(declarationsFor(`${panel} #reconnect-title`).some(rule=>rule.color==='#176044'),'The existing prominent heading must turn green only in the verified state');
  for(const rule of styleRules.filter(rule=>rule.selectors.some(selector=>selector.includes('verification-complete')))){
    assert.ok(rule.selectors.every(selector=>selector.startsWith(panel)),'Verified styling must not affect unrelated controls');
    for(const property of ['animation','transition','outline','outline-offset','transform'])assert.ok(!Object.hasOwn(rule.declarations,property),'Success must remain static and preserve independent keyboard focus');
  }
  assert.ok(!declarationsFor(`${panel} #select-port`).some(rule=>Object.hasOwn(rule,'display')||Object.hasOwn(rule,'visibility')),'A verified result must not hide the chooser needed for another radio');
});

test('the main next-device path has a neutral callout and a legible primary action rather than urgent verification styling',()=>{
  const panel='.page-header.next-device',header=get('flasher'),rules=declarationsFor(panel),reconnect=declarationsFor('.page-header.reconnect-needed');
  assert.ok(!hasClass(header,'next-device'),'Post-transfer next-device styling must not appear before a transfer');
  assert.ok(rules.some(rule=>rule.width==='100%'&&parseFloat(rule.padding)>=20&&/^1px\s+solid\s+/.test(rule.border||'')&&rule.background),'The ordinary next-device choice needs its own neutral bounded panel');
  assert.ok(rules.some(rule=>reconnect.every(other=>rule.background!==other.background&&rule.border!==other.border)),'Optional verification must not reuse the urgent amber reconnect presentation');
  assert.ok(declarationsFor(`${panel} #reconnect-title`).some(rule=>rule.color==='var(--navy)'),'The next-device heading should use the ordinary heading color');
  const action=declarationsFor('#start-new-radio');assert.ok(action.some(rule=>parseFloat(rule['min-height']||'0')>=64&&parseFloat(rule['font-size']||'0')>=16),'The primary next-device button needs a readable 64px touch target');
  for(const rule of styleRules.filter(rule=>rule.selectors.some(selector=>selector.includes('next-device')))){
    assert.ok(rule.selectors.every(selector=>selector.startsWith(panel)),'Next-device styling must not affect required recovery or reconnect controls');
    assert.ok(!Object.hasOwn(rule.declarations,'animation'),'The optional choice must not flash or pulse');
  }
});

test('the firmware build picker has adjacent accessible selection guidance without stealing focus',()=>{
  const field=get('artifact-field'),picker=get('artifact'),hint=get('artifact-choice-hint'),badge=get('artifact-required'),choices=get('firmware-choices');
  assert.equal(field.tag,'div');assert.ok(hasClass(field,'artifact-field'));assert.ok(inside(field,choices));
  assert.ok(!hasClass(field,'choice-required'),'A missing-choice highlight must be computed from current state, not shown unconditionally');
  assert.equal(picker.parent,field);assert.equal(picker.tag,'select');assert.ok(!has(picker,'required'),'A deliberate custom file can satisfy the firmware requirement without a catalog choice');
  assert.ok(!has(picker,'aria-required')||picker.attrs['aria-required']==='false','Required state must be computed dynamically, not forced for every workflow');
  assert.ok((picker.attrs['aria-describedby']||'').split(/\s+/).includes(hint.attrs.id),'Screen readers must receive the same selection prompt');
  assert.equal(hint.parent,field);assert.ok(hint.start>picker.start,'Selection guidance must follow its own picker');
  assert.equal(hint.tag,'p');assert.ok(hasClass(hint,'hint'));assert.equal(hint.attrs.role,'status');assert.equal(hint.attrs['aria-live'],'polite');assert.ok(has(hint,'hidden'),'Guidance starts hidden until a choice is needed');
  assert.match(html.slice(hint.start).split('</p>')[0],/Step 2\.5: Choose a firmware build to continue/);
  assert.equal(badge.tag,'span');assert.ok(has(badge,'hidden'));assert.equal(badge.parent.tag,'label');assert.equal(badge.parent.attrs.for,picker.attrs.id);assert.match(html.slice(badge.start).split('</span>')[0],/>2\.5$/);
  assert.equal(closedAncestors(picker).length,0);assert.equal(closedAncestors(hint).length,0);
  assert.ok(!has(picker,'autofocus')&&!has(field,'tabindex'),'Highlighting a missing build must not move focus or add a fake control');
});

test('firmware build has a conditional non-action step 2.5 badge without renumbering primary steps',()=>{
  const badge=get('artifact-required'),picker=get('artifact'),field=get('artifact-field');
  assert.ok(hasClass(badge,'artifact-step-number'));assert.equal(badge.attrs['aria-hidden'],'true');assert.ok(has(badge,'hidden'),'Step 2.5 is shown only when its manual choice is needed');
  assert.ok(!hasClass(badge,'action-number'),'Conditional step 2.5 must not change the primary step sequence');assert.ok(!has(badge,'role')&&!has(badge,'tabindex'),'The badge is a label, not another control');
  assert.ok(inside(badge,field));assert.equal(badge.parent,picker.parent.children.find(node=>node.tag==='label'));
  assert.match(html.slice(badge.start).split('</label>')[0],/^<[^>]+>2\.5<\/span>\s*Firmware build/,'The optional number must appear before Firmware build');
  assert.ok(!/Step 2\.5/.test(picker.attrs['aria-label']||''),'The initial picker must not announce an inactive conditional step');
  const numbers=nodes.filter(node=>hasClass(node,'action-number')).map(node=>/^<[^>]+>([^<]*)</.exec(html.slice(node.start))?.[1].trim());
  assert.deepEqual(numbers,['1','2','3','4','5'],'The main steps follow numeric order with verification after flash');
  const rules=declarationsFor('.artifact-step-number');
  assert.ok(rules.some(rule=>parseFloat(rule['min-width']||'0')>=52),'The decimal step badge needs enough room for 2.5');
  assert.ok(rules.some(rule=>parseFloat(rule.height||'0')>=40),'Step 2.5 should match the main badge height');
  assert.ok(rules.some(rule=>parseFloat(rule['font-size']||'0')>=24),'Step 2.5 must remain visually prominent');
  assert.ok(rules.some(rule=>rule.background==='var(--navy)'),'The optional number should use the same dark badge color as the installation step');
});

test('missing-build highlighting is scoped to the required field and preserves keyboard focus',()=>{
  const panel=declarationsFor('.artifact-field.choice-required'),picker=declarationsFor('.artifact-field.choice-required select');
  assert.ok(panel.some(rule=>Object.hasOwn(rule,'background')||Object.hasOwn(rule,'background-color')),'The required build needs a visible background');
  assert.ok(panel.some(rule=>Object.hasOwn(rule,'border')||Object.hasOwn(rule,'border-color')),'The required build needs a visible boundary');
  assert.ok(picker.some(rule=>Object.hasOwn(rule,'border')||Object.hasOwn(rule,'border-color')),'The picker itself must be visibly highlighted');
  const requiredRules=styleRules.filter(rule=>rule.selectors.some(selector=>selector.includes('choice-required')));
  for(const rule of requiredRules){
    assert.ok(rule.selectors.every(selector=>selector.includes('.artifact-field.choice-required')),'Required highlighting must not recolor unrelated inputs');
    assert.ok(!Object.hasOwn(rule.declarations,'animation'),'The required field should not flash or pulse');
    assert.ok(!/^(?:none|0)(?:\s|$)/.test(rule.declarations.outline||''),'Required styling must not erase focus outlines');
  }
  assert.ok(declarationsFor('select:focus-visible').some(rule=>/^[1-9]\d*(?:\.\d+)?px\s+solid\s+/.test(rule.outline||'')),'Keyboard users must retain a visible focus ring');
});

test('USB and flash actions precede non-action badges and explanatory copy',()=>{
  const usb=get('select-port'),badge=get('browser-status'),prepare=get('prepare'),flash=get('flash');
  assert.equal(usb.parent,badge.parent);assert.ok(usb.start<badge.start,'USB selection must precede non-action status badges');assert.ok(get('start-new-radio').start<usb.start,'The next-device action must precede optional verification reconnect');
  assert.equal(prepare.parent,flash.parent);assert.ok(prepare.start<flash.start);
  assert.ok(prepare.parent.children.every(node=>node.tag==='button'),'The action row must contain only its numbered buttons');
  assert.ok(get('workflow-guidance').start>get('progress-label').start,'Explanatory copy belongs below progress, not beside the buttons');
});

test('backup progress and its status precede explanatory text and visible firmware warnings',()=>{
  const workflow=nodes.find(node=>hasClass(node,'workflow')),actions=get('prepare').parent,bar=get('progress'),status=get('progress-label');
  assert.equal(actions.parent,workflow);assert.equal(bar.parent,workflow);assert.equal(status.parent,workflow);
  const actionIndex=workflow.children.indexOf(actions),barIndex=workflow.children.indexOf(bar);
  assert.deepEqual(workflow.children.slice(actionIndex+1,barIndex),[get('stop-migration-auto')],'Only the conditional stop control may appear between buttons and progress');
  assert.equal(workflow.children[barIndex+1],status,'Current operation status must stay directly below its progress bar');
  const detailIds=['workflow-guidance','install-mode-hint','automatic-summary','image-name','image-warning'];
  for(const id of detailIds){const node=get(id);assert.ok(inside(node,workflow));assert.ok(node.start>status.start,`#${id} must be below backup progress/status`);assert.equal(closedAncestors(node).length,0,`#${id} must not be hidden in optional details`);}
  assert.ok(get('firmware-details').start>get('image-warning').start,'Optional release details stay after visible warnings');
  assert.equal(get('workflow-guidance').tag,'p');assert.ok(hasClass(get('workflow-guidance'),'hint'));
  assert.equal(get('image-warning').attrs['aria-live'],'polite');assert.equal(get('install-mode-switch').attrs['aria-describedby'],'install-mode-hint');
  const copy=html.slice(get('workflow-guidance').start).split('</p>')[0];assert.match(copy,/Step 3 offers a backup by default/);assert.match(copy,/Select Skip backup to go straight to step 4/);assert.match(copy,/checks run automatically before confirmation/);
});

test('main and optional action groups keep left alignment at every breakpoint',()=>{
  for(const selector of ['.sidebar','.connect-controls','.mode-step','.review-actions','.inline-actions','.bootloader-offer','.console-input','.firmware-file-links','footer'])assertProperty(selector,'justify-content','flex-start');
  assertProperty('.bootloader-offer','align-items','flex-start');assertProperty('.bootloader-offer','flex-direction','column');
  assertProperty('.page-header','align-items','flex-start');assertProperty('.page-header','flex-direction','column');
  for(const selector of ['button','.button']){assertProperty(selector,'justify-content','flex-start');assertProperty(selector,'text-align','left');}
});

test('firmware links wrap on narrow screens without stretching actions or creating another workflow step',()=>{
  const rows=declarationsFor('.firmware-file-links');assert.ok(rows.some(rule=>rule.display==='flex'&&rule['flex-wrap']==='wrap'&&rule['min-width']==='0'));
  assert.ok(rows.some(rule=>/^8px\s+12px$/.test(rule.gap||'')),'The small public links need clear separation without a full-width action');
  const links=declarationsFor('.firmware-file-links a');assert.ok(links.some(rule=>rule['max-width']==='100%'&&rule['overflow-wrap']==='anywhere'));
  assert.ok(declarationsFor('.text-link').some(rule=>parseFloat(rule['min-height']||'0')>=32),'Links retain usable touch targets');
  for(const rule of [...rows,...links]){assert.ok(!/\bauto\b/.test(rule['margin-left']||''),'Links must not be pushed to the right');assert.ok(!/^1(?:\s|$)/.test(rule.flex||''),'Public file links must not grow across empty space');}
});

test('action buttons are not pushed right by auto margins or stretched to fill their row',()=>{
  for(const selector of ['#workflow-guidance','.card-title > button','.primary span'])for(const rule of declarationsFor(selector))for(const property of ['margin','margin-left','margin-right']){
    assert.ok(!/\bauto\b/.test(rule[property]||''),`${selector} ${property} cannot push user actions right`);
  }
  for(const selector of ['.inline-actions > .secondary','.review-actions button','#select-port','.console-input input'])for(const rule of declarationsFor(selector))if(Object.hasOwn(rule,'flex')){
    assert.match(rule.flex,/^0(?:\s|$)/,`${selector} must not grow across empty space, including on mobile`);
  }
});

test('one visible Update or Erase/new-install switch precedes the build list and defaults to Update',()=>{
  const group=get('install-mode-switch'),update=get('install-mode-update'),install=get('install-mode-install'),hint=get('install-mode-hint'),workflow=nodes.find(node=>hasClass(node,'workflow'));
  assert.equal(group.tag,'fieldset');assert.ok(group.children.some(node=>node.tag==='legend'),'Mode switch requires an accessible group label');assert.ok(inside(group,workflow));assert.ok(group.start<get('artifact').start);
  for(const radio of [update,install]){assert.equal(radio.tag,'input');assert.equal(radio.attrs.type,'radio');assert.equal(radio.attrs.name,'install-mode');assert.ok(inside(radio,group));assert.equal(closedAncestors(radio).length,0);}
  assert.equal(update.attrs.value,'update');assert.equal(install.attrs.value,'install');assert.ok(has(update,'checked'));assert.ok(!has(install,'checked'));
  assert.ok(inside(hint,workflow));assert.equal(closedAncestors(hint).length,0);assert.equal(hint.attrs['aria-live'],'polite');
  assert.equal(get('flash-action').tag,'input');assert.equal(get('flash-action').attrs.type,'hidden','The legacy nRF action is a mirror, not a second conflicting user choice');
});

test('USB, backup and flash are primary actions while optional verification keeps its stable step 5 label',()=>{
  for(const [id,number]of [['select-port','1'],['prepare','3'],['flash','4'],['verify-app','5']]){
    const button=get(id),badge=button.children.find(node=>hasClass(node,'action-number')),label=button.children.find(node=>hasClass(node,'action-label'));
    if(id==='verify-app'){assert.ok(hasClass(button,'secondary'),'Optional verification must use the secondary style');assert.ok(!hasClass(button,'primary'));assert.equal(button.attrs['aria-label'],'Optional step 5: Verify running application');}
    else{assert.ok(hasClass(button,'primary'),`#${id} must use the dark primary style`);assert.ok(!hasClass(button,'secondary'),`#${id} cannot use the light secondary style`);}
    assert.ok(hasClass(button,'step-button'),id);assert.ok(badge,`#${id} needs a persistent number badge`);assert.ok(label,`#${id} needs a separate editable label`);
    assert.equal(badge.attrs['aria-hidden'],'true');assert.equal(/^<[^>]+>([^<]*)</.exec(html.slice(badge.start))?.[1].trim(),number,id);
    assert.match(button.attrs['aria-label']||'',new RegExp(`step ${number}\\b`,'i'),`#${id} must announce its step`);
  }
  assert.ok(inside(get('prepare-label'),get('prepare')));assert.match(html.slice(get('prepare-label').start).split('</span>')[0],/Backup\s*(?:&amp;|&)\s*prepare/i);
  assert.ok(!nodes.filter(node=>node.tag==='button'&&!['select-port','prepare','flash','verify-app'].includes(node.attrs.id)).some(node=>hasClass(node,'step-button')),'Optional tools must not suggest extra mandatory workflow steps');
  const verify=get('verify-app'),row=get('flash').parent;assert.equal(verify.parent,row);assert.deepEqual(row.children.map(node=>node.attrs.id),['prepare','flash','verify-app'],'The main action row must follow steps 3, 4, 5');assert.equal(closedAncestors(verify).length,0);assert.ok(!inside(verify,get('verification-options')));assert.ok(has(verify,'disabled')&&has(verify,'data-lock'));
});

test('step 2 numbers the installation choices once without creating a fake action or hiding their group label',()=>{
  const group=get('install-mode-switch'),legend=group.children.find(node=>node.tag==='legend'),row=group.children.find(node=>hasClass(node,'mode-step'));
  assert.equal(group.attrs['aria-describedby'],'install-mode-hint');assert.ok(legend);assert.ok(row);assert.equal(row.tag,'div');
  assert.match(html.slice(legend.start).split('</legend>')[0],/Step 2:\s*<\/span>Installation/);
  const badge=row.children.find(node=>hasClass(node,'action-number'));assert.ok(badge);assert.equal(badge.attrs['aria-hidden'],'true');
  assert.ok(!has(row,'role')&&!has(row,'tabindex'),'The shared step badge is not another input or button');
  for(const id of ['install-mode-update','install-mode-install'])assert.ok(inside(get(id),row));
  const numbers=nodes.filter(node=>hasClass(node,'action-number')).map(node=>/^<[^>]+>([^<]*)</.exec(html.slice(node.start))?.[1].trim());
  assert.deepEqual(numbers,['1','2','3','4','5'],'Each numbered step must appear once, with verification after flash');
  const backgrounds=declarationsFor('.mode-step > .action-number').filter(rule=>Object.hasOwn(rule,'background'));assert.equal(backgrounds.at(-1)?.background,'var(--navy)','The installation badge must finish with the dark primary color');
});

test('next-step instructions stay visible and numbered actions remain legible on phones',()=>{
  const guidance=get('step-guidance');assert.equal(guidance.attrs.role,'status');assert.equal(guidance.attrs['aria-live'],'polite');assert.equal(closedAncestors(guidance).length,0);
  const numberSize=[...declarationsFor('.action-number'),...declarationsFor('.step-button .action-number')].find(rule=>rule['font-size'])?.['font-size'];assert.ok(numberSize&&parseFloat(numberSize)>=28,'Step numbers must be visually prominent');
  const buttonHeight=declarationsFor('.step-button').find(rule=>rule['min-height'])?.['min-height'];assert.ok(buttonHeight&&parseFloat(buttonHeight)>=62,'Numbered main actions need a readable touch target');
  const phoneCss=css.slice(css.indexOf('@media (max-width: 600px)'));assert.match(phoneCss,/\.step-button[^{}]*\{[^}]*width:\s*100%/,'Phone actions must have room for number and backup text');
  const labelRules=[...declarationsFor('.action-label'),...declarationsFor('.step-button .action-label')];
  assert.ok(labelRules.some(rule=>rule['min-width']==='0'),'Long labels need room to shrink and wrap');assert.ok(!labelRules.some(rule=>rule['white-space']==='nowrap'||rule.overflow==='hidden'),'Step instructions must not be clipped or forced onto one line');
});

test('captured backup JSON has hidden-by-default read-only private text views in tools and the copy popup',()=>{
  for(const prefix of ['', 'question-']){
    const view=get(prefix+'backup-json-view'),field=get(prefix+'backup-json'),warning=get(prefix+'backup-json-warning'),status=get(prefix+'backup-json-status');
    assert.ok(has(view,'hidden'),'No backup text is revealed on page load');assert.ok(inside(field,view));assert.equal(field.tag,'textarea');assert.ok(hasClass(field,'backup-json'));
    assert.ok(has(field,'readonly'));assert.equal(field.attrs.rows,'10');assert.equal(field.attrs.spellcheck,'false');assert.equal(field.attrs.autocomplete,'off');assert.equal(field.attrs['aria-describedby'],warning.attrs.id);
    assert.ok(nodes.some(node=>node.tag==='label'&&node.attrs.for===field.attrs.id&&inside(node,view)),'A visible label must identify each text box');
    const warningText=html.slice(warning.start).split('</p>')[0];assert.match(warningText,/private identity and channel secrets/);
    if(!prefix)assert.match(warningText,/page memory only/);else assert.ok(warningText.replace(/<[^>]*>/g,'').length<100,'The copy popup needs only a brief privacy reminder');
    assert.equal(status.attrs.role,'status');assert.equal(status.attrs['aria-live'],'polite');assert.ok(inside(status,view));
    assert.equal(html.slice(field.start).split('>')[1].split('</textarea')[0],'','Static HTML cannot contain any captured data');
  }
  assert.ok(inside(get('backup-json-view'),get('backups')));assert.ok(get('backup-json-view').start>get('backup-summary').start);
  assert.ok(inside(get('question-backup-json-view'),get('question-dialog')));assert.ok(get('question-backup-json-view').start<get('question-actions').start);
});

test('backup download status is a conditional H1 before the JSON while ordinary questions keep their H2',()=>{
  const title=get('question-backup-title'),generic=get('question-title'),dialog=get('question-dialog'),view=get('question-backup-json-view'),hint=get('question-backup-download-hint');
  assert.equal(title.tag,'h1');assert.ok(has(title,'hidden'),'No downloaded-backup claim may be visible before a successful capture');assert.ok(inside(title,dialog));
  assert.match(html.slice(title.start).split('</h1>')[0],/>JSON backup has been downloaded$/);
  assert.equal(generic.tag,'h2');assert.ok(inside(generic,dialog));assert.ok(title.start<generic.start&&generic.start<view.start,'The backup-specific heading precedes ordinary question content');
  assert.ok(title.start<get('question-backup-json').start);assert.equal(hint.tag,'p');assert.ok(inside(hint,view));assert.ok(hint.start<get('question-backup-json').start);
  assert.match(html.slice(hint.start).split('</p>')[0],/Check your browser[’']s Downloads for the JSON file\./);
  assert.ok(declarationsFor('#question-backup-download-hint').some(rule=>rule['flex-basis']==='100%'),'The download location hint needs a readable full-width row');
  const rules=declarationsFor('#question-backup-title');
  assert.ok(rules.some(rule=>rule['flex-basis']==='100%'&&rule['overflow-wrap']==='anywhere'),'The longer H1 must wrap within the popup on phones');
  assert.ok(rules.some(rule=>/^clamp\(28px,\s*3\.2vw,\s*36px\)$/.test(rule['font-size']||'')),'The downloaded heading must be prominent without overflowing small screens');
});

test('backup JSON copy and tools-only clear remain usable without submitting the popup',()=>{
  for(const [prefix,ids]of [['',['copy-backup-json','clear-backup-json']],['question-',['copy-question-backup-json']]])for(const id of ids){
    const button=get(id);assert.equal(button.tag,'button');assert.equal(button.attrs.type,'button');assert.ok(inside(button,get(prefix+'backup-json-view')));
    assert.ok(!has(button,'data-lock'),'Copy and clear are local text actions, not busy-locked USB operations');assert.ok(!has(button,'disabled'));
  }
  const rules=declarationsFor('.backup-json');assert.ok(rules.some(rule=>rule.width==='100%'&&rule['max-width']==='100%'&&rule['min-width']==='0'),'Text boxes must fit their container on phones and dialogs');
  assert.ok(rules.some(rule=>rule.resize==='vertical'&&/monospace/.test(rule['font-family']||'')),'JSON should be legible and vertically resizable');
});

test('the backup popup has one Copy text action beside dynamic Stop and Continue actions without clear or save controls',()=>{
  const view=get('question-backup-json-view'),copy=get('copy-question-backup-json'),actions=get('question-actions'),dialog=get('question-dialog');
  const buttons=nodes.filter(node=>node.tag==='button'&&inside(node,view));assert.deepEqual(buttons,[copy]);assert.ok(!byId.has('clear-question-backup-json'));
  assert.match(html.slice(copy.start).split('</button>')[0],/>Copy text$/);assert.ok(hasClass(copy,'primary'));
  assert.ok(inside(actions,dialog));assert.equal(actions.children.length,0,'Stop and Continue are created for the active prompt, not a second static save acknowledgement');
  const dialogRule='#question-dialog:has(#question-backup-json-view:not([hidden])) form';
  assert.ok(declarationsFor(dialogRule).some(rule=>rule.display==='flex'&&rule['flex-wrap']==='wrap'),'Backup actions share a wrapping row');
  assert.ok(declarationsFor('#question-backup-json-view:not([hidden])').some(rule=>rule.display==='contents'),'Copy, Stop and Continue must remain adjacent in the same wrapping form layout');
  assert.ok(declarationsFor('#question-backup-json').some(rule=>/^min\(\d+(?:\.\d+)?dvh,\s*\d+px\)$/.test(rule.height||'')),'Backup text stays bounded by the viewport and an explicit pixel ceiling');
});

test('a partial-backup warning has a brief readable place in the same copy popup',()=>{
  const summary=get('question-backup-summary'),view=get('question-backup-json-view');
  assert.equal(summary.tag,'p');assert.ok(inside(summary,view));assert.ok(has(summary,'hidden'),'No partial-backup warning is shown before a capture is classified');
  assert.ok(summary.start<get('question-backup-json').start,'The concise partial warning must precede its backup text');
  assert.equal(closedAncestors(summary).length,0,'The warning cannot depend on opening optional details');
  assert.ok(declarationsFor('#question-backup-summary').some(rule=>rule['flex-basis']==='100%'),'The partial warning needs its own full-width row');
  assert.equal(html.slice(summary.start).split('>')[1].split('</p')[0],'','Static HTML cannot pre-classify the backup or expose captured data');
});

test('backup popup JSON and controls use larger text without overflowing phones',()=>{
  const popup='#question-dialog:has(#question-backup-json-view:not([hidden]))';
  for(const selector of ['#question-backup-json',`${popup} p`,`${popup} label`,`${popup} button`]){
    const sizes=declarationsFor(selector).filter(rule=>Object.hasOwn(rule,'font-size')).map(rule=>rule['font-size']);
    assert.ok(sizes.length,`Missing enlarged text for ${selector}`);assert.ok(sizes.every(size=>/^\d+(?:\.\d+)?px$/.test(size)&&parseFloat(size)>=16),`${selector} needs at least 16px readable text, including responsive overrides`);
  }
  const headings=declarationsFor('#question-backup-title').filter(rule=>rule['font-size']);assert.ok(headings.some(rule=>/^clamp\(28px,\s*3\.2vw,\s*36px\)$/.test(rule['font-size'])),'The backup H1 should scale with its larger content');
  assert.ok(declarationsFor(popup).some(rule=>parseFloat(rule['max-width'])>=900),'The enlarged text needs a wider desktop popup');
  assert.ok(declarationsFor('dialog').some(rule=>rule.width==='calc(100% - 30px)'&&rule['max-height']==='calc(100dvh - 30px)'&&rule.overflow==='auto'),'The dialog must still fit and scroll on phones');
  assert.ok(declarationsFor('.backup-json').some(rule=>rule.width==='100%'&&rule['max-width']==='100%'&&rule['min-width']==='0'&&rule.overflow==='auto'),'Large JSON remains within its scrollable text box');
  assert.ok(has(get('question-backup-json'),'readonly'),'Increasing readability must not make the backup editable');
});
