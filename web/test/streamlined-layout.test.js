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

test('USB selection is the first main-page control in the compact header',()=>{
  const header=get('flasher'),button=get('select-port'),main=nodes.find(node=>node.tag==='main');
  assert.equal(header.tag,'header');assert.ok(hasClass(header,'page-header'));assert.ok(inside(button,header));
  const controls=nodes.filter(node=>inside(node,main)&&['button','select','input','textarea'].includes(node.tag)&&node.attrs.type!=='hidden');
  assert.equal(controls[0],button);assert.equal(closedAncestors(button).length,0);
  assert.ok(!nodes.some(node=>hasClass(node,'hero')),'Large introductory hero must not precede the controls');
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

test('advanced, backup, console and capability controls are collapsed by default',()=>{
  for(const id of ['advanced-options','backups','console','capabilities']){const node=get(id);assert.equal(node.tag,'details',id);assert.ok(!has(node,'open'),`#${id} must start collapsed`);}
  for(const id of ['connection-options','custom-firmware','bootloader-options','nrf-actions','migration-options','verification-options','esp-retry-options','image-details']){
    const node=get(id);assert.equal(node.tag,'details',id);assert.ok(!has(node,'open'),id);assert.ok(inside(node,get('advanced-options')),`#${id} belongs under extras`);
  }
  for(const id of ['auto-detect-board','auto-backup','auto-finish'])assert.ok(has(get(id),'checked'),`Collapsing #${id} must not change its safe default`);
});

test('status, warnings, progress and required expert offsets cannot be trapped in closed extras',()=>{
  for(const id of ['notice','automatic-summary','image-warning','progress','progress-label','expert-fields'])assert.equal(closedAncestors(get(id)).length,0,`#${id} must remain visible when needed`);
  assert.equal(get('notice').attrs.role,'status');assert.equal(get('notice').attrs['aria-live'],'polite');
  assert.equal(get('progress-label').attrs['aria-live'],'polite');assert.ok(inside(get('expert-offset'),get('expert-fields')));
  assert.ok(inside(get('archive-picker'),get('custom-firmware')));assert.ok(inside(get('download-migration'),get('migration-options')));
  for(const id of ['confirm-dialog','question-dialog']){assert.equal(get(id).tag,'dialog');assert.equal(closedAncestors(get(id)).length,0);}
  assert.ok(has(get('confirm-submit'),'disabled'),'Typed flash authorization must remain required');
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
  assert.deepEqual(numbers,['1','2','3','4'],'The original main steps must keep their numbering');
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
  assert.equal(usb.parent,badge.parent);assert.ok(usb.start<badge.start,'USB must be the leftmost header control');
  assert.equal(prepare.parent,flash.parent);assert.ok(prepare.start<flash.start);
  assert.ok(prepare.parent.children.every(node=>node.tag==='button'),'The action row must contain only its two buttons');
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
  assert.match(html.slice(get('workflow-guidance').start).split('</p>')[0],/Step 3 offers a backup/);
});

test('main and optional action groups keep left alignment at every breakpoint',()=>{
  for(const selector of ['.sidebar','.connect-controls','.mode-step','.review-actions','.inline-actions','.bootloader-offer','.console-input','footer'])assertProperty(selector,'justify-content','flex-start');
  assertProperty('.bootloader-offer','align-items','flex-start');assertProperty('.bootloader-offer','flex-direction','column');
  assertProperty('.page-header','align-items','flex-start');assertProperty('.page-header','flex-direction','column');
  for(const selector of ['button','.button']){assertProperty(selector,'justify-content','flex-start');assertProperty(selector,'text-align','left');}
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

test('USB, backup and flash buttons are dark primary actions with stable step numbers 1, 3 and 4',()=>{
  for(const [id,number]of [['select-port','1'],['prepare','3'],['flash','4']]){
    const button=get(id),badge=button.children.find(node=>hasClass(node,'action-number')),label=button.children.find(node=>hasClass(node,'action-label'));
    assert.ok(hasClass(button,'primary'),`#${id} must use the dark primary style`);assert.ok(!hasClass(button,'secondary'),`#${id} cannot use the light secondary style`);assert.ok(hasClass(button,'step-button'),id);assert.ok(badge,`#${id} needs a persistent number badge`);assert.ok(label,`#${id} needs a separate editable label`);
    assert.equal(badge.attrs['aria-hidden'],'true');assert.equal(/^<[^>]+>([^<]*)</.exec(html.slice(badge.start))?.[1].trim(),number,id);
    assert.match(button.attrs['aria-label']||'',new RegExp(`Step ${number}\\b`),`#${id} must announce its step`);
  }
  assert.ok(inside(get('prepare-label'),get('prepare')));assert.match(html.slice(get('prepare-label').start).split('</span>')[0],/Backup\s*(?:&amp;|&)\s*prepare/i);
  assert.ok(!nodes.filter(node=>node.tag==='button'&&!['select-port','prepare','flash'].includes(node.attrs.id)).some(node=>hasClass(node,'step-button')),'Optional tools must not suggest extra mandatory workflow steps');
});

test('step 2 numbers the installation choices once without creating a fake action or hiding their group label',()=>{
  const group=get('install-mode-switch'),legend=group.children.find(node=>node.tag==='legend'),row=group.children.find(node=>hasClass(node,'mode-step'));
  assert.equal(group.attrs['aria-describedby'],'install-mode-hint');assert.ok(legend);assert.ok(row);assert.equal(row.tag,'div');
  assert.match(html.slice(legend.start).split('</legend>')[0],/Step 2:\s*<\/span>Installation/);
  const badge=row.children.find(node=>hasClass(node,'action-number'));assert.ok(badge);assert.equal(badge.attrs['aria-hidden'],'true');
  assert.ok(!has(row,'role')&&!has(row,'tabindex'),'The shared step badge is not another input or button');
  for(const id of ['install-mode-update','install-mode-install'])assert.ok(inside(get(id),row));
  const numbers=nodes.filter(node=>hasClass(node,'action-number')).map(node=>/^<[^>]+>([^<]*)</.exec(html.slice(node.start))?.[1].trim());
  assert.deepEqual(numbers,['1','2','3','4'],'Four steps must appear once, in workflow order');
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
  const headings=declarationsFor(`${popup} h2`).filter(rule=>rule['font-size']);assert.ok(headings.some(rule=>parseFloat(rule['font-size'])>=26),'The popup heading should scale with its larger content');
  assert.ok(declarationsFor(popup).some(rule=>parseFloat(rule['max-width'])>=900),'The enlarged text needs a wider desktop popup');
  assert.ok(declarationsFor('dialog').some(rule=>rule.width==='calc(100% - 30px)'&&rule['max-height']==='calc(100dvh - 30px)'&&rule.overflow==='auto'),'The dialog must still fit and scroll on phones');
  assert.ok(declarationsFor('.backup-json').some(rule=>rule.width==='100%'&&rule['max-width']==='100%'&&rule['min-width']==='0'&&rule.overflow==='auto'),'Large JSON remains within its scrollable text box');
  assert.ok(has(get('question-backup-json'),'readonly'),'Increasing readability must not make the backup editable');
});
