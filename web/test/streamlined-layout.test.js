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

test('USB and flash actions precede non-action badges and explanatory copy',()=>{
  const usb=get('select-port'),badge=get('browser-status'),prepare=get('prepare'),flash=get('flash');
  assert.equal(usb.parent,badge.parent);assert.ok(usb.start<badge.start,'USB must be the leftmost header control');
  assert.equal(prepare.parent,flash.parent);assert.ok(prepare.start<flash.start);
  const explanation=prepare.parent.children.find(node=>node.tag==='p');
  assert.ok(explanation);assert.ok(flash.start<explanation.start,'Explanation must not push the main actions away from the left edge');
});

test('main and optional action groups keep left alignment at every breakpoint',()=>{
  for(const selector of ['.sidebar','.connect-controls','.mode-step','.review-actions','.inline-actions','.bootloader-offer','.console-input','footer'])assertProperty(selector,'justify-content','flex-start');
  assertProperty('.bootloader-offer','align-items','flex-start');assertProperty('.bootloader-offer','flex-direction','column');
  assertProperty('.page-header','align-items','flex-start');assertProperty('.page-header','flex-direction','column');
  for(const selector of ['button','.button']){assertProperty(selector,'justify-content','flex-start');assertProperty(selector,'text-align','left');}
});

test('action buttons are not pushed right by auto margins or stretched to fill their row',()=>{
  for(const selector of ['.review-actions > p','.card-title > button','.primary span'])for(const rule of declarationsFor(selector))for(const property of ['margin','margin-left','margin-right']){
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

test('captured backup JSON has hidden-by-default read-only private text views in tools and the save prompt',()=>{
  for(const prefix of ['', 'question-']){
    const view=get(prefix+'backup-json-view'),field=get(prefix+'backup-json'),warning=get(prefix+'backup-json-warning'),status=get(prefix+'backup-json-status');
    assert.ok(has(view,'hidden'),'No backup text is revealed on page load');assert.ok(inside(field,view));assert.equal(field.tag,'textarea');assert.ok(hasClass(field,'backup-json'));
    assert.ok(has(field,'readonly'));assert.equal(field.attrs.rows,'10');assert.equal(field.attrs.spellcheck,'false');assert.equal(field.attrs.autocomplete,'off');assert.equal(field.attrs['aria-describedby'],warning.attrs.id);
    assert.ok(nodes.some(node=>node.tag==='label'&&node.attrs.for===field.attrs.id&&inside(node,view)),'A visible label must identify each text box');
    assert.match(html.slice(warning.start).split('</p>')[0],/private identity and channel secrets/);assert.match(html.slice(warning.start).split('</p>')[0],/page memory only/);
    assert.equal(status.attrs.role,'status');assert.equal(status.attrs['aria-live'],'polite');assert.ok(inside(status,view));
    assert.equal(html.slice(field.start).split('>')[1].split('</textarea')[0],'','Static HTML cannot contain any captured data');
  }
  assert.ok(inside(get('backup-json-view'),get('backups')));assert.ok(get('backup-json-view').start>get('backup-summary').start);
  assert.ok(inside(get('question-backup-json-view'),get('question-dialog')));assert.ok(get('question-backup-json-view').start<get('question-actions').start);
});

test('backup JSON copy and clear remain usable during the save prompt without submitting it',()=>{
  for(const [prefix,ids]of [['',['copy-backup-json','clear-backup-json']],['question-',['copy-question-backup-json','clear-question-backup-json']]])for(const id of ids){
    const button=get(id);assert.equal(button.tag,'button');assert.equal(button.attrs.type,'button');assert.ok(inside(button,get(prefix+'backup-json-view')));
    assert.ok(!has(button,'data-lock'),'Copy and clear are local text actions, not busy-locked USB operations');assert.ok(!has(button,'disabled'));
  }
  const rules=declarationsFor('.backup-json');assert.ok(rules.some(rule=>rule.width==='100%'&&rule['max-width']==='100%'&&rule['min-width']==='0'),'Text boxes must fit their container on phones and dialogs');
  assert.ok(rules.some(rule=>rule.resize==='vertical'&&/monospace/.test(rule['font-family']||'')),'JSON should be legible and vertically resizable');
});
