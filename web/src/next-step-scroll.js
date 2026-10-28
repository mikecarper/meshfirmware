// Guidance only: never focus, click, reveal panels or change a control's value.
// Call update(null) while busy so the next action may be shown once afterward.
export function createNextStepScroller({window:win=globalThis.window,document:doc=win?.document,topInset=24,bottomInset=24}={}){
  let initialized=false,lastTarget=null,pending=null,generation=0,disposed=false;
  const cancel=()=>{if(pending!==null)win?.cancelAnimationFrame?.(pending);pending=null;};
  const modalAllows=target=>{const dialog=doc?.querySelector?.('dialog[open]');return !dialog||dialog===target||dialog.contains?.(target);};
  const usable=target=>!!target&&target.isConnected!==false&&!target.disabled&&!target.hidden&&target.getAttribute?.('aria-disabled')!=='true'&&!target.closest?.('[hidden], [inert]')&&typeof target.getBoundingClientRect==='function'&&typeof target.scrollIntoView==='function';
  function shouldScroll(target){
    if(!usable(target)||!modalAllows(target))return false;
    if(target.getClientRects&&target.getClientRects().length===0)return false;
    const rect=target.getBoundingClientRect(),viewport=win?.visualViewport;
    const left=Number(viewport?.offsetLeft)||0,top=Number(viewport?.offsetTop)||0,width=Number(viewport?.width)||Number(win?.innerWidth)||Number(doc?.documentElement?.clientWidth),height=Number(viewport?.height)||Number(win?.innerHeight)||Number(doc?.documentElement?.clientHeight);
    if(![rect.top,rect.bottom,rect.left,rect.right,width,height].every(Number.isFinite)||width<=0||height<=0||rect.bottom<=rect.top||rect.right<=rect.left)return false;
    const safeTop=top+Math.min(Math.max(0,topInset),height/4),safeBottom=top+height-Math.min(Math.max(0,bottomInset),height/4);
    if(rect.top<safeTop||rect.bottom>safeBottom||rect.left<left+8||rect.right>left+width-8)return true;
    // A fully in-view target may still sit underneath a fixed header/overlay.
    // Ignore an unavailable hit test; a missing result is not proof of coverage.
    const hit=doc?.elementFromPoint?.((rect.left+rect.right)/2,(rect.top+rect.bottom)/2);
    return !!hit&&hit!==target&&!target.contains?.(hit);
  }
  return {
    update(element,{initial=false}={}){
      if(disposed)return false;
      const target=element||null;
      if(!initialized||initial){initialized=true;lastTarget=target;generation++;cancel();return false;}
      if(target===lastTarget)return false;
      lastTarget=target;const expected=++generation;cancel();
      if(!usable(target)||!modalAllows(target)||typeof win?.requestAnimationFrame!=='function')return false;
      pending=win.requestAnimationFrame(()=>{
        pending=null;
        if(disposed||generation!==expected||lastTarget!==target)return;
        try{
          if(!shouldScroll(target))return;
          const reduced=win.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches===true;
          target.scrollIntoView({block:'center',behavior:reduced?'auto':'smooth'});
        }catch{/* Guidance failures must not affect a firmware operation. */}
      });
      return true;
    },
    destroy(){disposed=true;generation++;cancel();lastTarget=null;}
  };
}
