/* Exalyte Question Studio — JSON editor + live "exactly as students see it" preview + per-section drafts.
   Plugs into the existing Upload Questions card; the original #questionsJson textarea and upload API are reused. */
(function(){
'use strict';
var $=function(i){return document.getElementById(i)};
var E=function(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})};
var LS='exalyte_qstudio_v1',PAGE=40,LET=['A','B','C','D'];
var drafts={},curExam='',curKey='',view='exam',shown=PAGE,timer,mob='code',lastItems=[];
try{drafts=JSON.parse(localStorage.getItem(LS)||'{}')||{}}catch(e){drafts={}}
function persist(){try{localStorage.setItem(LS,JSON.stringify(drafts))}catch(e){}}
function ta(){return $('questionsJson')}
function dget(ex,k){return(drafts[ex]&&drafts[ex][k])||''}
function dset(ex,k,v){if(!ex)return;drafts[ex]=drafts[ex]||{};if(v&&v.trim())drafts[ex][k]=v;else delete drafts[ex][k];persist()}

/* ---------- parsing & validation (mirrors the server's rules in handleAdminBulkQuestions) ---------- */
function norm(q){q=(q&&typeof q==='object')?q:{};var g=function(){for(var i=0;i<arguments.length;i++){var v=q[arguments[i]];if(v!=null&&v!=='')return String(v)}return''};
  return{question:g('question','question_text'),o:[g('option_a','a'),g('option_b','b'),g('option_c','c'),g('option_d','d')],ans:g('answer','correct_answer').trim().toUpperCase(),img:g('image_url','image'),exp:g('explanation'),sec:g('section')}}
function sectionsOf(){var s=$('uploadSectionSelect');return s?[].slice.call(s.options).map(function(o){return o.value}).filter(Boolean):[]}
function targets(){var ex=(window.allExams||[]).filter(function(e){return String(e.id)===String(curExam)})[0],m={};
  try{var c=JSON.parse(ex&&ex.section_config||'{}');['required','compulsory_group','normal_group'].forEach(function(k){(c[k]||[]).forEach(function(s){if(s&&s.name)m[s.name]=s.count||s.questions||s.num||0})})}catch(e){}return m}
function analyze(text){
  var r={empty:!text.trim(),items:[],fatal:'',errLine:0,valid:0,bad:0,warn:0,list:[]};
  if(r.empty)return r;
  var arr;try{arr=JSON.parse(text)}catch(e){
    var m=String(e.message).match(/position (\d+)/),ln=String(e.message).match(/line (\d+)/);
    r.errLine=ln?+ln[1]:m?text.slice(0,+m[1]).split('\n').length:0;
    r.fatal='Invalid JSON'+(r.errLine?' near line '+r.errLine:'')+': '+String(e.message).replace(/ in JSON.*$/,'').slice(0,90);return r}
  if(!Array.isArray(arr)){r.fatal='Top level must be an array: [ {...}, {...} ]';return r}
  if(!arr.length){r.fatal='The array is empty';return r}
  var secs=sectionsOf();
  arr.forEach(function(raw,i){var n=norm(raw),errs=[],warns=[];
    if(!raw||typeof raw!=='object'||Array.isArray(raw))errs.push('not an object');
    if(!n.question)errs.push('question missing');
    n.o.forEach(function(o,j){if(!o)errs.push('option '+LET[j]+' missing')});
    if(LET.indexOf(n.ans)<0)errs.push('answer must be A, B, C or D');
    if(!errs.length&&new Set(n.o.map(function(x){return x.trim()})).size<4)warns.push('two options are identical');
    if(n.sec&&secs.length&&secs.indexOf(n.sec)<0)warns.push('section “'+n.sec+'” is not in this exam');
    if(n.sec&&!secs.length)warns.push('exam has no sections; section ignored by students');
    if(curKey&&n.sec&&n.sec!==curKey)warns.push('has its own section “'+n.sec+'” (overrides this tab)');
    r.items.push({n:n,raw:raw,errs:errs,warns:warns});
    if(errs.length){r.bad++;r.list.push({i:i,t:'err',m:errs.join(', ')})}else r.valid++;
    if(warns.length){r.warn++;r.list.push({i:i,t:'warn',m:warns.join(', ')})}});
  return r}

/* ---------- safe HTML (the exam page renders question HTML raw, so the preview does too, minus scripts) ---------- */
function clean(h){var d=new DOMParser().parseFromString('<body>'+String(h||'')+'</body>','text/html');
  d.querySelectorAll('script,iframe,object,embed,link,meta,style,form,base').forEach(function(n){n.remove()});
  d.querySelectorAll('*').forEach(function(n){[].slice.call(n.attributes).forEach(function(a){var v=a.value.trim().toLowerCase();
    if(/^on/i.test(a.name)||((a.name==='href'||a.name==='src')&&/^(javascript|vbscript|data:text\/html)/.test(v)))n.removeAttribute(a.name)})});return d.body.innerHTML}
function isImg(s){var t=(s||'').trim();return t.indexOf('http')===0&&/(\.jpg|\.jpeg|\.png|\.webp|\.gif|ibb\.co|images\.unsplash\.com|i\.imgur\.com)/.test(t)}
function short(t){return!!t&&!isImg(t)&&!/<img/i.test(t)&&t.replace(/<[^>]*>/g,'').trim().length<=26}
function oc(t,cls){return isImg(t)?'<img src="'+E(t)+'" class="'+cls+'" alt="" onerror="this.style.display=\'none\'">':clean(t)}

function card(it,i,sec){var n=it.n,bad=it.errs.length,grid=!bad&&n.o.every(short);
  var chip=bad?'<span class="qsp-chip bad">Skipped · '+E(it.errs[0])+'</span>':it.warns.length?'<span class="qsp-chip warn">⚠ '+E(it.warns[0])+'</span>':'<span class="qsp-chip ok">✓ Valid</span>';
  var label=n.sec||sec,pill=label?'<span class="q-section">'+E(label)+'</span>':'';
  var head='<div class="q-top"><div class="q-num">'+(i+1)+'</div><div class="q-text">'+clean(n.question||'<i style="color:var(--t4)">(empty question)</i>')+pill+'</div></div>'+
    (n.img?'<img src="'+E(n.img)+'" class="q-img" alt="" style="margin-left:38px" onerror="this.style.display=\'none\'">':'');
  var body;
  if(view==='exam'){
    body='<div class="options'+(grid?' grid':'')+'">'+n.o.map(function(o,j){return'<div class="option"><div class="option-letter">'+LET[j]+'</div><div class="option-text">'+oc(o,'option-img')+'</div></div>'}).join('')+'</div>'}
  else{
    body='<div class="rv-opts'+(grid?' grid':'')+'" style="margin-left:38px">'+n.o.map(function(o,j){var c=LET[j]===n.ans;
      return'<div class="rv-opt'+(c?' rv-ok':' rv-faded')+'"><div class="rv-ol">'+(c?'✓':LET[j])+'</div><div class="rv-ot">'+oc(o,'rv-opt-img')+'</div></div>'}).join('')+'</div>'+
      '<div class="rv-note">Correct answer: '+E(n.ans||'—')+'</div>'+
      (n.exp&&n.exp.trim()?'<div class="rv-explanation">'+(isImg(n.exp)?'<img src="'+E(n.exp)+'" class="rv-explanation-img" alt="">':clean(n.exp))+'</div>':'<div class="rv-noexp">No explanation</div>')}
  return'<div class="q-card qsp-card'+(bad?' is-bad':'')+'" data-i="'+i+'" tabindex="0" role="button" aria-label="Edit question '+(i+1)+'">'+chip+head+body+'</div>'}

/* ---------- UI ---------- */
var CSS='#qs{margin-bottom:16px}.qs-tabs{display:flex;gap:6px;overflow-x:auto;padding-bottom:6px;margin-bottom:10px;-webkit-overflow-scrolling:touch}.qs-tab{flex:0 0 auto;display:inline-flex;align-items:center;gap:6px;min-height:38px;padding:0 14px;border:1px solid var(--border);border-radius:999px;background:var(--surf);font-family:var(--gs);font-size:.78rem;font-weight:500;color:var(--t2);cursor:pointer;white-space:nowrap}.qs-tab:hover{border-color:var(--blue)}.qs-tab.on{background:#e8f0fe;border-color:#c6dafc;color:var(--blue)}.qs-tab small{font-size:.68rem;padding:1px 7px;border-radius:999px;background:var(--hov);color:var(--t3)}.qs-tab.on small{background:#fff}.qs-tab small.full{background:var(--grn-bg);color:var(--green)}.qs-tab small.err{background:var(--red-bg);color:var(--red)}'+
'.qs-bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}.qs-bar .sp{flex:1}.qs-seg{display:inline-flex;border:1px solid var(--border);border-radius:999px;overflow:hidden}.qs-seg button{border:0;background:var(--surf);padding:0 14px;min-height:36px;font-family:var(--gs);font-size:.76rem;font-weight:500;color:var(--t3);cursor:pointer}.qs-seg button.on{background:#e8f0fe;color:var(--blue)}'+
'.qs-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;align-items:start}.qs-pane{border:1px solid var(--border);border-radius:12px;background:var(--surf);overflow:hidden;min-width:0}.qs-ph{padding:8px 14px;border-bottom:1px solid var(--border);font-family:var(--gs);font-size:.75rem;font-weight:500;color:var(--t3);display:flex;justify-content:space-between;gap:8px}'+
'.qs-code{display:flex;height:520px;background:#fbfcfe}.qs-gut{padding:10px 8px 10px 10px;text-align:right;color:#9aa0a6;font:12px/20px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#f1f3f4;overflow:hidden;user-select:none;min-width:38px}.qs-gut .er{background:#fce8e6;color:#d93025;font-weight:700;display:block}.qs-gut div{display:block}'+
'#questionsJson{flex:1;height:100%!important;border:0!important;border-radius:0!important;resize:none;padding:10px 12px!important;font:12.5px/20px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace!important;white-space:pre;overflow:auto;background:transparent!important;color:#202124;tab-size:2;min-width:0;box-shadow:none!important}'+
'.qs-sum{padding:10px 14px;border-top:1px solid var(--border);font-size:.78rem;display:flex;gap:12px;flex-wrap:wrap;align-items:center}.qs-sum b.ok{color:var(--green)}.qs-sum b.wn{color:#b06000}.qs-sum b.bd{color:var(--red)}.qs-fatal{background:var(--red-bg);color:var(--red);padding:10px 14px;font-size:.8rem;border-top:1px solid #f4c7c3}.qs-iss{max-height:130px;overflow:auto;border-top:1px solid var(--border)}.qs-iss button{display:block;width:100%;text-align:left;border:0;background:none;padding:7px 14px;font-size:.76rem;cursor:pointer;color:var(--t2)}.qs-iss button:hover{background:var(--hov)}.qs-iss .e{color:var(--red)}.qs-iss .w{color:#b06000}'+
'.qsp{height:520px;overflow:auto;padding:6px 22px 20px;background:var(--surf)}.qsp-empty{padding:60px 20px;text-align:center;color:var(--t3);font-size:.85rem}.qsp-more{display:block;margin:12px auto;padding:10px 22px;border:1px solid var(--border);border-radius:999px;background:var(--surf);cursor:pointer;font-family:var(--gs);font-size:.8rem;color:var(--blue)}'+
'.qsp .q-card{padding:22px 0 20px;border-bottom:1px solid var(--border);position:relative;cursor:pointer;border-radius:8px}.qsp .q-card:hover{background:#f8fbff}.qsp .q-card:focus-visible{outline:2px solid var(--blue)}.qsp-chip{position:absolute;right:0;top:8px;font-size:.66rem;font-weight:600;padding:2px 9px;border-radius:999px}.qsp-chip.ok{background:var(--grn-bg);color:var(--green)}.qsp-chip.warn{background:#fef7e0;color:#b06000}.qsp-chip.bad{background:var(--red-bg);color:var(--red)}.qsp .is-bad{opacity:.75}'+
'.qsp .q-top{display:flex;align-items:flex-start;gap:10px;margin-bottom:12px;padding-top:6px}.qsp .q-num{min-width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-family:var(--gs);font-size:.7rem;font-weight:500;background:var(--hov);color:var(--t3);flex-shrink:0}.qsp .q-text{font-size:.9rem;color:var(--t1);line-height:1.6;flex:1;min-width:0;padding-right:70px}.qsp .q-text p,.qsp .option-text p{margin:0;display:inline}.qsp .q-section{display:inline-block;font-size:.65rem;background:#e8f0fe;color:var(--blue);padding:2px 8px;border-radius:20px;margin-left:6px;vertical-align:middle}.qsp .q-img{max-width:100%;max-height:200px;border-radius:8px;margin-bottom:12px;border:1px solid var(--border);object-fit:contain}'+
'.qsp .options{display:flex;flex-direction:column;gap:2px;margin-left:38px}.qsp .options.grid,.qsp .rv-opts.grid{display:grid;grid-template-columns:1fr 1fr;gap:2px 16px}.qsp .option,.qsp .rv-opt{display:flex;align-items:center;gap:12px;padding:6px 8px 6px 4px;min-height:44px;font-size:.82rem;color:var(--t2);line-height:1.4}.qsp .option-letter,.qsp .rv-ol{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-family:var(--gs);font-size:.8rem;font-weight:500;background:var(--surf);color:var(--t3);border:1.5px solid var(--t4);flex-shrink:0}.qsp .option-text,.qsp .rv-ot{flex:1;min-width:0}.qsp .option-img{max-width:100%;max-height:160px;border-radius:8px;border:1px solid var(--border);object-fit:contain}.qsp .rv-opt-img{max-width:100%;max-height:120px;border-radius:8px;border:1px solid var(--border)}'+
'.qsp .rv-ok .rv-ol{background:var(--green);border-color:var(--green);color:#fff}.qsp .rv-ok{color:var(--t1);font-weight:500}.qsp .rv-faded{opacity:.6}.qsp .rv-note{margin:6px 0 4px 38px;font-size:.74rem;color:var(--green);font-weight:500}.qsp .rv-explanation{margin:6px 0 0 38px;padding:2px 0 2px 14px;border-left:3px solid var(--blue);font-size:.82rem;color:var(--t2);line-height:1.65}.qsp .rv-explanation p{margin:0;display:inline}.qsp .rv-explanation-img{max-width:100%;max-height:200px;border-radius:8px;border:1px solid var(--border)}.qsp .rv-noexp{margin:6px 0 0 38px;font-size:.74rem;color:var(--t4)}.qsp img{max-width:100%;height:auto}'+
'#questionsJson:focus{outline:none}.qs-cd:focus-within{border-color:var(--blue);box-shadow:0 0 0 3px rgba(26,115,232,.12)}.qs-mob{display:none}@media(max-width:1000px){.qs-grid{grid-template-columns:1fr}.qs-mob{display:inline-flex}#qs.m-code .qs-pv,#qs.m-prev .qs-cd{display:none}.qs-code,.qsp{height:420px}}'+
'.qse-back{position:fixed;inset:0;z-index:9500;background:rgba(32,33,36,.5);display:flex;align-items:center;justify-content:center;padding:16px}.qse{background:#fff;border-radius:18px;width:100%;max-width:640px;max-height:calc(100vh - 32px);overflow:auto;padding:22px;box-shadow:0 24px 64px rgba(0,0,0,.3)}.qse h3{font-family:var(--gs);font-weight:500;font-size:1.05rem;margin-bottom:14px}.qse label{display:block;font-size:.74rem;font-weight:500;color:var(--t3);margin:10px 0 4px}.qse textarea,.qse input,.qse select{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:10px;font:inherit;font-size:16px;background:#fff}.qse textarea{min-height:70px;resize:vertical}.qse .row{display:grid;grid-template-columns:1fr 1fr;gap:10px}.qse .act{display:flex;gap:8px;margin-top:18px;flex-wrap:wrap}.qse .act .sp{flex:1}@media(max-width:560px){.qse .row{grid-template-columns:1fr}.qse-back{align-items:flex-end;padding:0}.qse{border-radius:20px 20px 0 0;max-height:92vh}}';

function mount(){
  if($('qs'))return;var t=ta();if(!t)return;var grp=t.closest('.form-group');if(!grp)return;
  var st=document.createElement('style');st.textContent=CSS;document.head.appendChild(st);
  var root=document.createElement('div');root.id='qs';root.className='m-code';
  root.innerHTML='<div class="qs-tabs" id="qsTabs" style="display:none"></div>'+
   '<div class="qs-bar"><div class="qs-seg qs-mob"><button type="button" data-m="code" class="on">Code</button><button type="button" data-m="prev">Preview</button></div>'+
   '<div class="qs-seg" id="qsView"><button type="button" data-v="exam" class="on">Exam view</button><button type="button" data-v="review">Answers &amp; explanations</button></div><span class="sp"></span>'+
   '<button type="button" class="btn btn-outline btn-sm" id="qsFmt">Format</button><button type="button" class="btn btn-outline btn-sm" id="qsEx">Example</button><button type="button" class="btn btn-outline btn-sm" id="qsAdd">+ Add question</button></div>'+
   '<div class="qs-grid"><div class="qs-pane qs-cd"><div class="qs-ph"><span>JSON code</span><span id="qsCount"></span></div><div class="qs-code"><div class="qs-gut" id="qsGut"></div><div id="qsSlot" style="flex:1;display:flex;min-width:0"></div></div><div id="qsFatal"></div><div class="qs-sum" id="qsSum"></div><div class="qs-iss" id="qsIss"></div></div>'+
   '<div class="qs-pane qs-pv"><div class="qs-ph"><span>Live preview — tap a question to edit</span><span id="qsPvInfo"></span></div><div class="qsp" id="qsPrev"></div></div></div>'+
   '<div class="qs-bar" style="margin-top:12px" id="qsFoot"></div>';
  grp.parentNode.insertBefore(root,grp);$('qsSlot').appendChild(t);grp.style.display='none';
  t.setAttribute('spellcheck','false');t.setAttribute('wrap','off');t.removeAttribute('rows');
  var w=$('uploadSectionWrap');if(w)w.style.display='none';
  var up=document.querySelector('button[onclick="uploadQuestions()"]');if(up)up.textContent='Upload this tab';
  t.addEventListener('input',function(){dset(curExam,curKey,t.value);schedule()});
  t.addEventListener('scroll',function(){$('qsGut').scrollTop=t.scrollTop});
  $('qsView').addEventListener('click',function(e){var b=e.target.closest('button');if(!b)return;view=b.dataset.v;[].forEach.call(this.children,function(x){x.classList.toggle('on',x===b)});render()});
  root.querySelector('.qs-mob').addEventListener('click',function(e){var b=e.target.closest('button');if(!b)return;mob=b.dataset.m;[].forEach.call(this.children,function(x){x.classList.toggle('on',x===b)});root.className='m-'+mob});
  $('qsFmt').onclick=format;$('qsEx').onclick=example;$('qsAdd').onclick=function(){edit(-1)};
  $('qsPrev').addEventListener('click',function(e){var m=e.target.closest('.qs-more');if(m){shown+=PAGE;render();return}var c=e.target.closest('.qsp-card');if(c)edit(+c.dataset.i)});
  $('qsPrev').addEventListener('keydown',function(e){if(e.key==='Enter'&&e.target.classList.contains('qsp-card'))edit(+e.target.dataset.i)});
  $('qsIss').addEventListener('click',function(e){var b=e.target.closest('button');if(b)edit(+b.dataset.i)});
  render();
}
function schedule(){clearTimeout(timer);timer=setTimeout(render,200)}
function tabKeys(){var s=sectionsOf();return s.length?[''].concat(s):[]}
function drawTabs(){
  var el=$('qsTabs'),keys=tabKeys();if(!keys.length){el.style.display='none';return}
  var tg=targets();el.style.display='flex';
  el.innerHTML=keys.map(function(k){var txt=k===curKey?ta().value:dget(curExam,k),r=analyze(txt),tgt=tg[k]||0,cls='',lab='';
    if(!txt.trim())lab='—';else if(r.fatal){lab='!';cls='err'}else{lab=tgt?r.valid+'/'+tgt:String(r.valid);if(tgt&&r.valid===tgt&&!r.bad)cls='full';else if(r.bad)cls='err'}
    return'<button type="button" class="qs-tab'+(k===curKey?' on':'')+'" data-k="'+E(k)+'">'+E(k||'All sections')+' <small class="'+cls+'">'+lab+'</small></button>'}).join('');
  [].forEach.call(el.querySelectorAll('.qs-tab'),function(b){b.onclick=function(){switchTab(b.dataset.k)}});
}
function switchTab(k){
  dset(curExam,curKey,ta().value);curKey=k;var sel=$('uploadSectionSelect');if(sel)sel.value=k;
  if(window.updateDeleteAllBtnLabel)window.updateDeleteAllBtnLabel();
  ta().value=dget(curExam,k);shown=PAGE;render();
}
function render(){
  var t=ta();if(!t||!$('qs'))return;var text=t.value,r=analyze(text);lastItems=r.items;
  var lines=Math.max(1,text.split('\n').length);
  $('qsGut').innerHTML=Array.apply(null,Array(lines)).map(function(_,i){return'<div'+(r.errLine===i+1?' class="er"':'')+'>'+(i+1)+'</div>'}).join('');$('qsGut').scrollTop=t.scrollTop;
  $('qsFatal').innerHTML=r.fatal?'<div class="qs-fatal">✗ '+E(r.fatal)+'</div>':'';
  $('qsCount').textContent=r.items.length?r.items.length+' question'+(r.items.length>1?'s':''):'';
  $('qsSum').innerHTML=r.empty?'<span style="color:var(--t3)">Paste JSON here, or press “Example”. The preview updates as you type.</span>':r.fatal?'':'<span><b class="ok">'+r.valid+'</b> will upload</span>'+(r.warn?'<span><b class="wn">'+r.warn+'</b> warning'+(r.warn>1?'s':'')+'</span>':'')+(r.bad?'<span><b class="bd">'+r.bad+'</b> will be skipped</span>':'');
  $('qsIss').innerHTML=r.list.slice(0,60).map(function(x){return'<button type="button" data-i="'+x.i+'" class="'+(x.t==='err'?'e':'w')+'">'+(x.t==='err'?'✗':'⚠')+' Q'+(x.i+1)+': '+E(x.m)+'</button>'}).join('');
  var pv=$('qsPrev'),keep=pv.scrollTop;
  if(!r.items.length)pv.innerHTML='<div class="qsp-empty">'+(r.fatal?'Fix the JSON to see the preview.':'Your questions will appear here exactly as students see them.')+'</div>';
  else{pv.innerHTML=r.items.slice(0,shown).map(function(it,i){return card(it,i,curKey)}).join('')+(r.items.length>shown?'<button type="button" class="qsp-more qs-more">Show '+Math.min(PAGE,r.items.length-shown)+' more ('+(r.items.length-shown)+' hidden)</button>':'');pv.scrollTop=keep}
  $('qsPvInfo').textContent=view==='exam'?'Exam view':'After submission';
  drawTabs();footer();
}
function footer(){
  var f=$('qsFoot');if(!f)return;if(!tabKeys().length){f.innerHTML='';return}
  f.innerHTML='<button type="button" class="btn btn-primary" id="qsAll">Upload all sections</button><span style="font-size:.76rem;color:var(--t3)">Uploads every tab that has a draft. Drafts are saved on this device.</span>';
  $('qsAll').onclick=uploadAll;
}
function format(){try{var v=JSON.parse(ta().value);ta().value=JSON.stringify(v,null,2);dset(curExam,curKey,ta().value);render();toast('Formatted')}catch(e){toast('Fix the JSON first','warn')}}
function example(){
  var s=sectionsOf(),sec=curKey||'';
  var ex=[{question:'What is the SI unit of force?',option_a:'Joule',option_b:'Newton',option_c:'Pascal',option_d:'Watt',answer:'B',explanation:'Force = mass × acceleration, measured in <b>newtons</b> (N).'}];
  if(sec)ex[0].section=sec;ta().value=JSON.stringify(ex,null,2);dset(curExam,curKey,ta().value);render()}

/* ---------- edit one question (writes back into the JSON) ---------- */
function readArr(){var v=ta().value.trim();if(!v)return[];try{var a=JSON.parse(v);return Array.isArray(a)?a:null}catch(e){return null}}
function edit(i){
  var arr=readArr();if(arr===null){toast('Fix the JSON before editing a question','warn');return}
  var isNew=i<0,raw=isNew?{}:arr[i],n=norm(raw),secs=sectionsOf();
  var back=document.createElement('div');back.className='qse-back';
  back.innerHTML='<div class="qse" role="dialog" aria-modal="true" aria-label="Edit question"><h3>'+(isNew?'New question':'Edit question '+(i+1))+'</h3>'+
   '<label>Question (HTML allowed)</label><textarea id="qeQ">'+E(n.question)+'</textarea><div class="row">'+LET.map(function(l,j){return'<div><label>Option '+l+'</label><input id="qeO'+j+'" value="'+E(n.o[j])+'"></div>'}).join('')+'</div>'+
   '<div class="row"><div><label>Correct answer</label><select id="qeA">'+['','A','B','C','D'].map(function(l){return'<option value="'+l+'"'+(l===n.ans?' selected':'')+'>'+(l||'— choose —')+'</option>'}).join('')+'</select></div>'+
   (secs.length?'<div><label>Section</label><select id="qeS"><option value="">'+(curKey?'(use tab: '+E(curKey)+')':'(none)')+'</option>'+secs.map(function(s){return'<option'+(s===n.sec?' selected':'')+'>'+E(s)+'</option>'}).join('')+'</select></div>':'<div></div>')+'</div>'+
   '<label>Explanation (HTML or image link)</label><textarea id="qeE">'+E(n.exp)+'</textarea><label>Question image link (optional)</label><input id="qeI" value="'+E(n.img)+'">'+
   '<div class="act">'+(isNew?'':'<button type="button" class="btn btn-danger btn-sm" id="qeD">Delete</button>')+'<span class="sp"></span><button type="button" class="btn btn-outline" id="qeC">Cancel</button><button type="button" class="btn btn-primary" id="qeOK">Apply</button></div></div>';
  document.body.appendChild(back);$('qeQ').focus();
  function close(){back.remove();document.removeEventListener('keydown',esc,true)}
  function esc(e){if(e.key==='Escape'){e.preventDefault();close()}}document.addEventListener('keydown',esc,true);
  back.addEventListener('mousedown',function(e){if(e.target===back)close()});$('qeC').onclick=close;
  if($('qeD'))$('qeD').onclick=function(){arr.splice(i,1);write(arr);close()};
  $('qeOK').onclick=function(){
    var o=(isNew?{}:raw);['question_text','a','b','c','d','correct_answer','image'].forEach(function(k){delete o[k]});
    o.question=$('qeQ').value;LET.forEach(function(l,j){o['option_'+l.toLowerCase()]=$('qeO'+j).value});o.answer=$('qeA').value;
    if($('qeE').value.trim())o.explanation=$('qeE').value;else delete o.explanation;
    if($('qeI').value.trim())o.image_url=$('qeI').value.trim();else delete o.image_url;
    var s=$('qeS')?$('qeS').value:'';if(s)o.section=s;else if(isNew&&curKey&&!$('qeS'))delete o.section;else if($('qeS'))delete o.section;
    if(isNew)arr.push(o);else arr[i]=o;write(arr);close();
  };
}
function write(arr){ta().value=arr.length?JSON.stringify(arr,null,2):'';dset(curExam,curKey,ta().value);render()}

/* ---------- upload every tab that has a draft ---------- */
async function uploadAll(){
  dset(curExam,curKey,ta().value);var ex=curExam;if(!ex){toast('Select an exam first','warn');return}
  var keys=tabKeys().filter(function(k){return dget(ex,k).trim()}).sort(function(a,b){return a===''?-1:b===''?1:0});
  if(!keys.length){toast('Nothing to upload — all tabs are empty','warn');return}
  var plan=[],problems=[];
  keys.forEach(function(k){var r=analyze(dget(ex,k));if(r.fatal)problems.push((k||'All sections')+': '+r.fatal);else if(!r.valid)problems.push((k||'All sections')+': no valid questions');else plan.push({k:k,r:r})});
  if(problems.length){toast(problems[0]+(problems.length>1?' (+'+(problems.length-1)+' more)':''),'err');return}
  var replace=$('replaceQuestions')&&$('replaceQuestions').checked,total=plan.reduce(function(s,p){return s+p.r.valid},0),skipped=plan.reduce(function(s,p){return s+p.r.bad},0);
  var msg=(replace?'Replace questions in '+plan.length+' tab'+(plan.length>1?'s':'')+'?\nThis deletes the existing questions in those tabs first and cannot be undone.':'Upload '+total+' question'+(total!==1?'s':'')+'?\nAdds to what is already in this exam.')+(skipped?'\n'+skipped+' invalid question'+(skipped>1?'s':'')+' will be skipped.':'')+'\n'+plan.map(function(p){return(p.k||'All sections')+': '+p.r.valid}).join(' · ');
  if(!(await window.exConfirm(msg,{title:replace?'Replace and upload all?':'Upload all sections?',danger:!!replace,label:replace?'Replace & upload':'Upload',typed:false})))return;
  var btn=$('qsAll');if(btn){btn.disabled=true;btn.textContent='Uploading…'}
  var done=[],failed=[];
  for(var p of plan){
    try{
      if(replace)await apiFetch(p.k?'/admin/questions/'+ex+'?section='+encodeURIComponent(p.k):'/admin/questions/'+ex,{method:'DELETE'});
      var res=await apiFetch('/admin/questions/bulk',{method:'POST',body:JSON.stringify({exam_id:parseInt(ex),questions:JSON.parse(dget(ex,p.k)),section:p.k})});
      if(res.ok===false)throw new Error('failed');done.push((p.k||'All')+' '+((res.data&&res.data.inserted)!=null?res.data.inserted:p.r.valid));dset(ex,p.k,'');
    }catch(e){failed.push(p.k||'All sections')}}
  if(ta()&&ex===curExam)ta().value=dget(ex,curKey);
  if(btn){btn.disabled=false;btn.textContent='Upload all sections'}
  render();
  toast(failed.length?'Uploaded '+done.length+', failed: '+failed.join(', '):'Uploaded — '+done.join(' · '),failed.length?'err':'',6000);
  try{await window.loadQuestionsForExam();await window.loadExams();await window.loadDashboard()}catch(e){}
}

/* ---------- hooks into existing admin.js behaviour ---------- */
function hook(){
  var oc=window.clearQuestionsJson;
  window.clearQuestionsJson=function(){
    var sel=$('questionExamSelect'),now=sel?sel.value:'';
    if($('qs')&&now!==curExam)dset(curExam,curKey,ta().value);   // switching exams: keep the old draft
    oc&&oc();
    if($('qs')&&now===curExam){dset(curExam,curKey,'');render()}  // after an upload / explicit clear
  };
  var ou=window.updateUploadSectionSelector;
  window.updateUploadSectionSelector=function(id){
    ou&&ou(id);if(!$('qs'))return;
    curExam=String(id||'');curKey='';var sel=$('uploadSectionSelect');if(sel)sel.value='';shown=PAGE;
    ta().value=dget(curExam,'');render();
  };
}
function init(){mount();hook()}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
