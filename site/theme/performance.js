const API='/board13/api';
const byId=id=>document.getElementById(id);
const money=n=>(Number(n||0)<0?'-¥':'¥')+Math.abs(Number(n||0)).toLocaleString('zh-CN',{minimumFractionDigits:2,maximumFractionDigits:2});
const esc=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const statusText=s=>s==='confirmed'?'已核账':s==='rejected'?'已退回':'待核账';
const roiText=v=>v==null?'—':Number(v).toFixed(2);
function shDate(offset=0){const d=new Date(Date.now()+offset*86400000),p=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Shanghai',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(d),o={};p.forEach(x=>o[x.type]=x.value);return `${o.year}-${o.month}-${o.day}`}
function rangeOf(scope){const today=shDate();if(scope==='today')return[today,today];if(scope==='month')return[today.slice(0,8)+'01',today];return[shDate(-6),today]}
function toast(text,ok=false,scroll=false){const el=byId('msg');if(!el)return;el.textContent=text;el.className='msg '+(ok?'ok':'bad');if(scroll)el.scrollIntoView({behavior:'smooth',block:'nearest'})}
function clearToast(){const el=byId('msg');if(!el)return;el.textContent='';el.className='msg'}
async function api(path,opt={}){let r;try{r=await fetch(API+path,{credentials:'same-origin',...opt})}catch(e){throw new Error('网络连接失败，请检查网络后重试')}let d={};const raw=await r.text();if(raw){try{d=JSON.parse(raw)}catch(e){if(!r.ok)throw new Error(`服务器暂时异常（${r.status}），请稍后重试`);throw new Error('服务器返回内容异常，请刷新后重试')}}if(!r.ok)throw new Error(d.err||`操作失败（${r.status}）`);return d}
async function logout(){try{await fetch(API+'/logout',{method:'POST',credentials:'same-origin'})}finally{location.href='login.html'}}
async function identity(){return api('/ecom/v2/me')}
function safeVoucherUrl(url){const value=String(url||'');return /^\/zb-t1365d2f4f3\/_uploads\/[A-Za-z0-9_.-]+\.(?:jpg|jpeg|png|gif)$/i.test(value)?value:''}
function voucherAnchor(url,label='查看凭证'){const safe=safeVoucherUrl(url);return safe?`<a class="voucher" target="_blank" rel="noopener noreferrer" href="${esc(safe)}">${esc(label)}</a>`:'<span class="sub">无有效凭证</span>'}
function setBusy(el,busy,busyText='处理中…'){if(!el)return;if(busy){if(!el.dataset.idleText)el.dataset.idleText=el.textContent;el.disabled=true;el.setAttribute('aria-busy','true');el.textContent=busyText}else{el.disabled=false;el.removeAttribute('aria-busy');if(el.dataset.idleText){el.textContent=el.dataset.idleText;delete el.dataset.idleText}}}
function setPageLoading(loading,text='正在读取…'){document.body.classList.toggle('is-loading',loading);document.querySelectorAll('[data-query-button]').forEach(el=>setBusy(el,loading,text))}
function setMessageAccessibility(){const el=byId('msg');if(el){el.setAttribute('role','status');el.setAttribute('aria-live','polite');el.setAttribute('aria-atomic','true')}}
function renderNav(me,active=''){
  const nav=byId('nav');if(!nav)return;
  let links=[['首页','首页.html'],['每日填报','每日填报.html']];
  if(me.role==='admin')links.push(['总后台','后台.html'],['核账','核账中心.html'],['报销','报销中心.html'],['结算','结算中心.html'],['账号台账','账号台账.html'],['绩效海报','绩效海报.html'],['人员分组','人员分组.html']);
  else if(me.is_leader)links.push(['组内数据','组内看板.html'],['报销','报销中心.html']);
  nav.setAttribute('aria-label','系统主导航');
  nav.innerHTML='<button class="nav-toggle" type="button" aria-expanded="false" aria-label="展开系统菜单" onclick="toggleNav(this)">菜单</button><div class="nav-links">'+links.map(x=>`<a class="${active===x[0]?'on':''}" ${active===x[0]?'aria-current="page"':''} href="${x[1]}">${x[0]}</a>`).join('')+'<button type="button" onclick="logout()">退出</button></div>';
  markWideTables();setMessageAccessibility();
}
function toggleNav(button){const nav=button.closest('.nav'),open=nav.classList.toggle('open');button.setAttribute('aria-expanded',String(open));button.setAttribute('aria-label',open?'收起系统菜单':'展开系统菜单');button.textContent=open?'收起':'菜单'}
function closeNav(focusToggle=false){const nav=document.querySelector('.nav.open');if(!nav)return;nav.classList.remove('open');const button=nav.querySelector('.nav-toggle');if(button){button.setAttribute('aria-expanded','false');button.setAttribute('aria-label','展开系统菜单');button.textContent='菜单';if(focusToggle)button.focus()}}
function markWideTables(){document.querySelectorAll('.scroll').forEach(x=>{if(x.querySelector('.table:not(.mobile-cards)'))x.classList.add('wide-scroll')})}
function labelDynamicControls(root=document){root.querySelectorAll('input,select,textarea,button').forEach(el=>{if(el.getAttribute('aria-label')||el.getAttribute('aria-labelledby')||(el.labels&&el.labels.length))return;const ownText=el.matches('button')?el.textContent.trim():'';const label=ownText||el.closest('td')?.dataset.label||el.placeholder||el.textContent.trim();if(label)el.setAttribute('aria-label',label)})}
document.addEventListener('DOMContentLoaded',()=>{setMessageAccessibility();labelDynamicControls()});
document.addEventListener('keydown',event=>{if(event.key==='Escape')closeNav(true)});
