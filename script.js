const KEY="phishguard_cs03_v1";
const defaultState={events:[],quizScore:0,training:{},checks:{},theme:"dark",simulation:{clicks:0,reports:0}};
let state=loadState();

const pages={
 dashboard:"Security Dashboard",simulator:"Phishing Email Simulator",checker:"Suspicious Link Checker",
 training:"Security Training",quiz:"Phishing Awareness Quiz",reports:"Security Reports"
};

function loadState(){try{return {...defaultState,...JSON.parse(localStorage.getItem(KEY)||"{}")}}catch{return {...defaultState}}}
function save(){localStorage.setItem(KEY,JSON.stringify(state));}
function now(){return new Date().toLocaleString([], {dateStyle:"short",timeStyle:"short"});}
function toast(msg){const t=document.getElementById("toast");t.textContent=msg;t.classList.add("show");clearTimeout(window.tt);window.tt=setTimeout(()=>t.classList.remove("show"),2800)}
function addEvent(event,outcome,score){state.events.unshift({time:now(),event,outcome,score});state.events=state.events.slice(0,40);save();renderDashboard();renderReports()}
function go(page){document.querySelectorAll(".page").forEach(x=>x.classList.toggle("active",x.id===page));document.querySelectorAll(".nav-item").forEach(x=>x.classList.toggle("active",x.dataset.page===page));document.getElementById("pageTitle").textContent=pages[page];document.getElementById("sidebar").classList.remove("open");window.scrollTo({top:0,behavior:"smooth"});if(page==="dashboard")renderDashboard();if(page==="reports")renderReports()}
document.querySelectorAll(".nav-item").forEach(b=>b.addEventListener("click",()=>go(b.dataset.page)));
document.querySelectorAll("[data-go]").forEach(b=>b.addEventListener("click",()=>go(b.dataset.go)));
document.getElementById("mobileMenu").onclick=()=>document.getElementById("sidebar").classList.toggle("open");

function renderDashboard(){
  const sims=state.simulation||{clicks:0,reports:0};
  const total=sims.clicks+sims.reports;
  const clickRate=total?Math.round(sims.clicks/total*100):0;
  const reportRate=total?Math.round(sims.reports/total*100):0;
  document.getElementById("clickRate").textContent=clickRate+"%";
  document.getElementById("reportRate").textContent=reportRate+"%";
  document.getElementById("quizScore").textContent=(state.quizScore||0)+"%";
  const trainingDone=Object.values(state.training||{}).filter(Boolean).length;
  const awareness=Math.min(100,Math.round(reportRate*.35+(state.quizScore||0)*.35+trainingDone/4*30));
  document.getElementById("riskScore").textContent=Math.max(0,100-awareness);
  document.getElementById("recentEvents").innerHTML=(state.events||[]).slice(0,6).map(e=>`<tr><td>${esc(e.event)}</td><td class="${e.outcome.includes("Correct")||e.outcome.includes("Safe")?"result-good":e.outcome.includes("Risk")?"result-bad":"result-mid"}">${esc(e.outcome)}</td><td>${e.score}/100</td><td>${e.time}</td></tr>`).join("")||`<tr><td colspan="4">No activity yet. Start the simulator.</td></tr>`;
  document.querySelectorAll("[data-check]").forEach(c=>c.checked=!!state.checks[c.dataset.check]);
  renderChart();
}
function renderChart(){
  const vals=[25,42,31,55,46,68,Math.max(12,Math.min(92,(state.quizScore||0)+20))];
  document.getElementById("activityChart").innerHTML=vals.map((v,i)=>`<div class="bar-wrap"><div class="bar" style="height:${v}%"></div><span class="bar-label">${["M","T","W","T","F","S","S"][i]}</span></div>`).join("");
}
document.querySelectorAll("[data-check]").forEach(c=>c.addEventListener("change",()=>{state.checks[c.dataset.check]=c.checked;save();toast(c.checked?"Security control marked complete.":"Security control unchecked.");}));

document.getElementById("phishBtn").onclick=()=>{
 state.simulation.reports++;addEvent("Phishing simulation","Correct — reported",95);toast("Excellent. You identified and reported the simulation.");showModal("Correct response","This was a simulated phishing email. Reporting it is the safest response. Look for urgency, suspicious domains and unexpected login requests.");
};
document.getElementById("deleteBtn").onclick=()=>{
 state.simulation.reports++;addEvent("Phishing simulation","Correct — deleted",88);toast("Good decision. Reporting is even better.");showModal("Good decision","Deleting a suspicious email prevents accidental interaction. In a real organization, use the approved phishing-reporting process so security teams can investigate.");
};
function failedSimulation(){
 state.simulation.clicks++;addEvent("Phishing simulation","Risk — clicked link",25);toast("Simulation triggered: you clicked a phishing link.");showModal("This was a simulation","In a real attack, a malicious link could lead to credential theft or malware. Never enter a password after following an unexpected link. Close the page and report the message.");
}
document.getElementById("openBtn").onclick=failedSimulation;
document.getElementById("simLink").onclick=failedSimulation;

function analyzeUrl(raw){
  let input=raw.trim();if(!input)return null;
  let value=input.match(/^https?:\/\//i)?input:"https://"+input;
  let u;try{u=new URL(value)}catch{return {score:100,level:"Invalid",findings:["The value is not a valid URL."]}};
  let score=0,findings=[];
  if(u.protocol!=="https:"){score+=25;findings.push("No HTTPS encryption");}
  const host=u.hostname.toLowerCase();
  if(host.includes("xn--")){score+=25;findings.push("Punycode / look-alike domain");}
  if((host.match(/-/g)||[]).length>=3){score+=12;findings.push("Many hyphens in domain");}
  if((host.match(/\./g)||[]).length>=3){score+=12;findings.push("Unusually deep subdomains");}
  if(host.split(".").length>2 && /(login|verify|secure|account|update|support|microsoft|google|bank)/.test(host)){score+=20;findings.push("Sensitive keyword in subdomain");}
  if(/@/.test(u.href)){score+=20;findings.push("URL contains @ symbol");}
  if(u.port && !["80","443"].includes(u.port)){score+=10;findings.push("Non-standard port");}
  if(/[0-9]{7,}/.test(host)){score+=10;findings.push("Numeric-heavy hostname");}
  score=Math.min(100,score);
  return {score,level:score>=60?"High risk":score>=30?"Suspicious":"Lower risk",findings,host};
}
function showUrlResult(result){
 const box=document.getElementById("urlResult");box.classList.remove("hidden","safe","risky");box.classList.add(result.score>=30?"risky":"safe");
 box.innerHTML=`<div class="url-score">${result.score}/100</div><h3>${result.level}</h3><p class="muted">${result.host?`Analyzed domain: <b>${esc(result.host)}</b>`:"Unable to parse this URL."}</p><div class="findings">${result.findings.length?result.findings.map(x=>`<span class="finding ${result.score>=30?"bad":""}">${esc(x)}</span>`).join(""):`<span class="finding">No common heuristic red flags detected</span>`}</div><p class="muted" style="margin-bottom:0">This result is heuristic only. A low score does not guarantee that a website is safe.</p>`;
}
document.getElementById("checkUrl").onclick=()=>{const r=analyzeUrl(document.getElementById("urlInput").value);if(!r){toast("Enter a URL to analyze.");return}showUrlResult(r);addEvent("URL heuristic check",r.score>=30?"Risk indicators found":"Safe-looking result",100-r.score);};
document.querySelectorAll("[data-url]").forEach(b=>b.onclick=()=>{document.getElementById("urlInput").value=b.dataset.url;document.getElementById("checkUrl").click()});
document.getElementById("urlInput").addEventListener("keydown",e=>{if(e.key==="Enter")document.getElementById("checkUrl").click()});

const modules=[
["01","Spot the signs","Learn the five warning signs of a phishing message.","Look for urgency, unusual senders, unexpected links, requests for secrets and emotional pressure."],
["02","Safe link handling","Understand domains, HTTPS and deceptive URLs.","HTTPS is useful but not proof of legitimacy. Inspect the actual domain before trusting a link."],
["03","Credential protection","Learn how attackers target passwords and MFA.","Never submit credentials through an unexpected link. Use your normal bookmark or trusted app instead."],
["04","Report & respond","Know what to do after a suspicious message or click.","Stop interacting, report the message, tell the security team and follow your organization's incident process."]
];
function renderTraining(){
 document.getElementById("trainingGrid").innerHTML=modules.map((m,i)=>`<article class="card training-card"><span class="module-num">MODULE ${m[0]}</span><h3>${m[1]}</h3><p>${m[2]}</p><div class="progress"><i style="width:${state.training[i]?100:0}%"></i></div><button class="btn ${state.training[i]?"secondary":"primary"}" data-module="${i}">${state.training[i]?"Completed ✓":"Open lesson"}</button></article>`).join("");
 document.querySelectorAll("[data-module]").forEach(b=>b.onclick=()=>{const i=+b.dataset.module;state.training[i]=true;save();addEvent("Training module "+modules[i][0],"Completed",100);showModal(modules[i][1],`<p>${modules[i][3]}</p><p><b>Remember:</b> When something feels urgent or unusual, pause and verify using a trusted channel.</p>`);renderTraining();});
}
renderTraining();

const questions=[
{q:"You receive an unexpected email asking you to reset your password. What is the safest first action?",a:["Click the email button quickly","Open your normal company portal directly","Reply with your password","Forward it to friends"],c:1},
{q:"Which statement about HTTPS is correct?",a:["HTTPS guarantees a website is legitimate","HTTPS means the site is encrypted in transit, but it can still be malicious","HTTPS means the site belongs to a bank","HTTPS prevents phishing"],c:1},
{q:"What should you do with a suspicious work email?",a:["Click it to investigate","Report it using the approved security process","Send it to everyone","Enter fake credentials"],c:1},
{q:"An attacker asks for an MFA code over the phone. What should you do?",a:["Share it if they sound professional","Share only the first digits","Do not share it and verify the request independently","Post it in the company chat"],c:2},
{q:"Which is a common phishing red flag?",a:["An unexpected urgent request","A normal calendar event","A known internal contact you expected","A document you requested"],c:0}
];
let qIndex=0,qCorrect=0;
function renderQuiz(){
 const box=document.getElementById("quizBox");
 if(qIndex>=questions.length){const score=Math.round(qCorrect/questions.length*100);state.quizScore=score;save();addEvent("Security quiz","Completed — "+score+"%",score);box.innerHTML=`<div class="quiz-result"><span class="pill">QUIZ COMPLETE</span><strong>${score}%</strong><h3>${score>=80?"Excellent awareness":"Keep learning"}</h3><p class="muted">${score>=80?"You demonstrated strong phishing awareness.":"Review the training modules and try the quiz again."}</p><button class="btn primary" id="retryQuiz">Retake quiz</button></div>`;document.getElementById("retryQuiz").onclick=()=>{qIndex=0;qCorrect=0;renderQuiz()};return}
 const q=questions[qIndex];
 box.innerHTML=`<div class="quiz-progress"><i style="width:${qIndex/questions.length*100}%"></i></div><p class="eyebrow">QUESTION ${qIndex+1} OF ${questions.length}</p><div class="question">${q.q}</div><div class="answers">${q.a.map((x,i)=>`<button class="answer" data-answer="${i}">${x}</button>`).join("")}</div>`;
 document.querySelectorAll("[data-answer]").forEach(b=>b.onclick=()=>{const i=+b.dataset.answer;document.querySelectorAll(".answer").forEach(x=>x.disabled=true);b.classList.add(i===q.c?"correct":"wrong");if(i===q.c){qCorrect++;toast("Correct answer.")}else toast("Not quite — review the explanation.");setTimeout(()=>{qIndex++;renderQuiz()},700)});
}
renderQuiz();

function renderReports(){
 const sims=state.simulation||{clicks:0,reports:0};const total=sims.clicks+sims.reports;const reportRate=total?Math.round(sims.reports/total*100):0;const trainingDone=Object.values(state.training||{}).filter(Boolean).length;const awareness=Math.min(100,Math.round(reportRate*.35+(state.quizScore||0)*.35+trainingDone/4*30));const risk=100-awareness;
 document.getElementById("awarenessScore").textContent=awareness+"%";document.getElementById("awarenessBar").style.width=awareness+"%";document.getElementById("simRisk").textContent=risk;document.getElementById("riskBar").style.width=risk+"%";
 document.getElementById("auditLog").innerHTML=state.events.map(e=>`<tr><td>${e.time}</td><td>${esc(e.event)}</td><td>${esc(e.outcome)}</td><td>${e.score}/100</td></tr>`).join("")||`<tr><td colspan="4">No audit activity yet.</td></tr>`;
}
document.getElementById("exportBtn").onclick=()=>{
 const rows=[["Timestamp","Event","Outcome","Score"],...state.events.map(e=>[e.time,e.event,e.outcome,e.score])];
 const csv=rows.map(r=>r.map(v=>`"${String(v).replaceAll('"','""')}"`).join(",")).join("\n");
 const blob=new Blob([csv],{type:"text/csv"}),a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="phishguard-demo-report.csv";a.click();URL.revokeObjectURL(a.href);toast("CSV report exported.");
};

function showModal(title,body){document.getElementById("modalContent").innerHTML=`<h3>${title}</h3>${body}`;document.getElementById("modal").classList.remove("hidden")}
document.getElementById("modalClose").onclick=()=>document.getElementById("modal").classList.add("hidden");
document.getElementById("modal").addEventListener("click",e=>{if(e.target.id==="modal")e.currentTarget.classList.add("hidden")});

document.getElementById("themeBtn").onclick=()=>{state.theme=state.theme==="dark"?"light":"dark";document.body.classList.toggle("light",state.theme==="light");save()};
document.getElementById("resetBtn").onclick=()=>{if(confirm("Reset all local demo activity?")){localStorage.removeItem(KEY);location.reload()}};
function esc(s){return String(s).replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]))}
document.body.classList.toggle("light",state.theme==="light");
renderDashboard();renderReports();
