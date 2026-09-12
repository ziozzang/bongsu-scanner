package report

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
)

const pageSize = 200

func renderHTML(w io.Writer, d Document) error {
	rows := make([][]string, len(d.Findings))
	for i, f := range d.Findings {
		rows[i] = cells(f)
	}
	n := len(rows)
	if n > pageSize {
		n = pageSize
	}
	data := struct {
		Document   Document
		Fields     []field
		Severities []string
		Columns    []string
		Initial    [][]string
		Rows       [][]string
		Compressed string
	}{d, headerFields(d), severities, columns, rows[:n], rows, ""}
	if len(rows) > 10000 {
		var b bytes.Buffer
		gz := gzip.NewWriter(&b)
		payload := struct {
			Rows     [][]string `json:"rows"`
			Packages []Package  `json:"packages"`
		}{rows, d.Packages}
		if err := json.NewEncoder(gz).Encode(payload); err != nil {
			return err
		}
		if err := gz.Close(); err != nil {
			return err
		}
		data.Compressed = base64.StdEncoding.EncodeToString(b.Bytes())
		data.Rows = nil
		if len(data.Document.Packages) > 50 {
			data.Document.Packages = data.Document.Packages[:50]
		}
	}
	return htmlPage.Execute(w, data)
}

var htmlPage = template.Must(template.New("report").Funcs(template.FuncMap{"join": func(p Package) string { return p.Name + " (" + p.Ecosystem + ")" }}).Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Vulnerability report — {{.Document.Target}}</title>
<style>
:root{color-scheme:light dark;--bg:#fafbfc;--fg:#17212b;--panel:#fff;--line:#cad2dc;--accent:#1659ac}*{box-sizing:border-box}body{overflow-wrap:anywhere;margin:auto;padding:24px;max-width:1600px;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}h1{font-size:28px}h2{margin-top:28px}a{color:var(--accent)}dl{display:grid;grid-template-columns:minmax(130px,180px) 1fr;gap:5px 16px}dt{font-weight:600}dd{margin:0;overflow-wrap:anywhere}.panel,details{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;margin:8px 0}.scroll{overflow:auto;max-height:75vh}table{border-collapse:collapse;width:100%}td,th{padding:8px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);max-width:380px;overflow-wrap:anywhere;min-width:90px}th{position:sticky;top:0;background:var(--panel)}button,input{font:inherit;color:inherit;background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:6px}button,summary{cursor:pointer}fieldset{min-width:0}label{display:inline-block;margin:5px}.severity{display:inline-block;margin:5px;padding:8px;border:1px solid var(--line);border-radius:5px}[data-severity="CRITICAL"],[data-severity="HIGH"]{font-weight:700}#query{width:min(100%,450px)}#status{min-height:24px}.package-counts{display:flex;gap:12px;flex-wrap:wrap}.package-counts span{white-space:nowrap}@media(prefers-color-scheme:dark){:root{--bg:#101820;--fg:#e3e9f0;--panel:#18232e;--line:#405267;--accent:#8cbfff}}@media(max-width:650px){body{padding:12px}dl{grid-template-columns:1fr}dd{margin-bottom:10px}h1{font-size:22px}}
</style></head><body>
<h1>Vulnerability report: {{.Document.Target}}</h1>
<details class="panel" open><summary>Report context and scan completeness</summary><dl>{{range .Fields}}<dt>{{.Name}}</dt><dd>{{.Value}}</dd>{{end}}</dl></details>
<h2>Summary</h2><p>{{.Document.Summary.Subjects}} subjects · {{.Document.Summary.Matched}} matched packages · {{.Document.Summary.Findings}} findings</p>
<div>{{range .Severities}}<span class="severity">{{.}}: {{index $.Document.Summary.BySeverity .}}</span>{{end}}</div>
<h2>Top 20 packages by critical/high</h2><ol>{{range .Document.TopPackages}}<li>{{join .}} — CRITICAL {{index .BySeverity "CRITICAL"}}, HIGH {{index .BySeverity "HIGH"}}</li>{{else}}<li>No critical/high findings.</li>{{end}}</ol>
<h2>Findings</h2><div class="panel"><label for="query">Text filter</label><input id="query" type="search" placeholder="Package, vulnerability, summary…"><fieldset id="severity-filters"><legend>Severity filters</legend>{{range .Severities}}<label><input type="checkbox" value="{{.}}" checked> {{.}}</label>{{end}}</fieldset><button id="clear" type="button">Clear package filter</button><p id="status" role="status">First {{len .Initial}} findings shown; enable JavaScript for filtering and more rows.</p></div>
<div class="scroll"><table id="findings"><thead><tr>{{range $i,$col:=.Columns}}<th scope="col"><button type="button" data-sort="{{$i}}">{{$col}}</button></th>{{end}}</tr></thead><tbody>{{range .Initial}}<tr data-severity="{{index . 5}}">{{range $i,$cell:=.}}<td>{{if eq $i 12}}{{/* URLs are space-separated only in the compact data; JS turns them into links. */}}{{$cell}}{{else}}{{$cell}}{{end}}</td>{{end}}</tr>{{end}}</tbody></table></div><button id="more" type="button" hidden>Show more (200)</button>
<h2>Per-package rollup</h2><p>Worst fix version is the highest comparable reported fix in this ecosystem/release. It is not a guarantee that every advisory is fixed.</p>
<div id="packages">{{range $p:=.Document.Packages}}<details class="package"><summary>{{join .}}</summary><div class="package-counts">{{range $s:=$.Severities}}<span>{{$s}} {{index $p.BySeverity $s}}</span>{{end}}</div><p>Worst fix version: {{.WorstFix}} · Findings without fix: {{.Unfixed}} {{.FixNote}}</p><button type="button" data-package="{{.Name}}" data-ecosystem="{{.Ecosystem}}">View package findings</button></details>{{end}}</div>
<noscript><p>JavaScript is required to show all findings. Export JSON or CSV for a complete machine-readable report.</p></noscript>
<script>
'use strict';
(async()=>{
const status=document.getElementById('status'),tbody=document.querySelector('#findings tbody'),more=document.getElementById('more');
try {
let rows={{.Rows}};
const compressed={{.Compressed}};
if(compressed){if(typeof DecompressionStream==='undefined')throw new Error('This large report requires a browser with DecompressionStream (current Chrome, Firefox, Safari or Edge). Export JSON/CSV if unavailable.');const bytes=Uint8Array.from(atob(compressed),c=>c.charCodeAt(0));const payload=JSON.parse(await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))).text());rows=payload.rows;const groups=document.getElementById('packages'),fragment=document.createDocumentFragment();for(const p of payload.packages){const details=document.createElement('details'),summary=document.createElement('summary'),counts=document.createElement('p'),fix=document.createElement('p'),button=document.createElement('button');details.className='package';summary.textContent=p.package+' ('+p.ecosystem+')';counts.textContent=Object.entries(p.by_severity).map(([s,n])=>s+' '+n).join(' · ');fix.textContent='Worst fix version: '+p.worst_fix_version+' · Findings without fix: '+p.findings_without_fix+' '+(p.fix_note||'');button.type='button';button.dataset.package=p.package;button.dataset.ecosystem=p.ecosystem;button.textContent='View package findings';details.append(summary,counts,fix,button);fragment.append(details);}groups.replaceChildren(fragment);}
rows=rows||[];
let selected=[],shown=0,sort=-1,direction=1,pkg=null;
const ranks={CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,NEGLIGIBLE:1,UNKNOWN:0};
function append(){const stop=Math.min(shown+200,selected.length),fragment=document.createDocumentFragment();for(;shown<stop;shown++){const r=selected[shown],tr=document.createElement('tr');tr.dataset.severity=r[5];r.forEach((value,i)=>{const td=document.createElement('td');if(i===12){for(const u of value.split(' ').filter(Boolean)){try{const url=new URL(u);if(url.protocol!=='https:'&&url.protocol!=='http:')continue;const a=document.createElement('a');a.href=url.href;a.rel='noreferrer';a.textContent=u;td.append(a,document.createElement('br'));}catch{}}}else{td.textContent=value;}tr.append(td);});fragment.append(tr);}tbody.append(fragment);more.hidden=shown>=selected.length;status.textContent=shown+' of '+selected.length+' matching findings shown ('+rows.length+' total)'+(pkg?' — '+pkg[0]:'');}
function refresh(){const q=document.getElementById('query').value.toLowerCase(),allowed=new Set(Array.from(document.querySelectorAll('#severity-filters input:checked'),x=>x.value));selected=rows.filter(r=>allowed.has(r[5])&&(!pkg||(r[0]===pkg[0]&&r[2]===pkg[1]))&&(!q||r.some(v=>v.toLowerCase().includes(q))));if(sort>=0)selected.sort((a,b)=>direction*(sort===5?ranks[a[5]]-ranks[b[5]]:sort===6?Number(a[6])-Number(b[6]):a[sort].localeCompare(b[sort])));tbody.replaceChildren();shown=0;append();}
let timer;document.getElementById('query').addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(refresh,120);});document.getElementById('severity-filters').addEventListener('change',refresh);more.addEventListener('click',append);document.getElementById('clear').addEventListener('click',()=>{pkg=null;refresh();});document.querySelectorAll('[data-sort]').forEach(b=>b.addEventListener('click',()=>{const i=Number(b.dataset.sort);direction=sort===i?-direction:(i===5||i===6?-1:1);sort=i;refresh();}));document.querySelectorAll('[data-package]').forEach(b=>b.addEventListener('click',()=>{pkg=[b.dataset.package,b.dataset.ecosystem];document.getElementById('query').value='';refresh();document.getElementById('query').scrollIntoView();}));refresh();
}catch(e){status.textContent='Unable to load all findings: '+e.message;}
})();
</script></body></html>`))
