const form=document.getElementById("analyze-form");
const fileInput=document.getElementById("file-input");
const dropzone=document.getElementById("dropzone");
const dropzoneBody=document.getElementById("dropzone-body");
const statusEl=document.getElementById("status");
const submitBtn=document.getElementById("submit-btn");
const results=document.getElementById("results");

dropzone.addEventListener("click",()=>fileInput.click());
["dragenter","dragover"].forEach(e=>dropzone.addEventListener(e,x=>{x.preventDefault();dropzone.classList.add("dragover")}));
["dragleave","drop"].forEach(e=>dropzone.addEventListener(e,x=>{x.preventDefault();dropzone.classList.remove("dragover")}));
dropzone.addEventListener("drop",e=>{if(e.dataTransfer.files.length){fileInput.files=e.dataTransfer.files;updateLabel()}});
fileInput.addEventListener("change",updateLabel);

function updateLabel(){
 if(fileInput.files.length) dropzoneBody.innerHTML=`<p class="dropzone-title">${fileInput.files[0].name}</p><p class="dropzone-sub">Click to choose a different file</p>`;
}
function status(message,error=false){statusEl.textContent=message;statusEl.classList.toggle("error",error)}

form.addEventListener("submit",async e=>{
 e.preventDefault();
 if(!fileInput.files.length)return status("Choose a file first.",true);
 const data=new FormData(form);
 submitBtn.disabled=true;status("Running analysis...");
 try{
  const response=await fetch("/analyze",{method:"POST",body:data});
  const result=await response.json();
  if(!response.ok){results.hidden=true;return status(result.error||"Something went wrong.",true)}
  render(result);status(`Done. Parsed ${result.total_entries} entries.`);
 }catch(err){status("Could not reach the server. Is it running?",true)}
 finally{submitBtn.disabled=false}
});

function render(data){
 results.hidden=false;
 document.getElementById("stat-total").textContent=data.total_entries;
 document.getElementById("stat-ips").textContent=data.flagged_ips.length;
 document.getElementById("stat-users").textContent=data.flagged_users.length;
 fill("ip-table","ip-empty",data.flagged_ips,"ip");
 fill("user-table","user-empty",data.flagged_users,"username");
 document.getElementById("report-text").textContent=data.report_text;
 document.getElementById("download-csv").style.display=data.csv_available?"inline":"none";
}
function fill(tableId,emptyId,rows,key){
 const table=document.getElementById(tableId), body=table.querySelector("tbody"), empty=document.getElementById(emptyId);
 body.innerHTML="";
 if(!rows.length){table.style.display="none";empty.hidden=false;return}
 table.style.display="table";empty.hidden=true;
 rows.slice().sort((a,b)=>b.failed-a.failed).forEach(row=>{
  const tr=document.createElement("tr");
  const a=document.createElement("td"),b=document.createElement("td");
  a.textContent=row[key];b.textContent=row.failed;tr.append(a,b);body.appendChild(tr);
 });
}
