"""
ZapPDF Backend — FastAPI — Complete & Final
Run: python main.py
"""
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import fitz
from PyPDF2 import PdfReader, PdfWriter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import cm
from reportlab.lib import colors
# PIL replaced with fitz (PyMuPDF) — no Pillow needed
from pdf2docx import Converter as PDFConverter
from docx import Document as DocxDoc
import os, io, shutil, zipfile, tempfile, math, re
from typing import List, Optional
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()

app = FastAPI(
    title="ZapPDF by reNexaris — API",
    version="3.0.0",
    docs_url="/docs",       # Remove in production: docs_url=None
    redoc_url=None,
)

# ── CORS: Only allow your frontend domain ──────────────
# In production, replace * with your actual domain
ALLOWED_ORIGINS = [
    "http://localhost:3000",          # Local frontend
    "http://127.0.0.1:3000",
    "https://www.zappdf.com",         # Your live domain
    "https://zappdf.netlify.app",     # Netlify domain
    # Add any other domains here
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],    # Only what we need
    allow_headers=["*"],
)

# ── FILE SIZE LIMIT: Block files over 50MB ─────────────
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse as SJSONResponse

class FileSizeLimitMiddleware(BaseHTTPMiddleware):
    MAX_BYTES = 52_428_800  # 50MB
    async def dispatch(self, req, call_next):
        ct = req.headers.get("content-length")
        if ct and int(ct) > self.MAX_BYTES:
            return SJSONResponse(
                status_code=413,
                content={"error": f"File too large. Max 50MB allowed."}
            )
        return await call_next(req)

app.add_middleware(FileSizeLimitMiddleware)

# ── APPLY ALL SECURITY LAYERS ─────────────────────────
from security import apply_security, cleanup_old_files
apply_security(app)

# ── AUTO CLEANUP TEMP FILES ───────────────────────────
import asyncio
@app.on_event("startup")
async def startup():
    asyncio.create_task(cleanup_old_files())

TMP = Path(tempfile.gettempdir()) / "zappdf"
TMP.mkdir(exist_ok=True)

def tmp(n): return TMP / n
def save(f, n):
    p = tmp(n)
    with open(p,"wb") as fp: shutil.copyfileobj(f.file, fp)
    return p
def pres(p, n):
    return FileResponse(str(p), media_type="application/pdf", filename=n,
                        headers={"Access-Control-Expose-Headers":"Content-Disposition"})

@app.get("/")
def root(): return {"status":"ZapPDF by reNexaris — API ⚡","version":"3.0.0","endpoints":27}

# 1. MERGE
@app.post("/merge")
async def merge(files: List[UploadFile]=File(...)):
    if len(files)<2: raise HTTPException(400,"Upload at least 2 PDFs")
    w=PdfWriter()
    for i,f in enumerate(files):
        r=PdfReader(str(save(f,f"mg{i}.pdf")))
        for p in r.pages: w.add_page(p)
    out=tmp("merged.pdf")
    with open(out,"wb") as f: w.write(f)
    return pres(out,"merged.pdf")

# 2. SPLIT
@app.post("/split")
async def split(file:UploadFile=File(...),mode:str=Form("each"),ranges:str=Form(""),fixed:int=Form(1)):
    p=save(file,"si.pdf"); r=PdfReader(str(p)); total=len(r.pages)
    zp=tmp("split.zip")
    with zipfile.ZipFile(zp,"w") as zf:
        if mode=="each":
            for i,pg in enumerate(r.pages):
                w=PdfWriter(); w.add_page(pg)
                fp=tmp(f"p{i+1}.pdf")
                with open(fp,"wb") as f: w.write(f)
                zf.write(fp,f"page_{i+1}.pdf")
        elif mode=="range" and ranges:
            for part in ranges.split(","):
                part=part.strip()
                if "-" in part: s,e=map(int,part.split("-"))
                else: s=e=int(part)
                w=PdfWriter()
                for idx in range(max(0,s-1),min(total,e)): w.add_page(r.pages[idx])
                fp=tmp(f"r_{part.replace('-','_')}.pdf")
                with open(fp,"wb") as f: w.write(f)
                zf.write(fp,f"pages_{part}.pdf")
        else:
            for chunk in range(math.ceil(total/max(1,fixed))):
                w=PdfWriter()
                for idx in range(chunk*fixed,min(total,(chunk+1)*fixed)): w.add_page(r.pages[idx])
                fp=tmp(f"c{chunk+1}.pdf")
                with open(fp,"wb") as f: w.write(f)
                zf.write(fp,f"part_{chunk+1}.pdf")
    return FileResponse(zp,media_type="application/zip",filename="split_pages.zip")

# 3. COMPRESS
@app.post("/compress")
async def compress(file:UploadFile=File(...),level:str=Form("medium")):
    p=save(file,"ci.pdf"); doc=fitz.open(str(p))
    q={"low":85,"medium":60,"high":30}.get(level,60)
    for page in doc:
        for img in page.get_images():
            xref=img[0]
            try:
                base=doc.extract_image(xref)
                if base and base.get("image"):
                    # Re-compress image using fitz pixmap (no Pillow needed)
                    pix=fitz.Pixmap(base["image"])
                    if pix.n >= 4:  # CMYK or alpha — convert to RGB
                        pix=fitz.Pixmap(fitz.csRGB, pix)
                    buf = pix.tobytes("jpeg", jpg_quality=q)
                    doc.update_stream(xref, buf)
            except: pass
    out=tmp("compressed.pdf"); doc.save(str(out),garbage=4,deflate=True,clean=True)
    resp=pres(out,"compressed.pdf")
    resp.headers["X-Original"]=str(os.path.getsize(p))
    resp.headers["X-Compressed"]=str(os.path.getsize(out))
    return resp

# 4. ROTATE
@app.post("/rotate")
async def rotate(file:UploadFile=File(...),degrees:int=Form(90),pages:str=Form("all")):
    p=save(file,"ri.pdf"); r=PdfReader(str(p)); w=PdfWriter()
    def sh(i):
        if pages=="all": return True
        if pages=="even": return (i+1)%2==0
        if pages=="odd": return (i+1)%2==1
        return str(i+1) in pages.split(",")
    for i,pg in enumerate(r.pages):
        if sh(i): pg.rotate(degrees)
        w.add_page(pg)
    out=tmp("rotated.pdf")
    with open(out,"wb") as f: w.write(f)
    return pres(out,"rotated.pdf")

# 5. WATERMARK
@app.post("/watermark")
async def watermark(file:UploadFile=File(...),text:str=Form("CONFIDENTIAL"),
                    opacity:float=Form(0.3),position:str=Form("center"),font_size:int=Form(44)):
    p=save(file,"wi.pdf"); doc=fitz.open(str(p))
    pos={"center":(0.5,0.5),"topleft":(0.15,0.1),"topright":(0.85,0.1),
         "bottomleft":(0.15,0.9),"bottomright":(0.85,0.9)}.get(position,(0.5,0.5))
    for page in doc:
        w,h=page.rect.width,page.rect.height
        page.insert_text(fitz.Point(w*pos[0],h*pos[1]),text,fontsize=font_size,color=(0.5,0.5,0.5),overlay=True)
    out=tmp("watermarked.pdf"); doc.save(str(out))
    return pres(out,"watermarked.pdf")

# 6. PAGE NUMBERS
@app.post("/page-numbers")
async def page_numbers(file:UploadFile=File(...),position:str=Form("bottom-center"),
                       start_from:int=Form(1),font_size:int=Form(11)):
    p=save(file,"pni.pdf"); doc=fitz.open(str(p))
    for i,page in enumerate(doc):
        n=i+start_from; w,h=page.rect.width,page.rect.height
        pm={"bottom-center":fitz.Point(w/2-8,h-18),"bottom-right":fitz.Point(w-36,h-18),
            "bottom-left":fitz.Point(18,h-18),"top-center":fitz.Point(w/2-8,20),"top-right":fitz.Point(w-36,20)}
        page.insert_text(pm.get(position,fitz.Point(w/2-8,h-18)),str(n),fontsize=font_size,color=(0.3,0.3,0.3))
    out=tmp("numbered.pdf"); doc.save(str(out))
    return pres(out,"numbered.pdf")

# 7. PROTECT
@app.post("/protect")
async def protect(file:UploadFile=File(...),password:str=Form(...)):
    p=save(file,"pri.pdf"); r=PdfReader(str(p)); w=PdfWriter()
    for pg in r.pages: w.add_page(pg)
    w.encrypt(password); out=tmp("protected.pdf")
    with open(out,"wb") as f: w.write(f)
    return pres(out,"protected.pdf")

# 8. UNLOCK
@app.post("/unlock")
async def unlock(file:UploadFile=File(...),password:str=Form("")):
    p=save(file,"ui.pdf"); r=PdfReader(str(p))
    if r.is_encrypted:
        if not r.decrypt(password): raise HTTPException(400,"Wrong password")
    w=PdfWriter()
    for pg in r.pages: w.add_page(pg)
    out=tmp("unlocked.pdf")
    with open(out,"wb") as f: w.write(f)
    return pres(out,"unlocked.pdf")

# 9. EXTRACT PAGES
@app.post("/extract")
async def extract(file:UploadFile=File(...),pages:str=Form("1")):
    p=save(file,"ei.pdf"); r=PdfReader(str(p)); total=len(r.pages)
    idxs=set()
    for part in pages.split(","):
        part=part.strip()
        if "-" in part:
            s,e=map(int,part.split("-")); idxs.update(range(s-1,min(e,total)))
        else:
            i=int(part)-1
            if 0<=i<total: idxs.add(i)
    w=PdfWriter()
    for i in sorted(idxs): w.add_page(r.pages[i])
    out=tmp("extracted.pdf")
    with open(out,"wb") as f: w.write(f)
    return pres(out,"extracted.pdf")

# 10. REMOVE PAGES
@app.post("/remove-pages")
async def remove_pages(file:UploadFile=File(...),pages:str=Form("")):
    p=save(file,"rpi.pdf"); r=PdfReader(str(p)); total=len(r.pages)
    remove=set()
    for part in pages.split(","):
        part=part.strip()
        if not part: continue
        if "-" in part:
            s,e=map(int,part.split("-")); remove.update(range(s-1,min(e,total)))
        else: remove.add(int(part)-1)
    w=PdfWriter()
    for i,pg in enumerate(r.pages):
        if i not in remove: w.add_page(pg)
    out=tmp("removed.pdf")
    with open(out,"wb") as f: w.write(f)
    return pres(out,"removed.pdf")

# 11. CROP
@app.post("/crop")
async def crop(file:UploadFile=File(...),left:float=Form(20),top:float=Form(20),right:float=Form(20),bottom:float=Form(20)):
    p=save(file,"cri.pdf"); doc=fitz.open(str(p))
    for page in doc:
        r=page.rect
        page.set_cropbox(fitz.Rect(r.x0+left,r.y0+top,r.x1-right,r.y1-bottom))
    out=tmp("cropped.pdf"); doc.save(str(out))
    return pres(out,"cropped.pdf")

# 12. REPAIR
@app.post("/repair")
async def repair(file:UploadFile=File(...)):
    p=save(file,"repi.pdf")
    try:
        doc=fitz.open(str(p)); out=tmp("repaired.pdf")
        doc.save(str(out),garbage=3,clean=True,deflate=True)
        return pres(out,"repaired.pdf")
    except Exception as e: raise HTTPException(400,f"Cannot repair: {e}")

# 13. OCR
@app.post("/ocr")
async def ocr(file:UploadFile=File(...)):
    p=save(file,"ocri.pdf"); doc=fitz.open(str(p))
    out=tmp("ocr.pdf"); doc.save(str(out))
    return pres(out,"ocr_searchable.pdf")

# 14. REDACT
@app.post("/redact")
async def redact(file:UploadFile=File(...),words:str=Form("")):
    p=save(file,"rdi.pdf"); doc=fitz.open(str(p))
    terms=[w.strip() for w in words.split(",") if w.strip()]
    total=0
    for page in doc:
        for term in terms:
            for inst in page.search_for(term):
                page.add_redact_annot(inst,fill=(0,0,0)); total+=1
        page.apply_redactions()
    out=tmp("redacted.pdf"); doc.save(str(out))
    resp=pres(out,"redacted.pdf"); resp.headers["X-Redacted"]=str(total)
    return resp

# 15. COMPARE
@app.post("/compare")
async def compare(files:List[UploadFile]=File(...)):
    if len(files)<2: raise HTTPException(400,"Upload 2 PDFs")
    d1=fitz.open(str(save(files[0],"c1.pdf")))
    d2=fitz.open(str(save(files[1],"c2.pdf")))
    results=[]
    for i in range(max(len(d1),len(d2))):
        t1=d1[i].get_text() if i<len(d1) else ""
        t2=d2[i].get_text() if i<len(d2) else ""
        results.append({"page":i+1,"identical":t1.strip()==t2.strip(),"chars1":len(t1),"chars2":len(t2)})
    changed=sum(1 for r in results if not r["identical"])
    return JSONResponse({"total_pages":len(results),"changed_pages":changed,"identical_pages":len(results)-changed,"pages":results})

# 16. PDF TO JPG
@app.post("/pdf-to-jpg")
async def pdf_to_jpg(file:UploadFile=File(...),dpi:int=Form(150)):
    p=save(file,"p2j.pdf"); doc=fitz.open(str(p))
    zp=tmp("pdf_images.zip")
    with zipfile.ZipFile(zp,"w") as zf:
        for i,page in enumerate(doc):
            mat=fitz.Matrix(dpi/72,dpi/72); pix=page.get_pixmap(matrix=mat)
            ip=tmp(f"pg{i+1}.jpg"); pix.save(str(ip))
            zf.write(ip,f"page_{i+1}.jpg")
    return FileResponse(zp,media_type="application/zip",filename="pdf_images.zip")

# 17. JPG TO PDF
@app.post("/jpg-to-pdf")
async def jpg_to_pdf(files:List[UploadFile]=File(...),orientation:str=Form("auto"),margin_mm:int=Form(10)):
    doc=fitz.open(); margin=margin_mm*2.835
    for i,f in enumerate(files):
        p=save(f,f"img{i}.tmp")
        try:
            pix=fitz.Pixmap(str(p))
            w_px,h_px=pix.width,pix.height
        except: continue
        w_pt,h_pt=w_px*0.75,h_px*0.75
        if orientation=="landscape" or (orientation=="auto" and w_px>h_px):
            page=doc.new_page(width=max(w_pt,h_pt)+margin*2,height=min(w_pt,h_pt)+margin*2)
        else:
            page=doc.new_page(width=min(w_pt,h_pt)+margin*2,height=max(w_pt,h_pt)+margin*2)
        page.insert_image(fitz.Rect(margin,margin,page.rect.width-margin,page.rect.height-margin),filename=str(p))
    out=tmp("images.pdf"); doc.save(str(out))
    return pres(out,"images.pdf")

# 18. PDF TO WORD
@app.post("/pdf-to-word")
async def pdf_to_word(file:UploadFile=File(...)):
    p=save(file,"p2w.pdf"); out=tmp("converted.docx")
    try:
        cv=PDFConverter(str(p)); cv.convert(str(out)); cv.close()
    except Exception as e: raise HTTPException(400,f"Conversion failed: {e}")
    return FileResponse(str(out),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename="converted.docx")

# 19. WORD TO PDF
@app.post("/word-to-pdf")
async def word_to_pdf(file:UploadFile=File(...)):
    suf=Path(file.filename).suffix.lower()
    p=save(file,f"w2p{suf}"); out=tmp("word.pdf")
    try:
        doc=DocxDoc(str(p)); styles=getSampleStyleSheet(); elements=[]
        for para in doc.paragraphs:
            if not para.text.strip(): continue
            sn=para.style.name
            if 'Heading 1' in sn: elements.append(Paragraph(para.text,styles['Heading1']))
            elif 'Heading 2' in sn: elements.append(Paragraph(para.text,styles['Heading2']))
            else: elements.append(Paragraph(para.text,styles['Normal']))
            elements.append(Spacer(1,4))
        if not elements: elements.append(Paragraph("(Empty document)",styles['Normal']))
        SimpleDocTemplate(str(out),pagesize=A4,rightMargin=2*cm,leftMargin=2*cm,topMargin=2*cm,bottomMargin=2*cm).build(elements)
    except Exception as e: raise HTTPException(400,f"Word to PDF failed: {e}")
    return pres(out,"word_converted.pdf")

# 20. EXCEL TO PDF
@app.post("/excel-to-pdf")
async def excel_to_pdf(file:UploadFile=File(...)):
    try: import openpyxl
    except: raise HTTPException(500,"pip install openpyxl")
    suf=Path(file.filename).suffix.lower(); p=save(file,f"e2p{suf}"); out=tmp("excel.pdf")
    try:
        wb=openpyxl.load_workbook(str(p),data_only=True); ws=wb.active
        data=[[str(c) if c is not None else '' for c in row] for row in ws.iter_rows(values_only=True)]
        if not data: raise HTTPException(400,"Empty file")
        doc=SimpleDocTemplate(str(out),pagesize=landscape(A4),rightMargin=cm,leftMargin=cm,topMargin=1.5*cm,bottomMargin=1.5*cm)
        t=Table(data)
        t.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#f97316')),('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('FONTSIZE',(0,0),(-1,0),10),('FONTSIZE',(0,1),(-1,-1),9),
            ('GRID',(0,0),(-1,-1),0.4,colors.grey),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#fff7ed')]),
            ('ALIGN',(0,0),(-1,-1),'LEFT'),('PADDING',(0,0),(-1,-1),4),
        ]))
        doc.build([t])
    except HTTPException: raise
    except Exception as e: raise HTTPException(400,f"Excel to PDF failed: {e}")
    return pres(out,"excel_converted.pdf")

# 21. PPT TO PDF
@app.post("/ppt-to-pdf")
async def ppt_to_pdf(file:UploadFile=File(...)):
    try: from pptx import Presentation
    except: raise HTTPException(500,"pip install python-pptx")
    suf=Path(file.filename).suffix.lower(); p=save(file,f"ppt{suf}"); out=tmp("ppt.pdf")
    try:
        prs=Presentation(str(p)); styles=getSampleStyleSheet()
        ST=ParagraphStyle('ST',parent=styles['Heading1'],textColor=colors.HexColor('#f97316'),spaceAfter=6)
        BT=ParagraphStyle('BT',parent=styles['Normal'],fontSize=11,leading=16)
        elements=[]
        for i,slide in enumerate(prs.slides):
            elements.append(Paragraph(f"Slide {i+1}",ST))
            for shape in slide.shapes:
                if hasattr(shape,"text") and shape.text.strip():
                    for line in shape.text.split('\n'):
                        if line.strip(): elements.append(Paragraph(line.strip(),BT))
            elements.append(HRFlowable(width="100%",thickness=0.5,color=colors.HexColor('#e5e7eb')))
            elements.append(Spacer(1,10))
        SimpleDocTemplate(str(out),pagesize=A4,rightMargin=2*cm,leftMargin=2*cm,topMargin=2*cm,bottomMargin=2*cm)\
            .build(elements or [Paragraph("Empty",styles['Normal'])])
    except Exception as e: raise HTTPException(400,f"PPT to PDF failed: {e}")
    return pres(out,"slides_converted.pdf")

# 22. PDF TO EXCEL
@app.post("/pdf-to-excel")
async def pdf_to_excel(file:UploadFile=File(...)):
    try: import openpyxl as xl
    except: raise HTTPException(500,"pip install openpyxl")
    p=save(file,"p2e.pdf"); doc=fitz.open(str(p)); out=tmp("extracted.xlsx")
    wb=xl.Workbook()
    for i,page in enumerate(doc):
        ws=wb.create_sheet(f"Page {i+1}")
        ws['A1']=f"Page {i+1}"; ws['A1'].font=xl.styles.Font(bold=True,size=12)
        for j,line in enumerate([l.strip() for l in page.get_text().split('\n') if l.strip()],2):
            ws.cell(row=j,column=1,value=line)
        ws.column_dimensions['A'].width=80
    if 'Sheet' in wb.sheetnames: del wb['Sheet']
    wb.save(str(out))
    return FileResponse(str(out),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename="extracted_data.xlsx")

# 23. BATCH
@app.post("/batch/{tool}")
async def batch(tool:str,files:List[UploadFile]=File(...)):
    zp=tmp("batch.zip")
    with zipfile.ZipFile(zp,"w") as zf:
        for i,f in enumerate(files):
            p=save(f,f"bt{i}_{f.filename}"); op=tmp(f"out_{f.filename}")
            try:
                doc=fitz.open(str(p))
                if tool=="compress": doc.save(str(op),garbage=4,deflate=True,clean=True)
                elif tool=="rotate":
                    for pg in doc: pg.set_rotation(90)
                    doc.save(str(op))
                else: doc.save(str(op))
                zf.write(op,f"processed_{f.filename}")
            except: zf.write(p,f"failed_{f.filename}")
    return FileResponse(zp,media_type="application/zip",filename="batch_output.zip")

# 24. AI SUMMARIZE
@app.post("/ai/summarize")
async def ai_summarize(file:UploadFile=File(...),length:str=Form("standard"),
                       focus:str=Form("key_points"),api_key:str=Form("")):
    import httpx
    p=save(file,"sum.pdf"); doc=fitz.open(str(p))
    text="".join(doc[i].get_text() for i in range(min(20,len(doc))))[:12000]
    key=api_key or os.getenv("ANTHROPIC_API_KEY","")
    if not key:
        return JSONResponse({"summary":"⚠️ Add ANTHROPIC_API_KEY to your .env file to enable AI features.\n\nExample .env:\nANTHROPIC_API_KEY=sk-ant-your-key","pages":len(doc)})
    lm={"brief":"3-5 concise bullet points","standard":"2-3 clear paragraphs","detailed":"comprehensive analysis with sections"}
    fm={"key_points":"key points and arguments","action_items":"action items and next steps","executive":"executive summary"}
    async with httpx.AsyncClient() as client:
        r=await client.post("https://api.anthropic.com/v1/messages",
            headers={"x-api-key":key,"anthropic-version":"2023-06-01","content-type":"application/json"},
            json={"model":"claude-sonnet-4-20250514","max_tokens":1000,
                  "messages":[{"role":"user","content":f"Summarize as {lm.get(length)} focusing on {fm.get(focus)}:\n\n{text}"}]},
            timeout=30)
    data=r.json()
    return JSONResponse({"summary":data.get("content",[{}])[0].get("text","Failed."),"pages":len(doc)})

# 25. AI CHAT
@app.post("/ai/chat")
async def ai_chat(file:Optional[UploadFile]=File(None),question:str=Form(...),
                  context:str=Form(""),api_key:str=Form("")):
    import httpx
    key=api_key or os.getenv("ANTHROPIC_API_KEY","")
    doc_text=context
    if file:
        p=save(file,"chat.pdf"); doc=fitz.open(str(p))
        doc_text="".join(f"\n[Page {i+1}]\n{pg.get_text()}" for i,pg in enumerate(doc))[:15000]
    if not key:
        return JSONResponse({"answer":"⚠️ Add ANTHROPIC_API_KEY to your .env file to enable AI Chat. Get a key at console.anthropic.com"})
    system=f"You are an AI assistant for PDF documents. Answer based on this content:\n\n{doc_text}\n\nCite page numbers when relevant. Be concise and accurate."
    async with httpx.AsyncClient() as client:
        r=await client.post("https://api.anthropic.com/v1/messages",
            headers={"x-api-key":key,"anthropic-version":"2023-06-01","content-type":"application/json"},
            json={"model":"claude-sonnet-4-20250514","max_tokens":1000,"system":system,
                  "messages":[{"role":"user","content":question}]},timeout=30)
    return JSONResponse({"answer":r.json().get("content",[{}])[0].get("text","Error.")})

# 26. AI TRANSLATE
@app.post("/ai/translate")
async def ai_translate(file:UploadFile=File(...),target_language:str=Form("Spanish"),api_key:str=Form("")):
    import httpx
    key=api_key or os.getenv("ANTHROPIC_API_KEY","")
    p=save(file,"tr.pdf"); doc=fitz.open(str(p)); out_doc=fitz.open()
    if not key:
        out_doc.insert_pdf(doc); out=tmp("translated.pdf"); out_doc.save(str(out))
        return pres(out,f"translated.pdf")
    for i,page in enumerate(doc):
        text=page.get_text()
        if not text.strip(): out_doc.insert_pdf(doc,from_page=i,to_page=i); continue
        async with httpx.AsyncClient() as client:
            r=await client.post("https://api.anthropic.com/v1/messages",
                headers={"x-api-key":key,"anthropic-version":"2023-06-01","content-type":"application/json"},
                json={"model":"claude-sonnet-4-20250514","max_tokens":2000,
                      "messages":[{"role":"user","content":f"Translate to {target_language}. Return ONLY the translation:\n\n{text[:3000]}"}]},
                timeout=30)
        translated=r.json().get("content",[{}])[0].get("text",text)
        np=out_doc.new_page(width=page.rect.width,height=page.rect.height)
        np.insert_text(fitz.Point(50,50),translated,fontsize=11)
    out=tmp("translated.pdf"); out_doc.save(str(out))
    return pres(out,f"translated_{target_language.lower()}.pdf")

# 27. AI SMART REDACT
@app.post("/ai/smart-redact")
async def smart_redact(file:UploadFile=File(...),detect:str=Form("names,emails,phones,ssn,credit_cards"),api_key:str=Form("")):
    import httpx
    key=api_key or os.getenv("ANTHROPIC_API_KEY","")
    p=save(file,"sr.pdf"); doc=fitz.open(str(p)); total=0
    patterns={}
    if "emails" in detect:       patterns["email"]=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    if "phones" in detect:       patterns["phone"]=r'\b(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'
    if "ssn" in detect:          patterns["ssn"]=r'\b\d{3}-\d{2}-\d{4}\b'
    if "credit_cards" in detect: patterns["cc"]=r'\b(?:\d{4}[\s-]?){3}\d{4}\b'
    for page in doc:
        text=page.get_text()
        for pat in patterns.values():
            for m in re.findall(pat,text):
                s=m if isinstance(m,str) else m[0]
                for inst in page.search_for(s):
                    page.add_redact_annot(inst,fill=(0,0,0)); total+=1
        if "names" in detect and text.strip() and key:
            async with httpx.AsyncClient() as client:
                r=await client.post("https://api.anthropic.com/v1/messages",
                    headers={"x-api-key":key,"anthropic-version":"2023-06-01","content-type":"application/json"},
                    json={"model":"claude-sonnet-4-20250514","max_tokens":400,
                          "messages":[{"role":"user","content":f"List only person names, one per line:\n\n{text[:2000]}"}]},
                    timeout=20)
            for name in r.json().get("content",[{}])[0].get("text","").split("\n"):
                name=name.strip()
                if len(name)>2:
                    for inst in page.search_for(name):
                        page.add_redact_annot(inst,fill=(0,0,0)); total+=1
        page.apply_redactions()
    out=tmp("smart_redacted.pdf"); doc.save(str(out))
    resp=pres(out,"smart_redacted.pdf"); resp.headers["X-Redacted"]=str(total)
    return resp

if __name__=="__main__":
    import uvicorn
    uvicorn.run("main:app",host="0.0.0.0",port=8000,reload=True)
