from fastapi import FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
import base64

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.middleware("http")
async def validate_tenants(request: Request, call_next):
    print('Request received at middleware')
    allowed_tenants = ['microsoft.com', 'contoso.com']
    try:
        body = await request.json()
        client_principal = body.get('clientPrincipal', {})
        user_details = client_principal.get('userDetails')
        claims = client_principal.get('claims', [])
        iss_val = None
        for claim in claims:
            if claim.get('typ') == 'iss':
                iss_val = claim.get('val')
                break
        # userDetailsのドメイン部分を抽出
        if user_details and '@' in user_details:
            domain = user_details.split('@')[-1]
            if domain not in allowed_tenants:
                return JSONResponse(
                    content={"error": f"Tenant '{domain}' is not allowed."},
                    status_code=403
                )
        else:
            return JSONResponse(
                content={"error": "userDetails not found or invalid."},
                status_code=403
            )
        # 値をrequest.stateに格納
        request.state.user_details = user_details
        request.state.iss_val = iss_val
    except Exception:
        # JSONでない、またはパースできない場合は403
        return JSONResponse(
            content={"error": "Request body must be JSON and contain valid clientPrincipal."},
            status_code=403
        )
    response = await call_next(request)
    
    return response

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    print('Request for index page received')
    return templates.TemplateResponse('index.html', {"request": request})

@app.get('/favicon.ico')
async def favicon():
    file_name = 'favicon.ico'
    file_path = './static/' + file_name
    return FileResponse(path=file_path, headers={'mimetype': 'image/vnd.microsoft.icon'})

@app.post('/hello', response_class=HTMLResponse)
async def hello(request: Request, name: str = Form(...)):
    if name:
        print('Request for hello page received with name=%s' % name)
        return templates.TemplateResponse('hello.html', {"request": request, 'name':name})
    else:
        print('Request for hello page received with no name or blank name -- redirecting')
        return RedirectResponse(request.url_for("index"), status_code=status.HTTP_302_FOUND)

# @app.post('/api/test')
# async def test(request: Request):
#     print('Request for test page received')
#     header = request.headers.get('x-ms-client-principal')

#     if header is None:
#         print("No x-ms-client-principal header found")
#         return JSONResponse(
#             content={"error": "No x-ms-client-principal header found"},
#             status_code=400
#         )
    
#     decoded = None
#     try:
#         encoded = base64.b64decode(header)
#         decoded = encoded.decode('ascii')
#         print(f"Client Principal: {decoded}")
#         return JSONResponse(
#             content={"client_principal": decoded},
#             status_code=200
#         )
#     except Exception as e:
#         return JSONResponse(
#             content={"error": f"Error decoding header: {e}"},
#             status_code=500
#         )

@app.post('/api/test')
async def test(request: Request):
    print('Request for test page received')
    user_details = getattr(request.state, 'user_details', None)
    iss_val = getattr(request.state, 'iss_val', None)
    if user_details is None or iss_val is None:
        return JSONResponse(
            content={"error": "userDetails or iss claim not found"},
            status_code=400
        )
    return JSONResponse(
        content={
            "userDetails": user_details,
            "iss": iss_val
        },
        status_code=200
    )

if __name__ == '__main__':
    uvicorn.run('main:app', host='0.0.0.0', port=8000)

